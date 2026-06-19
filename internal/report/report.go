// Package report renders a tlsscan.Report as human-readable text or JSON.
//
// Rendering is kept separate from scanning and never consults the wall
// clock: it relies entirely on the precomputed fields of the report
// (DaysRemaining, Expired, NotYetValid, WarnDays) so output is
// deterministic and testable.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"tlsee/internal/tlsscan"
)

// ANSI color codes used only when color output is enabled.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBold   = "\033[1m"
)

// status describes the overall health summary of a report.
type status struct {
	text  string
	color string
}

// summarize combines the report's conditions into a single prominent
// status. The most severe problem wins; an otherwise healthy certificate
// that is expiring within WarnDays is reported as expiring soon.
func summarize(r *tlsscan.Report) status {
	var problems []string
	worst := colorYellow

	if r.Leaf.Expired {
		problems = append(problems, "EXPIRED")
		worst = colorRed
	}
	if r.Leaf.NotYetValid {
		problems = append(problems, "NOT YET VALID")
		worst = colorRed
	}
	if !r.ChainTrusted {
		problems = append(problems, "UNTRUSTED CHAIN")
		worst = colorRed
	}
	if !r.HostnameMatch {
		problems = append(problems, "HOSTNAME MISMATCH")
		worst = colorRed
	}
	if !r.Leaf.Expired && !r.Leaf.NotYetValid && r.Leaf.DaysRemaining <= r.WarnDays {
		problems = append(problems, expiringStatus(r.Leaf.DaysRemaining))
	}
	if r.DeadSANs > 0 {
		problems = append(problems, deadSANStatus(r.DeadSANs))
		worst = colorRed
	}

	if len(problems) == 0 {
		return status{text: "VALID", color: colorGreen}
	}
	return status{text: strings.Join(problems, " | "), color: worst}
}

// deadSANStatus renders the count of dead/stale SAN names for the headline.
func deadSANStatus(n int) string {
	if n == 1 {
		return "1 DEAD SAN"
	}
	return fmt.Sprintf("%d DEAD SANS", n)
}

// paint wraps s in an ANSI color when enabled, otherwise returns it
// unchanged.
func paint(s, color string, enabled bool) string {
	if !enabled || color == "" {
		return s
	}
	return color + s + colorReset
}

// WriteText renders the report as an aligned, scannable text block. ANSI
// color is applied only when color is true.
func WriteText(w io.Writer, r *tlsscan.Report, color bool) {
	st := summarize(r)

	target := r.Target
	if target == "" {
		target = r.Host
	}

	fmt.Fprintf(w, "%s %s\n", paint("tlsee", colorBold, color), target)
	fmt.Fprintf(w, "Status: %s\n", paint(st.text, st.color+colorBold, color))
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)

	row := func(label, value string) {
		fmt.Fprintf(tw, "  %s\t%s\n", label, value)
	}

	// SAN DNS names are the primary thing the user wants to see.
	sans := r.Leaf.DNSNames
	if len(sans) == 0 {
		row("SAN DNS", paint("(none)", colorYellow, color))
	} else {
		row("SAN DNS", strings.Join(sans, ", "))
	}
	if len(r.Leaf.IPAddresses) > 0 {
		row("SAN IPs", strings.Join(r.Leaf.IPAddresses, ", "))
	}

	row("Subject", r.Leaf.Subject)
	row("Issuer", r.Leaf.Issuer)
	row("Serial", r.Leaf.SerialNumber)

	row("Not before", r.Leaf.NotBefore.Format("2006-01-02 15:04:05 MST"))
	expiry := r.Leaf.NotAfter.Format("2006-01-02 15:04:05 MST")
	expiry += fmt.Sprintf("  (%s)", daysPhrase(r.Leaf.DaysRemaining))
	row("Not after", paint(expiry, expiryColor(r), color))

	row("Trusted chain", boolText(r.ChainTrusted, color))
	if r.VerifyError != "" {
		row("Trust error", paint(r.VerifyError, colorRed, color))
	}
	row("Hostname match", boolText(r.HostnameMatch, color))

	row("TLS version", r.TLSVersion)
	row("Cipher suite", r.CipherSuite)
	row("Signature", r.Leaf.SignatureAlgorithm)
	row("Public key", r.Leaf.PublicKeyAlgorithm)
	row("SHA-256", r.Leaf.FingerprintSHA256)

	if len(r.ResolvedIPs) > 0 {
		row("Resolved IPs", strings.Join(r.ResolvedIPs, ", "))
	} else {
		row("Resolved IPs", "(none)")
	}

	if len(r.Chain) > 0 {
		row("Chain depth", fmt.Sprintf("%d additional certificate(s)", len(r.Chain)))
	}

	row("Elapsed", fmt.Sprintf("%d ms", r.ElapsedMs))

	tw.Flush()

	if len(r.SANChecks) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  SAN liveness:")
		stw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, c := range r.SANChecks {
			addrs, state, stColor := sanLiveness(c)
			fmt.Fprintf(stw, "    %s\t%s\t%s\n", c.Name, addrs, paint(state, stColor, color))
		}
		stw.Flush()
	}

	if len(r.Chain) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Chain:")
		ctw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for i, c := range r.Chain {
			fmt.Fprintf(ctw, "    [%d]\t%s\t(issuer: %s)\n", i+1, c.Subject, c.Issuer)
		}
		ctw.Flush()
	}
}

// WriteJSON renders the report as indented JSON. Color is never applied.
func WriteJSON(w io.Writer, r *tlsscan.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

// sanLiveness renders one SAN check as an address list, a state word, and the
// color for that state. A name is "open" when every resolved address is
// reachable, "partial" when only some are (for example an unreachable IPv6
// address alongside a reachable IPv4 one), "unreachable" when none are, and
// "NO DNS" when it does not resolve at all. Wildcard names are not probed.
func sanLiveness(c tlsscan.SANCheck) (addrs, state, color string) {
	if c.Wildcard {
		return "-", "wildcard (not probed)", ""
	}
	if !c.Resolved {
		return "-", "NO DNS (stale?)", colorRed
	}

	parts := make([]string, 0, len(c.Addrs))
	anyUp, allUp := false, true
	for _, a := range c.Addrs {
		if a.Reachable {
			anyUp = true
			parts = append(parts, a.IP)
		} else {
			allUp = false
			parts = append(parts, a.IP+" (down)")
		}
	}
	addrs = strings.Join(parts, ", ")

	switch {
	case !anyUp:
		return addrs, "unreachable", colorRed
	case !allUp:
		return addrs, "partial", colorYellow
	default:
		return addrs, "open", colorGreen
	}
}

// expiryColor chooses the color for the validity row based on the
// certificate's state.
func expiryColor(r *tlsscan.Report) string {
	switch {
	case r.Leaf.Expired, r.Leaf.NotYetValid:
		return colorRed
	case r.Leaf.DaysRemaining <= r.WarnDays:
		return colorYellow
	default:
		return colorGreen
	}
}

// expiringStatus renders the prominent "expiring soon" headline, mirroring
// the grammar of daysPhrase. Only non-negative day counts reach this branch
// (a negative count is reported as EXPIRED instead).
func expiringStatus(days int) string {
	switch {
	case days <= 0:
		return "EXPIRES TODAY"
	case days == 1:
		return "EXPIRING IN 1 DAY"
	default:
		return fmt.Sprintf("EXPIRING IN %d DAYS", days)
	}
}

// daysPhrase renders the days-remaining count as a readable phrase.
func daysPhrase(days int) string {
	switch {
	case days < 0:
		return fmt.Sprintf("expired %d days ago", -days)
	case days == 0:
		return "expires today"
	case days == 1:
		return "1 day remaining"
	default:
		return fmt.Sprintf("%d days remaining", days)
	}
}

// boolText renders a yes/no value, coloring it green for yes and red for
// no when color is enabled.
func boolText(v bool, color bool) string {
	if v {
		return paint("yes", colorGreen, color)
	}
	return paint("no", colorRed, color)
}

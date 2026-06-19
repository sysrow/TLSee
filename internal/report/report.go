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
	"sort"
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

// sweepWarnDays is the days-remaining threshold below which a sweep reports a
// certificate as expiring. The sweep subcommand has no --warn-days flag, so this
// matches the scan default for consistency.
const sweepWarnDays = 30

// status describes the overall health summary of a report.
type status struct {
	text  string
	color string
}

// summarize combines the report's conditions into a single prominent
// status. The most severe problem wins; an otherwise healthy certificate
// that is expiring within WarnDays is reported as expiring soon.
//
// Dead SANs are a non-red advisory, not a certificate problem: they do not
// change the exit code and a dead-SAN-only certificate stays "healthy" for
// --quiet, so they must neither erase the healthy VALID indicator nor turn
// the headline red. When the certificate is otherwise valid, the headline
// reads "VALID | N DEAD SAN(S)" in yellow; when there is already a real
// problem, the dead-SAN advisory is appended without escalating the color.
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

	// If nothing above flagged a real certificate problem, the certificate is
	// healthy. A dead-SAN advisory is then appended to the VALID headline as a
	// non-red note rather than replacing it.
	if len(problems) == 0 {
		if r.DeadSANs > 0 {
			return status{text: "VALID | " + deadSANStatus(r.DeadSANs), color: colorYellow}
		}
		return status{text: "VALID", color: colorGreen}
	}

	// A real problem exists. Append the dead-SAN advisory for visibility, but do
	// not let it escalate the color beyond what the real problems already set.
	if r.DeadSANs > 0 {
		problems = append(problems, deadSANStatus(r.DeadSANs))
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

	if len(r.Warnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Warnings:")
		for _, warning := range r.Warnings {
			fmt.Fprintf(w, "    %s\n", paint(warning, colorYellow, color))
		}
	}

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

	if len(r.IPCerts) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Per-IP certificates:")
		if r.IPCertsDiffer {
			fmt.Fprintf(w, "    %s\n", paint("certificates differ across IPs", colorRed+colorBold, color))
		}
		itw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, ic := range r.IPCerts {
			if ic.Error != "" {
				fmt.Fprintf(itw, "    %s\t%s\n", ic.IP, paint(ic.Error, colorRed, color))
				continue
			}
			cn := ic.SubjectCN
			if cn == "" {
				cn = "(no CN)"
			}
			// When the certificates differ across IPs, append a short fingerprint
			// prefix so otherwise-identical rows (same CN, same expiry) are visibly
			// distinct and the reader can see which address serves which cert. The
			// matching case stays narrow with no fingerprint column.
			if r.IPCertsDiffer {
				fmt.Fprintf(itw, "    %s\t%s\t%s\t%s\n", ic.IP, cn, daysPhrase(ic.DaysRemaining), shortFingerprint(ic.FingerprintSHA256))
				continue
			}
			fmt.Fprintf(itw, "    %s\t%s\t%s\n", ic.IP, cn, daysPhrase(ic.DaysRemaining))
		}
		itw.Flush()
	}

	if len(r.Chain) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Chain:")
		for i, c := range r.Chain {
			subject := certName(c.SubjectCN, c.Subject)
			issuer := certName(c.IssuerCN, c.Issuer)
			fmt.Fprintf(w, "    [%d]  %s  ->  %s\n", i+1, subject, issuer)
		}
	}
}

// certName returns the common name when present, falling back to the full
// distinguished name. It keeps the text chain narrow (one short line per cert)
// while the full DN remains available in JSON.
func certName(cn, full string) string {
	if cn != "" {
		return cn
	}
	if full != "" {
		return full
	}
	return "(unknown)"
}

// shortFingerprint returns a brief, human-comparable prefix of a colon-separated
// SHA-256 fingerprint for use as a per-IP discriminator. It keeps the first eight
// hex byte groups (for example "AA:BB:CC:DD:EE:FF:00:11") so differing
// certificates render as visibly distinct rows without printing the full 32-byte
// digest. An empty fingerprint yields "?".
func shortFingerprint(fp string) string {
	if fp == "" {
		return "?"
	}
	const groups = 8
	parts := strings.SplitN(fp, ":", groups+1)
	if len(parts) > groups {
		return strings.Join(parts[:groups], ":") + ":..."
	}
	return fp
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

// BatchRow pairs a target host with either its scan report or the error that
// scanning it produced. Exactly one of Report and Err is meaningful: when Err is
// non-empty the scan failed and Report is nil. It is the unit of the batch
// summary table and the batch JSON array.
type BatchRow struct {
	Host   string
	Report *tlsscan.Report
	Err    string
}

// batchStatus is the per-row status word, day count, dead-SAN count, and color
// derived from a BatchRow for the summary table.
type batchStatus struct {
	status string
	days   string
	dead   string
	color  string
}

// rowStatus reduces a BatchRow to its display fields. Errors sort and render
// first; otherwise the most severe certificate problem wins, mirroring
// summarize but as compact one-word column values.
func rowStatus(row BatchRow) batchStatus {
	if row.Err != "" {
		return batchStatus{status: "ERROR", days: "ERR", dead: "-", color: colorRed}
	}
	r := row.Report
	dead := fmt.Sprintf("%d", r.DeadSANs)
	days := fmt.Sprintf("%d", r.Leaf.DaysRemaining)
	switch {
	case r.Leaf.Expired, r.Leaf.NotYetValid:
		return batchStatus{status: "EXPIRED", days: days, dead: dead, color: colorRed}
	case !r.ChainTrusted:
		return batchStatus{status: "UNTRUSTED", days: days, dead: dead, color: colorRed}
	case !r.HostnameMatch:
		return batchStatus{status: "MISMATCH", days: days, dead: dead, color: colorRed}
	case r.Leaf.DaysRemaining <= r.WarnDays:
		return batchStatus{status: "EXPIRING", days: days, dead: dead, color: colorYellow}
	default:
		return batchStatus{status: "VALID", days: days, dead: dead, color: colorGreen}
	}
}

// batchSortKey orders rows for the summary table: most urgent first. Errored
// rows sort to the very top; among scanned rows, fewer days remaining sorts
// earlier. Ties break by host name for stable, deterministic output.
func batchSortKey(rows []BatchRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		ei, ej := rows[i].Err != "", rows[j].Err != ""
		if ei != ej {
			return ei // errors first
		}
		if ei && ej {
			return rows[i].Host < rows[j].Host
		}
		di, dj := rows[i].Report.Leaf.DaysRemaining, rows[j].Report.Leaf.DaysRemaining
		if di != dj {
			return di < dj
		}
		return rows[i].Host < rows[j].Host
	})
}

// WriteBatchTable renders one row per host as an aligned summary table sorted by
// urgency (errored hosts first, then fewest days remaining). When quiet is true,
// healthy rows are omitted; if every row is healthy nothing is written. The
// passed slice is sorted in place.
func WriteBatchTable(w io.Writer, rows []BatchRow, color, quiet bool) {
	batchSortKey(rows)

	visible := rows
	if quiet {
		visible = visible[:0:0]
		for _, row := range rows {
			if rowIsHealthy(row) {
				continue
			}
			visible = append(visible, row)
		}
		if len(visible) == 0 {
			return
		}
	}

	// The last column is labeled NOTE rather than DEAD: it honestly covers both
	// the dead-SAN count on a successful row and the free-text scan error on a
	// failed row, instead of putting an error message under a "dead SAN count"
	// header.
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tDAYS\tSTATUS\tNOTE")
	for _, row := range visible {
		bs := rowStatus(row)
		status := paint(bs.status, bs.color, color)
		note := bs.dead
		if row.Err != "" {
			note = row.Err
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", row.Host, bs.days, status, note)
	}
	tw.Flush()
}

// rowIsHealthy reports whether a batch row needs no attention: a successful scan
// of a certificate that is trusted, hostname-matching, currently valid, and not
// within its warn window. It mirrors the cli exit-code health predicate so quiet
// mode hides exactly the rows that would not change the exit code. Dead SANs do
// not make a row unhealthy here, matching the exit-code contract.
func rowIsHealthy(row BatchRow) bool {
	if row.Err != "" {
		return false
	}
	r := row.Report
	return r.ChainTrusted &&
		r.HostnameMatch &&
		!r.Leaf.Expired &&
		!r.Leaf.NotYetValid &&
		r.Leaf.DaysRemaining > r.WarnDays
}

// WriteBatchJSON renders the batch as a JSON array. Each healthy or unhealthy
// scan is emitted as its full report; each failed scan is emitted as a
// {host, error} object. When quiet is true, healthy rows are omitted and, if
// nothing remains, nothing is written at all (so quiet JSON stays silent for an
// all-healthy run, matching the text path). The passed slice is sorted in place
// to match the table ordering.
func WriteBatchJSON(w io.Writer, rows []BatchRow, quiet bool) error {
	batchSortKey(rows)

	type failure struct {
		Host  string `json:"host"`
		Error string `json:"error"`
	}

	items := make([]any, 0, len(rows))
	for _, row := range rows {
		if quiet && rowIsHealthy(row) {
			continue
		}
		if row.Err != "" {
			items = append(items, failure{Host: row.Host, Error: row.Err})
			continue
		}
		items = append(items, row.Report)
	}

	// In quiet mode, an empty result means every host was healthy: stay silent
	// rather than emitting an empty array, so a clean run produces no output.
	if quiet && len(items) == 0 {
		return nil
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(items); err != nil {
		return fmt.Errorf("encode batch: %w", err)
	}
	return nil
}

// WriteSweepText renders a port sweep as a table sorted by port. Closed ports
// and ports without TLS are reported alongside the certificates found. The CERT
// column shows the leaf subject common name; the STATUS column summarizes
// validity (VALID, EXPIRING Nd, EXPIRED, no TLS, or closed).
func WriteSweepText(w io.Writer, sr *tlsscan.SweepResult, color bool) {
	fmt.Fprintf(w, "%s %s\n\n", paint("tlsee sweep", colorBold, color), sr.Host)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PORT\tPROTO\tCERT\tSTATUS")
	for _, p := range sr.Ports {
		status, stColor := sweepStatus(p)
		cert := p.SubjectCN
		if cert == "" {
			cert = "-"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", p.Port, p.Proto, cert, paint(status, stColor, color))
	}
	tw.Flush()
}

// sweepStatus maps a port probe result to its STATUS column word and color.
func sweepStatus(p tlsscan.PortResult) (string, string) {
	switch {
	case !p.Open:
		return "closed", ""
	case !p.TLS:
		return "no TLS", colorYellow
	case p.Expired:
		return "EXPIRED", colorRed
	case p.DaysRemaining <= sweepWarnDays:
		return fmt.Sprintf("EXPIRING %dd", p.DaysRemaining), colorYellow
	default:
		return "VALID", colorGreen
	}
}

// WriteSweepJSON renders a sweep result as indented JSON.
func WriteSweepJSON(w io.Writer, sr *tlsscan.SweepResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sr); err != nil {
		return fmt.Errorf("encode sweep: %w", err)
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

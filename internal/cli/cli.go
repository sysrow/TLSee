// Package cli implements the tlsee command-line interface: flag parsing,
// subcommand dispatch, output rendering, and exit-code computation. It is
// the only boundary besides main that is allowed to touch os-level
// terminal details; everything below it takes injected writers.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"tlsee/internal/report"
	"tlsee/internal/tlsscan"
)

// version is the tool's version string, printed by the version subcommand.
const version = "tlsee 0.1.0"

// errTargetCount is returned when the scan subcommand does not receive
// exactly one positional target.
var errTargetCount = errors.New("exactly one target is required")

// Exit codes returned by Run.
const (
	exitOK       = 0 // healthy certificate, or explicitly requested help (or a problem suppressed by --insecure)
	exitError    = 1 // runtime error: bad flags, missing/extra args, unknown command, connection failure
	exitCertProb = 2 // certificate problem, or usage shown for no-args
	exitUsage    = 2 // usage shown for no-args
)

// Run parses args, dispatches the subcommand, renders output to stdout,
// reports errors to stderr, and returns the process exit code. os.Exit is
// never called here; that is main's responsibility.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return exitOK
	case "help", "-h", "--help":
		// Help was explicitly requested, so it is the requested output:
		// write to stdout and succeed, keeping the tool pipeable.
		writeUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "tlsee: unknown command %q\n\n", args[0])
		writeUsage(stderr)
		return exitError
	}
}

// runScan handles the "scan" subcommand.
func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		port      = fs.String("port", "443", "port to connect to when the target omits one")
		timeout   = fs.Duration("timeout", 10*time.Second, "dial and handshake timeout")
		sni       = fs.String("sni", "", "SNI server name override (default: target host)")
		asJSON    = fs.Bool("json", false, "emit JSON instead of text")
		colorMode = fs.String("color", "auto", "color output: auto|always|never")
		warnDays  = fs.Int("warn-days", 30, "warn when a certificate expires within this many days")
		insecure  = fs.Bool("insecure", false, "always exit 0 even when the certificate has problems")
		noCheck   = fs.Bool("no-check", false, "skip SAN liveness checks (resolve + TCP-probe of each certificate name)")
	)

	fs.Usage = func() { printScanUsage(stderr, fs) }

	// Explicit help is the requested output: print it to stdout and succeed,
	// matching the top-level help command and keeping the tool pipeable.
	for _, a := range args {
		if a == "-h" || a == "--help" {
			printScanUsage(stdout, fs)
			return exitOK
		}
	}

	target, err := parseInterspersed(fs, args)
	if err != nil {
		// A flag-parse error was already printed to stderr by the flag
		// package; the target-count error is ours to report.
		if errors.Is(err, errTargetCount) {
			fmt.Fprintln(stderr, "tlsee scan: "+err.Error())
			fs.Usage()
		}
		return exitError
	}

	useColor, err := resolveColor(*colorMode, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "tlsee scan: %v\n", err)
		return exitError
	}

	ctx := context.Background()
	rep, err := tlsscan.Scan(ctx, target, tlsscan.Options{
		Port:       *port,
		Timeout:    *timeout,
		ServerName: *sni,
		ResolveDNS: true,
		CheckSANs:  !*noCheck,
	})
	if err != nil {
		fmt.Fprintf(stderr, "tlsee scan: %v\n", err)
		return exitError
	}

	// The configurable warn-days threshold is carried on the report so
	// rendering and exit-code logic share one source of truth.
	rep.WarnDays = *warnDays

	if *asJSON {
		if err := report.WriteJSON(stdout, rep); err != nil {
			fmt.Fprintf(stderr, "tlsee scan: %v\n", err)
			return exitError
		}
	} else {
		report.WriteText(stdout, rep, useColor)
	}

	if *insecure {
		return exitOK
	}
	return exitCodeForReport(rep)
}

// parseInterspersed parses fs from args while allowing the single positional
// target to appear before, after, or among the flags. The stdlib flag package
// stops at the first non-flag argument, so Parse is re-invoked on the arguments
// that follow each positional until every flag is consumed. It returns the one
// target, or errTargetCount if there is not exactly one.
func parseInterspersed(fs *flag.FlagSet, args []string) (string, error) {
	var target string
	seen := false
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return "", err
		}
		if fs.NArg() == 0 {
			break
		}
		if seen {
			return "", errTargetCount
		}
		target = fs.Arg(0)
		seen = true
		rest = fs.Args()[1:]
	}
	if !seen {
		return "", errTargetCount
	}
	return target, nil
}

// exitCodeForReport returns exitCertProb when the certificate is unhealthy
// and exitOK otherwise. A certificate is healthy when the chain is
// trusted, the hostname matches, it is currently valid, and it is not
// within the warn window.
func exitCodeForReport(r *tlsscan.Report) int {
	healthy := r.ChainTrusted &&
		r.HostnameMatch &&
		!r.Leaf.Expired &&
		!r.Leaf.NotYetValid &&
		r.Leaf.DaysRemaining > r.WarnDays
	if healthy {
		return exitOK
	}
	return exitCertProb
}

// resolveColor decides whether ANSI color should be emitted, honoring the
// --color mode, NO_COLOR, and whether stdout is a terminal. Terminal
// detection inspects the passed writer (not the os.Stdout global) so that
// tests using buffers naturally disable color.
func resolveColor(mode string, stdout io.Writer) (bool, error) {
	switch mode {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "auto":
		if _, ok := os.LookupEnv("NO_COLOR"); ok {
			return false, nil
		}
		return isTerminal(stdout), nil
	default:
		return false, fmt.Errorf("invalid --color value %q (want auto, always, or never)", mode)
	}
}

// isTerminal reports whether w is a character device (a terminal).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// printScanUsage writes the scan subcommand usage and flag list to w.
func printScanUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintln(w, "Usage: tlsee scan <target> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// writeUsage prints top-level usage and exit-code documentation to w.
func writeUsage(w io.Writer) {
	fmt.Fprint(w, `tlsee - a friendly TLS certificate inspector

Usage:
  tlsee scan <target> [flags]   Inspect the TLS certificate at a target
  tlsee version                 Print the tlsee version
  tlsee help                    Show this help

Targets may be a hostname, host:port, IP, or URL. Examples:
  tlsee scan example.com
  tlsee scan https://example.com
  tlsee scan localhost:8443
  tlsee scan 127.0.0.1:8443
  tlsee scan [::1]:8443

Scan flags:
  --port N            port to use when the target omits one (default 443)
  --timeout 10s       dial and handshake timeout (default 10s)
  --sni name          SNI server name override (default: target host)
  --json              emit JSON instead of text
  --color MODE        auto|always|never (default auto)
  --warn-days N       warn when expiring within N days (default 30)
  --no-check          skip SAN liveness checks (on by default)
  --insecure          always exit 0 even when the certificate has problems

By default tlsee also resolves and TCP-probes every DNS name in the
certificate's SAN list and reports dead or stale entries (a name that no
longer resolves, or whose host is unreachable on the port). Dead SANs are
shown but do not change the exit code, which reflects the certificate's own
validity. Use --no-check to skip this.

Exit codes:
  0  healthy: trusted chain, hostname matches, valid, and not expiring soon
     (also when help is explicitly requested)
  1  runtime error: bad flags, missing target, unknown command, or
     connection failure
  2  usage shown for no arguments, or a certificate problem: expired, not
     yet valid, untrusted, hostname mismatch, or expiring within --warn-days
     (a certificate problem is suppressed by --insecure)
`)
}

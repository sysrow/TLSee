package cli

import (
	"bytes"
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"tlsee/internal/tlsscan"
)

// TestParseInterspersed verifies the target is extracted no matter where the
// flags sit relative to it, so "scan host --json" and "scan --json host" are
// both accepted.
func TestParseInterspersed(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantTarget string
		wantJSON   bool
		wantErr    bool
	}{
		{name: "target only", args: []string{"example.com"}, wantTarget: "example.com"},
		{name: "flag before target", args: []string{"--json", "example.com"}, wantTarget: "example.com", wantJSON: true},
		{name: "flag after target", args: []string{"example.com", "--json"}, wantTarget: "example.com", wantJSON: true},
		{name: "flags on both sides", args: []string{"--json", "example.com", "--color", "never"}, wantTarget: "example.com", wantJSON: true},
		{name: "no target", args: []string{"--json"}, wantErr: true},
		{name: "two targets", args: []string{"a", "b"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("scan", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			asJSON := fs.Bool("json", false, "")
			fs.String("color", "auto", "")

			target, err := parseInterspersed(fs, tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseInterspersed(%v) = (%q, nil); want error", tc.args, target)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInterspersed(%v) unexpected error: %v", tc.args, err)
			}
			if target != tc.wantTarget {
				t.Errorf("target = %q; want %q", target, tc.wantTarget)
			}
			if *asJSON != tc.wantJSON {
				t.Errorf("json = %v; want %v", *asJSON, tc.wantJSON)
			}
		})
	}
}

// healthyReport returns a report that passes every health predicate, so each
// test can flip exactly one condition to assert it drives the exit code.
func healthyReport() *tlsscan.Report {
	return &tlsscan.Report{
		ChainTrusted:  true,
		HostnameMatch: true,
		WarnDays:      30,
		Leaf: tlsscan.CertInfo{
			DaysRemaining: 90,
			Expired:       false,
			NotYetValid:   false,
		},
	}
}

func TestExitCodeForReport(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(r *tlsscan.Report)
		want   int
	}{
		{name: "healthy", mutate: func(*tlsscan.Report) {}, want: exitOK},
		{name: "expired", mutate: func(r *tlsscan.Report) { r.Leaf.Expired = true }, want: exitCertProb},
		{name: "not yet valid", mutate: func(r *tlsscan.Report) { r.Leaf.NotYetValid = true }, want: exitCertProb},
		{name: "untrusted chain", mutate: func(r *tlsscan.Report) { r.ChainTrusted = false }, want: exitCertProb},
		{name: "hostname mismatch", mutate: func(r *tlsscan.Report) { r.HostnameMatch = false }, want: exitCertProb},
		{
			name:   "at warn boundary is unhealthy",
			mutate: func(r *tlsscan.Report) { r.Leaf.DaysRemaining = r.WarnDays },
			want:   exitCertProb,
		},
		{
			name:   "one day past warn boundary is healthy",
			mutate: func(r *tlsscan.Report) { r.Leaf.DaysRemaining = r.WarnDays + 1 },
			want:   exitOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := healthyReport()
			tc.mutate(r)
			if got := exitCodeForReport(r); got != tc.want {
				t.Errorf("exitCodeForReport() = %d; want %d", got, tc.want)
			}
		})
	}
}

func TestResolveColor(t *testing.T) {
	t.Run("always", func(t *testing.T) {
		got, err := resolveColor("always", &bytes.Buffer{})
		if err != nil || !got {
			t.Errorf("resolveColor(always) = (%v, %v); want (true, nil)", got, err)
		}
	})

	t.Run("never", func(t *testing.T) {
		got, err := resolveColor("never", &bytes.Buffer{})
		if err != nil || got {
			t.Errorf("resolveColor(never) = (%v, %v); want (false, nil)", got, err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		got, err := resolveColor("sometimes", &bytes.Buffer{})
		if err == nil {
			t.Errorf("resolveColor(sometimes) = (%v, nil); want an error", got)
		}
	})

	t.Run("auto with NO_COLOR set", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		got, err := resolveColor("auto", &bytes.Buffer{})
		if err != nil || got {
			t.Errorf("resolveColor(auto, NO_COLOR) = (%v, %v); want (false, nil)", got, err)
		}
	})

	t.Run("auto with non-terminal writer", func(t *testing.T) {
		// With NO_COLOR unset, resolveColor falls through to isTerminal. A
		// *bytes.Buffer is not an *os.File character device, so color is
		// disabled by the terminal-detection path specifically. t.Setenv
		// records the original value and restores it on cleanup; the unset
		// makes this subtest exercise isTerminal rather than the NO_COLOR
		// short-circuit.
		t.Setenv("NO_COLOR", "")
		os.Unsetenv("NO_COLOR")
		got, err := resolveColor("auto", &bytes.Buffer{})
		if err != nil || got {
			t.Errorf("resolveColor(auto, buffer) = (%v, %v); want (false, nil)", got, err)
		}
	})
}

func TestRunDispatch(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantCode       int
		wantStdoutHas  string
		wantStderrHas  string
		wantStdoutOnly bool // output must be on stdout, stderr empty
	}{
		{
			name:           "version to stdout exit 0",
			args:           []string{"version"},
			wantCode:       exitOK,
			wantStdoutHas:  version,
			wantStdoutOnly: true,
		},
		{
			name:           "help to stdout exit 0",
			args:           []string{"help"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage:",
			wantStdoutOnly: true,
		},
		{
			name:           "-h to stdout exit 0",
			args:           []string{"-h"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage:",
			wantStdoutOnly: true,
		},
		{
			name:           "--help to stdout exit 0",
			args:           []string{"--help"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage:",
			wantStdoutOnly: true,
		},
		{
			name:           "scan --help to stdout exit 0",
			args:           []string{"scan", "--help"},
			wantCode:       exitOK,
			wantStdoutHas:  "Usage: tlsee scan",
			wantStdoutOnly: true,
		},
		{
			name:          "no args to stderr exit 2",
			args:          []string{},
			wantCode:      exitUsage,
			wantStderrHas: "Usage:",
		},
		{
			name:          "unknown command exit 1",
			args:          []string{"frobnicate"},
			wantCode:      exitError,
			wantStderrHas: "unknown command",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := Run(tc.args, &stdout, &stderr)
			if got != tc.wantCode {
				t.Errorf("Run(%v) = %d; want %d", tc.args, got, tc.wantCode)
			}
			if tc.wantStdoutHas != "" && !strings.Contains(stdout.String(), tc.wantStdoutHas) {
				t.Errorf("stdout missing %q\n---\n%s", tc.wantStdoutHas, stdout.String())
			}
			if tc.wantStderrHas != "" && !strings.Contains(stderr.String(), tc.wantStderrHas) {
				t.Errorf("stderr missing %q\n---\n%s", tc.wantStderrHas, stderr.String())
			}
			if tc.wantStdoutOnly && stderr.Len() != 0 {
				t.Errorf("expected empty stderr, got:\n%s", stderr.String())
			}
		})
	}
}

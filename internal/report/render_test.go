package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"tlsee/internal/tlsscan"
)

// TestWriteTextChainCNOnly verifies the chain section renders one narrow line
// per certificate using the common name, falling back to the full DN when the
// common name is empty.
func TestWriteTextChainCNOnly(t *testing.T) {
	r := fixedReport()
	r.Chain = []tlsscan.CertInfo{
		// CN present: render the short CN, not the wide DN.
		{
			Subject:   "CN=Intermediate CA,O=Example,L=Somewhere,C=US",
			Issuer:    "CN=Example Root,O=Example,L=Somewhere,C=US",
			SubjectCN: "Intermediate CA",
			IssuerCN:  "Example Root",
		},
		// CN empty: fall back to the full DN.
		{Subject: "OU=Org Unit,O=Example", Issuer: "OU=Root Unit,O=Example"},
	}

	var buf bytes.Buffer
	WriteText(&buf, r, false)
	out := buf.String()

	if !strings.Contains(out, "[1]  Intermediate CA  ->  Example Root") {
		t.Errorf("chain line 1 not rendered CN-only:\n%s", out)
	}
	if !strings.Contains(out, "[2]  OU=Org Unit,O=Example  ->  OU=Root Unit,O=Example") {
		t.Errorf("chain line 2 did not fall back to full DN:\n%s", out)
	}
	// The wide-DN form must not be used when a CN is available.
	if strings.Contains(out, "CN=Intermediate CA,O=Example,L=Somewhere,C=US") {
		t.Errorf("chain still rendered the wide DN despite a CN being present:\n%s", out)
	}
}

// TestWriteTextWarnings verifies the warnings section appears (yellow under
// color) when warnings are present and is omitted when empty.
func TestWriteTextWarnings(t *testing.T) {
	r := fixedReport()
	r.Warnings = []string{"weak TLS version: TLS 1.0", "weak RSA key: 1024 bits"}

	var plain bytes.Buffer
	WriteText(&plain, r, false)
	out := plain.String()
	for _, want := range []string{"Warnings:", "weak TLS version: TLS 1.0", "weak RSA key: 1024 bits"} {
		if !strings.Contains(out, want) {
			t.Errorf("warnings output missing %q\n---\n%s", want, out)
		}
	}

	var colored bytes.Buffer
	WriteText(&colored, r, true)
	if !strings.Contains(colored.String(), colorYellow+"weak TLS version: TLS 1.0"+colorReset) {
		t.Errorf("warning not rendered yellow with color enabled:\n%s", colored.String())
	}

	// No warnings: the section header must not appear.
	clean := fixedReport()
	var noWarn bytes.Buffer
	WriteText(&noWarn, clean, false)
	if strings.Contains(noWarn.String(), "Warnings:") {
		t.Errorf("warnings section rendered with no warnings:\n%s", noWarn.String())
	}
}

// TestWriteTextWarningsNoHeadlineEffect confirms warnings never change the
// status headline: a fully valid certificate with warnings still reads VALID.
func TestWriteTextWarningsNoHeadlineEffect(t *testing.T) {
	r := fixedReport()
	r.Warnings = []string{"weak signature algorithm: SHA1-RSA"}
	var buf bytes.Buffer
	WriteText(&buf, r, false)
	if !strings.Contains(buf.String(), "Status: VALID") {
		t.Errorf("warnings altered the status headline; want VALID:\n%s", buf.String())
	}
}

// TestWriteTextPerIP verifies the per-IP section lists each address with its CN
// or error, and shows the prominent differ note only when fingerprints differ.
func TestWriteTextPerIP(t *testing.T) {
	r := fixedReport()
	r.IPCerts = []tlsscan.IPCert{
		{IP: "10.0.0.1", FingerprintSHA256: "AA", SubjectCN: "example.com", DaysRemaining: 90},
		{IP: "10.0.0.2", FingerprintSHA256: "BB", SubjectCN: "example.com", DaysRemaining: 10},
		{IP: "10.0.0.3", Error: "connect 10.0.0.3:443: connection refused"},
	}
	r.IPCertsDiffer = true

	var buf bytes.Buffer
	WriteText(&buf, r, false)
	out := buf.String()
	for _, want := range []string{
		"Per-IP certificates:",
		"10.0.0.1", "90 days remaining",
		"10.0.0.2", "10 days remaining",
		"10.0.0.3", "connection refused",
		"certificates differ across IPs",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("per-IP output missing %q\n---\n%s", want, out)
		}
	}

	// When they do not differ, the note is absent but the list remains.
	same := fixedReport()
	same.IPCerts = []tlsscan.IPCert{
		{IP: "10.0.0.1", FingerprintSHA256: "AA", SubjectCN: "example.com", DaysRemaining: 90},
		{IP: "10.0.0.2", FingerprintSHA256: "AA", SubjectCN: "example.com", DaysRemaining: 90},
	}
	same.IPCertsDiffer = false
	var buf2 bytes.Buffer
	WriteText(&buf2, same, false)
	if strings.Contains(buf2.String(), "certificates differ across IPs") {
		t.Errorf("differ note shown when certificates match:\n%s", buf2.String())
	}
	if !strings.Contains(buf2.String(), "Per-IP certificates:") {
		t.Errorf("per-IP section missing when fingerprints match:\n%s", buf2.String())
	}
}

// TestWriteTextPerIPDifferShowsDiscriminator verifies that when certificates
// differ across IPs, rows that are otherwise identical (same CN, same expiry)
// still render visibly distinct via a truncated fingerprint, so the differ note
// does not sit above look-alike rows. The matching case adds no fingerprint
// column.
func TestWriteTextPerIPDifferShowsDiscriminator(t *testing.T) {
	differ := fixedReport()
	differ.IPCerts = []tlsscan.IPCert{
		{IP: "10.0.0.1", FingerprintSHA256: "AA:BB:CC:DD:EE:FF:00:11", SubjectCN: "example.com", DaysRemaining: 90},
		{IP: "10.0.0.2", FingerprintSHA256: "11:22:33:44:55:66:77:88", SubjectCN: "example.com", DaysRemaining: 90},
	}
	differ.IPCertsDiffer = true
	var buf bytes.Buffer
	WriteText(&buf, differ, false)
	out := buf.String()
	for _, want := range []string{"AA:BB:CC:DD", "11:22:33:44"} {
		if !strings.Contains(out, want) {
			t.Errorf("differing per-IP rows missing fingerprint discriminator %q\n---\n%s", want, out)
		}
	}

	// The matching case must not print a fingerprint discriminator.
	same := fixedReport()
	same.IPCerts = []tlsscan.IPCert{
		{IP: "10.0.0.1", FingerprintSHA256: "AA:BB:CC:DD:EE:FF:00:11", SubjectCN: "example.com", DaysRemaining: 90},
		{IP: "10.0.0.2", FingerprintSHA256: "AA:BB:CC:DD:EE:FF:00:11", SubjectCN: "example.com", DaysRemaining: 90},
	}
	same.IPCertsDiffer = false
	var buf2 bytes.Buffer
	WriteText(&buf2, same, false)
	if strings.Contains(buf2.String(), "AA:BB:CC:DD") {
		t.Errorf("matching per-IP rows should not print a fingerprint column:\n%s", buf2.String())
	}
}

// TestShortFingerprint covers the truncation helper: long fingerprints keep the
// first four byte groups with an ellipsis, short or empty inputs degrade safely.
func TestShortFingerprint(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AA:BB:CC:DD:EE:FF:00:11:22:33", "AA:BB:CC:DD:EE:FF:00:11:..."},
		{"AA:BB:CC:DD:EE:FF:00:11", "AA:BB:CC:DD:EE:FF:00:11"},
		{"AA:BB:CC:DD", "AA:BB:CC:DD"},
		{"AA:BB", "AA:BB"},
		{"AA", "AA"},
		{"", "?"},
	}
	for _, c := range cases {
		if got := shortFingerprint(c.in); got != c.want {
			t.Errorf("shortFingerprint(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// batchRows builds a deterministic mix of batch outcomes for table tests.
func batchRows() []BatchRow {
	mk := func(days int, trusted, hostnameMatch, expired bool) *tlsscan.Report {
		return &tlsscan.Report{
			ChainTrusted:  trusted,
			HostnameMatch: hostnameMatch,
			WarnDays:      30,
			Leaf: tlsscan.CertInfo{
				DaysRemaining: days,
				Expired:       expired,
			},
		}
	}
	return []BatchRow{
		{Host: "healthy.example.com", Report: mk(90, true, true, false)},
		{Host: "expiring.example.com", Report: mk(10, true, true, false)},
		{Host: "expired.example.com", Report: mk(-3, true, true, true)},
		{Host: "broken.example.com", Err: "connect broken.example.com:443: i/o timeout"},
		{Host: "mismatch.example.com", Report: mk(60, true, false, false)},
	}
}

// TestWriteBatchTableSortAndContent verifies the table is sorted with errors
// first then by ascending days, and that each status word appears.
func TestWriteBatchTableSortAndContent(t *testing.T) {
	var buf bytes.Buffer
	WriteBatchTable(&buf, batchRows(), false, false)
	out := buf.String()

	if !strings.Contains(out, "HOST") || !strings.Contains(out, "STATUS") || !strings.Contains(out, "NOTE") {
		t.Errorf("table header missing columns:\n%s", out)
	}
	for _, want := range []string{"VALID", "EXPIRING", "EXPIRED", "ERROR", "MISMATCH", "i/o timeout"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing status %q\n---\n%s", want, out)
		}
	}

	// Order: error first, then ascending days (-3, 10, 60, 90).
	order := []string{
		"broken.example.com",
		"expired.example.com",
		"expiring.example.com",
		"mismatch.example.com",
		"healthy.example.com",
	}
	lastIdx := -1
	for _, host := range order {
		idx := strings.Index(out, host)
		if idx < 0 {
			t.Fatalf("host %q not in table:\n%s", host, out)
		}
		if idx < lastIdx {
			t.Errorf("host %q out of order in table:\n%s", host, out)
		}
		lastIdx = idx
	}
}

// TestWriteBatchTableQuiet verifies quiet mode prints only problem rows, and
// nothing at all when every row is healthy.
func TestWriteBatchTableQuiet(t *testing.T) {
	var buf bytes.Buffer
	WriteBatchTable(&buf, batchRows(), false, true)
	out := buf.String()
	if strings.Contains(out, "healthy.example.com") {
		t.Errorf("quiet table included a healthy row:\n%s", out)
	}
	for _, want := range []string{"expired.example.com", "broken.example.com", "mismatch.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("quiet table missing problem row %q:\n%s", want, out)
		}
	}

	// All healthy: nothing at all, not even a header.
	allHealthy := []BatchRow{
		{Host: "a.example.com", Report: &tlsscan.Report{ChainTrusted: true, HostnameMatch: true, WarnDays: 30, Leaf: tlsscan.CertInfo{DaysRemaining: 90}}},
		{Host: "b.example.com", Report: &tlsscan.Report{ChainTrusted: true, HostnameMatch: true, WarnDays: 30, Leaf: tlsscan.CertInfo{DaysRemaining: 80}}},
	}
	var empty bytes.Buffer
	WriteBatchTable(&empty, allHealthy, false, true)
	if empty.Len() != 0 {
		t.Errorf("quiet table for all-healthy hosts wrote output:\n%s", empty.String())
	}
}

// TestWriteBatchJSON verifies the batch array carries full reports for scanned
// hosts and {host,error} objects for failures, and that quiet filters healthy
// entries.
func TestWriteBatchJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteBatchJSON(&buf, batchRows(), false); err != nil {
		t.Fatalf("WriteBatchJSON error: %v", err)
	}

	var items []json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("batch JSON is not an array: %v\n%s", err, buf.String())
	}
	if len(items) != 5 {
		t.Fatalf("batch JSON length = %d; want 5", len(items))
	}

	// The first item (errors sort first) must be a {host,error} object.
	var fail struct {
		Host  string `json:"host"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(items[0], &fail); err != nil || fail.Host != "broken.example.com" || fail.Error == "" {
		t.Errorf("first item not the failure object: %+v err=%v\n%s", fail, err, string(items[0]))
	}

	// Quiet filters healthy hosts out of the array.
	var quietBuf bytes.Buffer
	if err := WriteBatchJSON(&quietBuf, batchRows(), true); err != nil {
		t.Fatalf("WriteBatchJSON quiet error: %v", err)
	}
	if strings.Contains(quietBuf.String(), "healthy.example.com") {
		t.Errorf("quiet batch JSON included a healthy host:\n%s", quietBuf.String())
	}

	// Quiet with every host healthy writes nothing (not an empty array), so a
	// clean cron check produces no output on either the text or JSON path.
	allHealthy := []BatchRow{
		{Host: "a.example.com", Report: &tlsscan.Report{ChainTrusted: true, HostnameMatch: true, WarnDays: 30, Leaf: tlsscan.CertInfo{DaysRemaining: 90}}},
	}
	var silent bytes.Buffer
	if err := WriteBatchJSON(&silent, allHealthy, true); err != nil {
		t.Fatalf("WriteBatchJSON all-healthy quiet error: %v", err)
	}
	if silent.Len() != 0 {
		t.Errorf("quiet JSON for all-healthy hosts wrote output:\n%s", silent.String())
	}
}

// sweepFixture returns a deterministic sweep result covering every status word.
func sweepFixture() *tlsscan.SweepResult {
	notAfter := time.Date(2025, time.June, 1, 0, 0, 0, 0, time.UTC)
	return &tlsscan.SweepResult{
		Host: "example.com",
		Ports: []tlsscan.PortResult{
			{Port: 80, Proto: "tls", Open: false},
			{Port: 443, Proto: "https", Open: true, TLS: true, SubjectCN: "example.com", NotAfter: notAfter, DaysRemaining: 90},
			{Port: 587, Proto: "smtp", Open: true, TLS: true, SubjectCN: "mail.example.com", DaysRemaining: 10},
			{Port: 993, Proto: "imaps", Open: true, TLS: true, SubjectCN: "old.example.com", DaysRemaining: -2, Expired: true},
			{Port: 22, Proto: "tls", Open: true, TLS: false, Error: "no TLS"},
		},
	}
}

// TestWriteSweepText verifies the sweep table header, per-port rows, and the
// status word for each outcome.
func TestWriteSweepText(t *testing.T) {
	var buf bytes.Buffer
	WriteSweepText(&buf, sweepFixture(), false)
	out := buf.String()

	for _, want := range []string{
		"PORT", "PROTO", "CERT", "STATUS",
		"443", "https", "example.com", "VALID",
		"587", "smtp", "EXPIRING 10d",
		"993", "imaps", "EXPIRED",
		"80", "closed",
		"22", "no TLS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sweep table missing %q\n---\n%s", want, out)
		}
	}
}

// TestSweepStatus verifies the status mapping in isolation.
func TestSweepStatus(t *testing.T) {
	tests := []struct {
		name string
		in   tlsscan.PortResult
		want string
	}{
		{name: "closed", in: tlsscan.PortResult{Open: false}, want: "closed"},
		{name: "open no tls", in: tlsscan.PortResult{Open: true, TLS: false}, want: "no TLS"},
		{name: "expired", in: tlsscan.PortResult{Open: true, TLS: true, Expired: true, DaysRemaining: -1}, want: "EXPIRED"},
		{name: "expiring", in: tlsscan.PortResult{Open: true, TLS: true, DaysRemaining: 5}, want: "EXPIRING 5d"},
		{name: "at boundary expiring", in: tlsscan.PortResult{Open: true, TLS: true, DaysRemaining: sweepWarnDays}, want: "EXPIRING 30d"},
		{name: "valid", in: tlsscan.PortResult{Open: true, TLS: true, DaysRemaining: sweepWarnDays + 1}, want: "VALID"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := sweepStatus(tc.in)
			if got != tc.want {
				t.Errorf("sweepStatus(%+v) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestWriteSweepJSON verifies the sweep result round-trips through JSON.
func TestWriteSweepJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSweepJSON(&buf, sweepFixture()); err != nil {
		t.Fatalf("WriteSweepJSON error: %v", err)
	}
	var got tlsscan.SweepResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("sweep JSON did not round-trip: %v", err)
	}
	if got.Host != "example.com" || len(got.Ports) != 5 {
		t.Errorf("sweep JSON = %+v; want host example.com with 5 ports", got)
	}
	if !strings.Contains(buf.String(), "\n  \"host\":") {
		t.Errorf("sweep JSON is not 2-space indented:\n%s", buf.String())
	}
}

// TestRowIsHealthyIgnoresDeadSANs confirms quiet's health predicate matches the
// exit-code contract: a dead SAN does not make a row unhealthy.
func TestRowIsHealthyIgnoresDeadSANs(t *testing.T) {
	r := &tlsscan.Report{
		ChainTrusted:  true,
		HostnameMatch: true,
		WarnDays:      30,
		DeadSANs:      2,
		Leaf:          tlsscan.CertInfo{DaysRemaining: 90},
	}
	if !rowIsHealthy(BatchRow{Host: "x", Report: r}) {
		t.Errorf("row with dead SANs but valid cert should be healthy for quiet mode")
	}
}

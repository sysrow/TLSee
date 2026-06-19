// Package tlsscan connects to a TLS endpoint, retrieves the presented
// certificate chain, and reports detailed information about it.
//
// Verification is intentionally skipped during the handshake so that any
// certificate can be inspected, including expired, self-signed, or
// wrong-host certificates. Trust and hostname matching are evaluated
// separately and reported as independent facts.
package tlsscan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Options controls how a scan is performed.
type Options struct {
	// Port overrides the port to connect to when the target does not
	// include one. Defaults to "443".
	Port string
	// Timeout bounds the dial and handshake. Defaults to 10s.
	Timeout time.Duration
	// ServerName overrides the SNI sent during the handshake. When empty,
	// the host parsed from the target is used.
	ServerName string
	// ResolveDNS controls whether the host's A/AAAA records are looked up.
	// It is ignored for IP literals.
	ResolveDNS bool
}

// CertInfo describes a single parsed certificate.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serialNumber"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	DaysRemaining      int       `json:"daysRemaining"`
	Expired            bool      `json:"expired"`
	NotYetValid        bool      `json:"notYetValid"`
	DNSNames           []string  `json:"dnsNames"`
	IPAddresses        []string  `json:"ipAddresses"`
	IsCA               bool      `json:"isCA"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	FingerprintSHA256  string    `json:"fingerprintSHA256"`
}

// Report is the full result of scanning a target.
type Report struct {
	Target        string     `json:"target"`
	Host          string     `json:"host"`
	Port          string     `json:"port"`
	ResolvedIPs   []string   `json:"resolvedIPs"`
	TLSVersion    string     `json:"tlsVersion"`
	CipherSuite   string     `json:"cipherSuite"`
	Leaf          CertInfo   `json:"leaf"`
	Chain         []CertInfo `json:"chain"`
	ChainTrusted  bool       `json:"chainTrusted"`
	HostnameMatch bool       `json:"hostnameMatch"`
	VerifyError   string     `json:"verifyError,omitempty"`
	ElapsedMs     int64      `json:"elapsedMs"`
	// WarnDays is the threshold below which an unexpired certificate is
	// considered "expiring soon". It is carried on the report so that
	// rendering and exit-code logic share a single source of truth without
	// depending on the wall clock.
	WarnDays int `json:"warnDays"`
}

const (
	defaultPort     = "443"
	defaultTimeout  = 10 * time.Second
	defaultWarnDays = 30
)

// Scan connects to target over TLS, retrieves the certificate chain, and
// returns a populated Report. Connection-level failures return a wrapped
// error and a nil report; certificate problems are reported within the
// Report rather than as errors.
func Scan(ctx context.Context, target string, opts Options) (*Report, error) {
	host, port, err := parseTarget(target, opts.Port)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	warnDays := defaultWarnDays

	sni := opts.ServerName
	if sni == "" {
		sni = host
	}

	addr := net.JoinHostPort(host, port)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName: sni,
			// Verification is intentionally skipped so that any
			// certificate can be retrieved and inspected.
			InsecureSkipVerify: true,
		},
	}

	start := time.Now()
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	conn := rawConn.(*tls.Conn)
	defer conn.Close()

	state := conn.ConnectionState()
	elapsed := time.Since(start).Milliseconds()

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("connect %s: server presented no certificates", addr)
	}

	now := time.Now()
	leaf := state.PeerCertificates[0]

	report := &Report{
		Target:      target,
		Host:        host,
		Port:        port,
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Leaf:        certInfo(leaf, now),
		ElapsedMs:   elapsed,
		WarnDays:    warnDays,
	}

	for _, c := range state.PeerCertificates[1:] {
		report.Chain = append(report.Chain, certInfo(c, now))
	}

	// Trust: verify to a system root without any hostname constraint.
	pool := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		pool.AddCert(c)
	}
	if _, verifyErr := leaf.Verify(x509.VerifyOptions{
		Intermediates: pool,
		Roots:         nil,
	}); verifyErr != nil {
		report.ChainTrusted = false
		report.VerifyError = verifyErr.Error()
	} else {
		report.ChainTrusted = true
	}

	// Hostname matching is independent of trust. VerifyHostname also
	// handles IP SANs, so the parsed host is passed directly.
	report.HostnameMatch = leaf.VerifyHostname(host) == nil

	// DNS resolution is best-effort and skipped for IP literals. It is
	// bounded by its own timeout-derived context so a slow resolver cannot
	// make the scan exceed --timeout.
	if opts.ResolveDNS && net.ParseIP(host) == nil {
		lookupCtx, lookupCancel := context.WithTimeout(ctx, timeout)
		defer lookupCancel()
		if ips, lookupErr := net.DefaultResolver.LookupHost(lookupCtx, host); lookupErr == nil {
			report.ResolvedIPs = ips
		}
	}

	return report, nil
}

// parseTarget splits a target into host and port. It strips a leading
// scheme and any trailing path or query, then splits the host and port.
// When no port is present, defaultPortOverride (or 443) is used. IPv6
// literals such as "[::1]:8443" and "[::1]" are handled.
func parseTarget(target, defaultPortOverride string) (host, port string, err error) {
	port = defaultPortOverride
	if port == "" {
		port = defaultPort
	}

	remainder := strings.TrimSpace(target)
	if remainder == "" {
		return "", "", fmt.Errorf("parse target: empty target")
	}

	// Strip a leading scheme such as "https://" or "tls://".
	if i := strings.Index(remainder, "://"); i >= 0 {
		remainder = remainder[i+len("://"):]
	}

	// Strip any trailing path or query. For an IPv6 literal the host is
	// inside brackets, so only look past the closing bracket.
	cut := remainder
	if strings.HasPrefix(remainder, "[") {
		if end := strings.IndexByte(remainder, ']'); end >= 0 {
			cut = remainder[end:]
			if slash := strings.IndexAny(cut, "/?"); slash >= 0 {
				remainder = remainder[:end] + cut[:slash]
			}
		}
	} else if slash := strings.IndexAny(remainder, "/?"); slash >= 0 {
		remainder = remainder[:slash]
	}

	if remainder == "" {
		return "", "", fmt.Errorf("parse target %q: no host", target)
	}

	h, p, splitErr := net.SplitHostPort(remainder)
	if splitErr != nil {
		if strings.Contains(splitErr.Error(), "missing port in address") {
			// No port: treat the whole remainder as the host. Strip
			// brackets from an IPv6 literal so the bare address remains.
			host = strings.TrimSuffix(strings.TrimPrefix(remainder, "["), "]")
			return host, port, nil
		}
		return "", "", fmt.Errorf("parse target %q: %w", target, splitErr)
	}

	if p != "" {
		port = p
	}
	return h, port, nil
}

// certInfo builds a CertInfo from a parsed certificate, evaluating
// validity relative to now.
func certInfo(c *x509.Certificate, now time.Time) CertInfo {
	ips := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}

	sum := sha256.Sum256(c.Raw)

	return CertInfo{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SerialNumber:       c.SerialNumber.String(),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		DaysRemaining:      int(c.NotAfter.Sub(now).Hours() / 24),
		Expired:            now.After(c.NotAfter),
		NotYetValid:        now.Before(c.NotBefore),
		DNSNames:           c.DNSNames,
		IPAddresses:        ips,
		IsCA:               c.IsCA,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		FingerprintSHA256:  formatFingerprint(sum[:]),
	}
}

// formatFingerprint renders a digest as colon-separated uppercase hex.
func formatFingerprint(sum []byte) string {
	const hexDigits = "0123456789ABCDEF"
	b := make([]byte, 0, len(sum)*3)
	for i, v := range sum {
		if i > 0 {
			b = append(b, ':')
		}
		b = append(b, hexDigits[v>>4], hexDigits[v&0x0f])
	}
	return string(b)
}

// tlsVersionName maps a TLS version constant to a friendly string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

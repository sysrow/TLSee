// Command tlsee is a small, friendly TLS certificate inspector.
//
// It connects to a host's TLS port, retrieves the presented certificate
// chain, and prints a clear report covering the certificate's SAN DNS
// names, issuer/subject, validity window, trust status, hostname match,
// negotiated TLS parameters, and the host's resolved DNS records.
package main

import (
	"os"

	"github.com/sysrow/tlsee/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}

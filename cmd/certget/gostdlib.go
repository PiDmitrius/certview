package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"

	"github.com/PiDmitrius/certview/internal/ssrfguard"
)

type GoStdlibFetcher struct{}

func (GoStdlibFetcher) Name() string    { return "go-stdlib" }
func (GoStdlibFetcher) Available() bool { return true }

func (GoStdlibFetcher) Fetch(ctx context.Context, host, ip string, port int, sni string) (*Result, error) {
	dialer := &net.Dialer{Control: ssrfguard.DialerControl}
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// InsecureSkipVerify is intentional — we inspect whatever the server
	// presents, including expired/untrusted/wrong-name certificates.
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         sni,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}
	if len(state.PeerCertificates) > MaxChainLen {
		return nil, fmt.Errorf("chain too long: %d > %d", len(state.PeerCertificates), MaxChainLen)
	}

	chain := make([][]byte, 0, len(state.PeerCertificates))
	for _, c := range state.PeerCertificates {
		if len(c.Raw) > MaxCertSize {
			return nil, fmt.Errorf("cert too big: %d > %d", len(c.Raw), MaxCertSize)
		}
		chain = append(chain, c.Raw)
	}

	return &Result{
		Chain:       chain,
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

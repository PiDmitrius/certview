package dnshost

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// Normalize returns an ASCII hostname suitable for DNS lookup and SNI.
// IP literals are canonicalized; DNS names use the IDNA lookup profile because
// these hosts are used as real connection targets, not as display strings.
func Normalize(host string) (string, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return "", errors.New("empty host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("idna host %q: %w", host, err)
	}
	return ascii, nil
}

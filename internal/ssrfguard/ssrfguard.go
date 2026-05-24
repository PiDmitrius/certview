// Package ssrfguard rejects connections to private, loopback, link-local,
// multicast, or unspecified addresses. Used by both certview and certget.
package ssrfguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

var ErrBlocked = errors.New("address is not a public unicast address")

// Check validates that host is either an allowed IP literal or a name that
// resolves only to allowed addresses. An address is allowed if it is a global
// unicast IP — i.e. not unspecified, loopback, private (RFC1918 / ULA),
// link-local, or multicast.
//
// IPv4-mapped IPv6 addresses are unwrapped, so ::ffff:127.0.0.1 is rejected
// just like 127.0.0.1.
func Check(ctx context.Context, host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		if err := checkAddr(addr); err != nil {
			return fmt.Errorf("%s: %w", host, err)
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("resolve %s: no addresses", host)
	}
	for _, a := range addrs {
		if err := checkAddr(a); err != nil {
			return fmt.Errorf("%s → %s: %w", host, a, err)
		}
	}
	return nil
}

// DialerControl is suitable for net.Dialer.Control. It re-checks the resolved
// peer address at connect time, closing the TOCTOU window between Check and
// the actual TCP connect (DNS rebinding, cache flips).
func DialerControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrfguard: parse %q: %w", address, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("ssrfguard: parse addr %q: %w", host, err)
	}
	if err := checkAddr(addr); err != nil {
		return fmt.Errorf("ssrfguard: %s: %w", host, err)
	}
	return nil
}

// IANA special-purpose ranges that are not "public unicast" but are not
// covered by netip.Addr's predicates. Listed explicitly so the set is
// auditable; covers CGNAT, benchmark, TEST-NETs, IETF protocol assignments,
// reserved class E, NAT64, discard, and documentation ranges.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 CGNAT
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmark
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF Protocol Assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved (class E)
	netip.MustParsePrefix("64:ff9b::/96"),    // RFC 6052 NAT64 well-known
	netip.MustParsePrefix("100::/64"),        // RFC 6666 discard
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),   // RFC 3849 documentation
	netip.MustParsePrefix("3fff::/20"),       // RFC 9637 documentation
}

func checkAddr(addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.IsValid() ||
		addr.IsUnspecified() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() {
		return ErrBlocked
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return ErrBlocked
		}
	}
	return nil
}

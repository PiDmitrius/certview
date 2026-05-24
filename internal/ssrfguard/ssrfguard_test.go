package ssrfguard

import (
	"net/netip"
	"testing"
)

func TestCheckAddr(t *testing.T) {
	tests := []struct {
		addr    string
		blocked bool
	}{
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"2001:4860:4860::8888", false},
		{"2606:4700:4700::1111", false},

		{"127.0.0.1", true},
		{"127.255.255.254", true},
		{"::1", true},

		{"0.0.0.0", true},
		{"::", true},

		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"192.168.0.1", true},

		{"fc00::1", true},
		{"fd12:3456:789a::1", true},

		{"169.254.169.254", true},
		{"fe80::1", true},

		{"224.0.0.1", true},
		{"ff02::1", true},

		{"::ffff:127.0.0.1", true},
		{"::ffff:10.0.0.1", true},
		{"::ffff:8.8.8.8", false},

		// special-purpose IPv4 (RFC 6890, not covered by netip predicates)
		{"100.64.0.1", true},      // CGNAT
		{"100.127.255.254", true}, // CGNAT upper
		{"100.128.0.1", false},    // outside CGNAT
		{"198.18.0.1", true},      // benchmark
		{"198.19.255.254", true},  // benchmark upper
		{"198.20.0.1", false},     // outside benchmark
		{"192.0.0.1", true},       // IETF protocol assignments
		{"192.0.2.1", true},       // TEST-NET-1
		{"198.51.100.5", true},    // TEST-NET-2
		{"203.0.113.50", true},    // TEST-NET-3
		{"240.0.0.1", true},       // class E reserved

		// special-purpose IPv6
		{"64:ff9b::1", true},  // NAT64 well-known
		{"100::1", true},      // discard
		{"2001::1", true},     // IETF protocol assignments
		{"2001:db8::1", true}, // documentation
		{"2001:4860::1", false}, // Google DNS, outside 2001::/23
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			err := checkAddr(addr)
			got := err != nil
			if got != tt.blocked {
				t.Errorf("checkAddr(%s): blocked=%v want %v (err=%v)", tt.addr, got, tt.blocked, err)
			}
		})
	}
}

func TestCheckIPLiteral(t *testing.T) {
	if err := Check(t.Context(), "127.0.0.1"); err == nil {
		t.Error("expected error for 127.0.0.1")
	}
	if err := Check(t.Context(), "8.8.8.8"); err != nil {
		t.Errorf("expected ok for 8.8.8.8, got %v", err)
	}
}

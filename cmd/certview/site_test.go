package main

import "testing"

func TestNormalizeSiteURLIDNA(t *testing.T) {
	host, port, err := normalizeSiteURL("госуслуги.рф")
	if err != nil {
		t.Fatalf("normalizeSiteURL: %v", err)
	}
	if host != "xn--c1aapkosapc.xn--p1ai" {
		t.Fatalf("host = %q, want punycode", host)
	}
	if port != 443 {
		t.Fatalf("port = %d, want 443", port)
	}
}

func TestSplitHostPortIDNA(t *testing.T) {
	host, port, err := splitHostPort("госуслуги.рф:8443")
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}
	if host != "xn--c1aapkosapc.xn--p1ai" {
		t.Fatalf("host = %q, want punycode", host)
	}
	if port != 8443 {
		t.Fatalf("port = %d, want 8443", port)
	}
}

func TestSplitHostPortRejectsBracketedDNSName(t *testing.T) {
	if _, _, err := splitHostPort("[notanaddress]:443"); err == nil {
		t.Fatal("splitHostPort accepted bracketed non-IPv6 host")
	}
}

func TestSplitHostPortRejectsWhitespaceInBracketedIPv6(t *testing.T) {
	if _, _, err := splitHostPort("[ ::1 ]:443"); err == nil {
		t.Fatal("splitHostPort accepted whitespace inside bracketed IPv6 host")
	}
}

package dnshost

import "testing"

func TestNormalizeIDNA(t *testing.T) {
	host, err := Normalize("госуслуги.рф")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if host != "xn--c1aapkosapc.xn--p1ai" {
		t.Fatalf("host = %q, want punycode", host)
	}
}

func TestNormalizeIPLiteral(t *testing.T) {
	host, err := Normalize("2001:DB8::1")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if host != "2001:db8::1" {
		t.Fatalf("host = %q, want canonical IPv6", host)
	}
}

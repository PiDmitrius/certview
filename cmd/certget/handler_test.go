package main

import "testing"

func TestNormalizeURLIDNA(t *testing.T) {
	host, port, err := normalizeURL("госуслуги.рф")
	if err != nil {
		t.Fatalf("normalizeURL: %v", err)
	}
	if host != "xn--c1aapkosapc.xn--p1ai" {
		t.Fatalf("host = %q, want punycode", host)
	}
	if port != 443 {
		t.Fatalf("port = %d, want 443", port)
	}
}

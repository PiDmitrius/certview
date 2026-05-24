// certget is a stateless TLS-handshake probe with pluggable backends
// (currently Go crypto/tls and openssl s_client + gost-engine).
//
// Contract:
//
//   - Stateless. No disk, no caches, no deduplication, no history. Every
//     POST /fetch is a fresh TCP+TLS handshake; nothing about previous
//     requests influences the result. Restart loses nothing because there
//     is nothing to lose.
//
//   - Does only what the caller asked. No chain building, no AIA fetching,
//     no CRL/OCSP checking, no trust evaluation, no application-layer I/O
//     (the connection is closed right after the handshake — no "GET /"
//     is ever sent). InsecureSkipVerify=true: whatever the server presents
//     is returned verbatim.
//
//   - Not exposed to the public internet. Deployment assumes a trusted
//     internal network (e.g. a Docker compose service reachable only by
//     sibling containers). There is no authentication. Don't bind to a
//     public address.
//
//   - SSRF guard still applies. As defence-in-depth, certget independently
//     rejects private/loopback/link-local/multicast targets even if the
//     caller forgot to. This is the one safety floor it enforces.
//
//   - Rate-limiting, request coalescing (singleflight), result caching,
//     trust decisions, and any persistence are the caller's job. certview
//     is the canonical caller and owns all of that.
package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", ":9090", "listen address")
	flag.Parse()

	all := []Fetcher{
		GoStdlibFetcher{},
		OpensslGostFetcher{},
	}
	var available []Fetcher
	for _, f := range all {
		if f.Available() {
			available = append(available, f)
			log.Printf("fetcher enabled: %s", f.Name())
		} else {
			log.Printf("fetcher unavailable: %s", f.Name())
		}
	}
	if len(available) == 0 {
		log.Fatal("no fetchers available")
	}

	h := &handler{fetchers: available}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fetch", h.fetch)

	log.Printf("certget listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

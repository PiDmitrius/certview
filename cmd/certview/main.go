package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PiDmitrius/certview/internal/pki"
	"github.com/PiDmitrius/certview/internal/ssrfguard"
	"github.com/PiDmitrius/certview/internal/store"
	"github.com/PiDmitrius/certview/internal/trustbundle"
	"github.com/PiDmitrius/certview/web"
)

// newGuardedHTTPClient returns an http.Client whose dialer and redirect
// handler both reject SSRF targets (private, loopback, link-local, multicast,
// CGNAT, TEST-NET, etc — see internal/ssrfguard). Use it for any request
// whose URL comes from the wire: AIA, CRL, OCSP, anything pointed at by a
// remote certificate.
func newGuardedHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: ssrfguard.DialerControl}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				if err := ssrfguard.Check(ctx, host); err != nil {
					return nil, fmt.Errorf("ssrfguard: %w", err)
				}
				return dialer.DialContext(ctx, network, address)
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return ssrfguard.Check(req.Context(), req.URL.Hostname())
		},
	}
}

func main() {
	addr := flag.String("addr", ":8080", "public listen address (read-only)")
	adminAddr := flag.String("admin-addr", "", "admin listen address (with trust controls); empty to disable")
	dbPath := flag.String("db", "certview.db", "SQLite database path")
	siteCacheTTL := flag.Duration("site-cache-ttl", 60*time.Second, "site fetch cache TTL per (host,port,sni); 0 to disable")
	flag.Parse()

	ctx, err := pki.Open()
	if err != nil {
		log.Fatalf("pki.Open: %v", err)
	}
	defer ctx.Close()

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	if err := trustbundle.ImportDefaults(ctx, db); err != nil {
		log.Printf("trustbundle.ImportDefaults: %v", err)
	}

	client := newGuardedHTTPClient(60 * time.Second)
	internalClient := &http.Client{Timeout: 60 * time.Second}
	certgetURL := os.Getenv("CERTGET_URL")
	var pubSC, admSC *siteCache
	if certgetURL != "" {
		log.Printf("site fetch enabled via %s", certgetURL)
		if *siteCacheTTL > 0 {
			// Separate caches per listener so `IsAdmin` and any other
			// listener-specific UI hints never cross the public/admin boundary.
			pubSC = newSiteCache(*siteCacheTTL)
			admSC = newSiteCache(*siteCacheTTL)
			log.Printf("site cache enabled, ttl=%s", *siteCacheTTL)
		}
	}

	indexBytes, err := web.Static.ReadFile("index.html")
	if err != nil {
		log.Fatalf("web/index.html: %v", err)
	}
	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexBytes)
	}

	fileServer := http.FileServerFS(web.Static)
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never let unmatched /api/* paths fall through into the SPA shell:
		// API calls expect API errors, and serving HTML 200 here misleads
		// callers (e.g. POST /api/trust on the public listener would otherwise
		// appear successful in the browser).
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		// SPA fallback: any other path that doesn't match a real static file
		// is served the SPA, which parses location.pathname itself
		// (a hostname like "/www.gosuslugi.ru" routes to site fetch).
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			serveIndex(w, r)
			return
		}
		if _, err := web.Static.Open(p); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		serveIndex(w, r)
	})

	mount := func(mux *http.ServeMux, h *handler) {
		mux.HandleFunc("POST /api/analyze", h.analyze)
		mux.HandleFunc("GET /api/cert/{thumbprint}", h.analyzeByThumbprint)
		mux.HandleFunc("POST /api/site", h.analyzeSite)
		mux.HandleFunc("GET /api/site/{hostport}", h.analyzeSiteByHostPort)
		mux.HandleFunc("GET /api/config", h.config)
		mux.Handle("/", rootHandler)
	}

	pub := &handler{ctx: ctx, store: db, client: client, isAdmin: false, certgetURL: certgetURL, siteCache: pubSC, internalClient: internalClient}
	pubMux := http.NewServeMux()
	mount(pubMux, pub)

	log.Printf("public listening on %s, db: %s", *addr, *dbPath)
	go func() {
		log.Fatal(http.ListenAndServe(*addr, pubMux))
	}()

	if *adminAddr != "" {
		adm := &handler{ctx: ctx, store: db, client: client, isAdmin: true, certgetURL: certgetURL, siteCache: admSC, internalClient: internalClient}
		admMux := http.NewServeMux()
		mount(admMux, adm)
		admMux.HandleFunc("POST /api/trust", adm.trust)
		admMux.HandleFunc("POST /api/untrust", adm.untrust)

		log.Printf("admin listening on %s", *adminAddr)
		log.Fatal(http.ListenAndServe(*adminAddr, admMux))
	} else {
		select {}
	}
}

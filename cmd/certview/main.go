package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PiDmitrius/certview/internal/limits"
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
// remote certificate. A request fails when no data arrives for idle, however
// long a slow but progressing download takes, up to the overall timeout.
func newGuardedHTTPClient(idle, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: ssrfguard.DialerControl}
	return &http.Client{
		Timeout: timeout,
		Transport: idleTimeoutTransport{idle: idle, base: &http.Transport{
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     idle,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				if err := ssrfguard.Check(ctx, host); err != nil {
					return nil, &unreachableError{address, fmt.Errorf("ssrfguard: %w", err)}
				}
				conn, err := dialer.DialContext(ctx, network, address)
				if err != nil {
					return nil, &unreachableError{address, err}
				}
				return conn, nil
			},
		}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return ssrfguard.Check(req.Context(), req.URL.Hostname())
		},
	}
}

var errIdleTimeout = errors.New("no data received within idle timeout")

type idleTimeoutTransport struct {
	idle time.Duration
	base http.RoundTripper
}

func (t idleTimeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(req.Context())
	timer := time.AfterFunc(t.idle, func() { cancel(errIdleTimeout) })
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		timer.Stop()
		if context.Cause(ctx) == errIdleTimeout {
			err = errIdleTimeout
		}
		cancel(nil)
		return nil, err
	}
	resp.Body = &idleBody{ReadCloser: resp.Body, ctx: ctx, cancel: cancel, timer: timer, idle: t.idle}
	return resp, nil
}

type idleBody struct {
	io.ReadCloser
	ctx    context.Context
	cancel context.CancelCauseFunc
	timer  *time.Timer
	idle   time.Duration
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.timer.Reset(b.idle)
	}
	if err != nil && context.Cause(b.ctx) == errIdleTimeout {
		err = errIdleTimeout
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	b.cancel(nil)
	return b.ReadCloser.Close()
}

func main() {
	addr := flag.String("addr", ":8080", "public listen address (read-only)")
	adminAddr := flag.String("admin-addr", "", "admin listen address (with trust controls); empty to disable")
	dbPath := flag.String("db", "certview.db", "SQLite database path")
	cacheTTL := flag.Duration("cache-ttl", 60*time.Second, "how long site fetches, analyses and fetch failures are remembered; 0 to disable")
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

	client := newGuardedHTTPClient(30*time.Second, 10*time.Minute)
	go runWatchdog()
	internalClient := &http.Client{Timeout: 60 * time.Second}
	certgetURL := os.Getenv("CERTGET_URL")
	// Separate caches per listener so `IsAdmin` and any other listener-specific
	// UI hints never cross the public/admin boundary.
	inflight.failTTL = *cacheTTL
	pubAC := newRespCache[analyzeResponse](*cacheTTL)
	admAC := newRespCache[analyzeResponse](*cacheTTL)
	var pubSC, admSC *respCache[siteResponse]
	if certgetURL != "" {
		log.Printf("site fetch enabled via %s", certgetURL)
		pubSC = newRespCache[siteResponse](*cacheTTL)
		admSC = newRespCache[siteResponse](*cacheTTL)
	}
	log.Printf("cache ttl=%s", *cacheTTL)

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
		mux.HandleFunc("GET /api/der/{sha256}", h.derBySHA256)
		mux.HandleFunc("POST /api/site", h.analyzeSite)
		mux.HandleFunc("GET /api/site/{hostport}", h.analyzeSiteByHostPort)
		mux.HandleFunc("GET /api/config", h.config)
		mux.Handle("/", rootHandler)
	}

	pub := &handler{ctx: ctx, store: db, client: client, isAdmin: false, certgetURL: certgetURL, siteCache: pubSC, analysisCache: pubAC, internalClient: internalClient}
	pubMux := http.NewServeMux()
	mount(pubMux, pub)

	log.Printf("public listening on %s, db: %s", *addr, *dbPath)
	go func() {
		log.Fatal(limits.ListenAndServe(*addr, pubMux))
	}()

	if *adminAddr != "" {
		adm := &handler{ctx: ctx, store: db, client: client, isAdmin: true, certgetURL: certgetURL, siteCache: admSC, analysisCache: admAC, internalClient: internalClient}
		admMux := http.NewServeMux()
		mount(admMux, adm)
		admMux.HandleFunc("POST /api/trust", adm.trust)
		admMux.HandleFunc("POST /api/untrust", adm.untrust)

		log.Printf("admin listening on %s", *adminAddr)
		log.Fatal(limits.ListenAndServe(*adminAddr, admMux))
	} else {
		select {}
	}
}

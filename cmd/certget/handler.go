package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PiDmitrius/certview/internal/dnshost"
	"github.com/PiDmitrius/certview/internal/ssrfguard"
)

var reqCounter atomic.Uint64

type handler struct {
	fetchers []Fetcher
}

type fetchRequest struct {
	URL       string `json:"url"`
	SNI       string `json:"sni"`
	TimeoutMs int    `json:"timeout_ms"`
}

type fetchResponse struct {
	FetchedAt time.Time      `json:"fetched_at"`
	Host      string         `json:"host"`
	IP        string         `json:"ip"`
	Port      int            `json:"port"`
	SNI       string         `json:"sni"`
	Results   []fetchOutcome `json:"results"`
}

type fetchOutcome struct {
	Client      string   `json:"client"`
	OK          bool     `json:"ok"`
	Error       string   `json:"error,omitempty"`
	Chain       []string `json:"chain,omitempty"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	CipherSuite string   `json:"cipher_suite,omitempty"`
	DurationMs  int64    `json:"duration_ms"`
}

func (h *handler) fetch(w http.ResponseWriter, r *http.Request) {
	rl := reqLog{id: reqCounter.Add(1)}

	var req fetchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	host, port, err := normalizeURL(req.URL)
	if err != nil {
		rl.f("normalize: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sni := req.SNI
	if sni == "" {
		sni = host
	}

	const maxRequestTimeout = 60 * time.Second
	timeout := 30 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
		if timeout > maxRequestTimeout {
			timeout = maxRequestTimeout
		}
	}

	rl.f("fetch host=%s port=%d sni=%s timeout=%s", host, port, sni, timeout)

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	ip, err := resolveAndGuard(ctx, host)
	if err != nil {
		rl.f("guard: %v", err)
		http.Error(w, "blocked: "+err.Error(), http.StatusForbidden)
		return
	}
	rl.f("resolved %s → %s", host, ip)

	outcomes := h.runAll(ctx, rl, host, ip, port, sni)

	resp := fetchResponse{
		FetchedAt: time.Now().UTC(),
		Host:      host,
		IP:        ip,
		Port:      port,
		SNI:       sni,
		Results:   outcomes,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *handler) runAll(ctx context.Context, rl reqLog, host, ip string, port int, sni string) []fetchOutcome {
	outcomes := make([]fetchOutcome, len(h.fetchers))
	var wg sync.WaitGroup
	for i, f := range h.fetchers {
		wg.Add(1)
		go func(i int, f Fetcher) {
			defer wg.Done()
			start := time.Now()
			res, err := f.Fetch(ctx, host, ip, port, sni)
			dur := time.Since(start)
			o := fetchOutcome{Client: f.Name(), DurationMs: dur.Milliseconds()}
			if err != nil {
				o.Error = err.Error()
				rl.f("%s: FAIL %v (%dms)", f.Name(), err, dur.Milliseconds())
			} else {
				o.OK = true
				o.TLSVersion = res.TLSVersion
				o.CipherSuite = res.CipherSuite
				o.Chain = derToPEM(res.Chain)
				rl.f("%s: OK %d certs %s %s (%dms)",
					f.Name(), len(res.Chain), res.TLSVersion, res.CipherSuite, dur.Milliseconds())
			}
			outcomes[i] = o
		}(i, f)
	}
	wg.Wait()
	return outcomes
}

// resolveAndGuard returns a single allowed IP literal for host. If host is
// already an IP literal it is checked and returned. If host is a DNS name,
// every resolved address must pass the guard, and we return the first one to
// pin further dials to that exact address (defeats DNS rebinding between
// resolutions in different subprocesses).
func resolveAndGuard(ctx context.Context, host string) (string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if err := ssrfguard.Check(ctx, host); err != nil {
			return "", err
		}
		return addr.String(), nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("resolve %s: no addresses", host)
	}
	// Validate every resolved address (a single bad one rejects the host).
	for _, a := range addrs {
		if err := ssrfguard.Check(ctx, a.String()); err != nil {
			return "", err
		}
	}
	return addrs[0].String(), nil
}

func normalizeURL(input string) (string, int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", 0, fmt.Errorf("empty url")
	}
	if !strings.Contains(input, "://") {
		input = "https://" + input
	}
	u, err := url.Parse(input)
	if err != nil {
		return "", 0, fmt.Errorf("parse url: %w", err)
	}
	host, err := dnshost.Normalize(u.Hostname())
	if err != nil {
		return "", 0, err
	}
	port := 443
	if p := u.Port(); p != "" {
		v, err := strconv.Atoi(p)
		if err != nil || v < 1 || v > 65535 {
			return "", 0, fmt.Errorf("bad port %q", p)
		}
		port = v
	}
	return host, port, nil
}

func derToPEM(ders [][]byte) []string {
	out := make([]string, 0, len(ders))
	for _, der := range ders {
		out = append(out, string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})))
	}
	return out
}

type reqLog struct {
	id uint64
}

func (r reqLog) f(format string, args ...any) {
	log.Printf("[r%04d] %s", r.id, fmt.Sprintf(format, args...))
}

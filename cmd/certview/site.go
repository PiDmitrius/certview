package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/PiDmitrius/certview/internal/dnshost"
	"github.com/PiDmitrius/certview/internal/ssrfguard"
)

type siteRequest struct {
	URL string `json:"url"`
}

type siteResponse struct {
	Cached    bool         `json:"cached,omitempty"`
	FetchedAt string       `json:"fetched_at,omitempty"`
	Host      string       `json:"host"`
	IP        string       `json:"ip,omitempty"`
	Port      int          `json:"port"`
	SNI       string       `json:"sni"`
	Results   []siteResult `json:"results"`
}

type siteResult struct {
	Client      string           `json:"client"`
	OK          bool             `json:"ok"`
	Error       string           `json:"error,omitempty"`
	TLSVersion  string           `json:"tls_version,omitempty"`
	CipherSuite string           `json:"cipher_suite,omitempty"`
	DurationMs  int64            `json:"duration_ms"`
	Analysis    *analyzeResponse `json:"analysis,omitempty"`
}

// Mirror of certget's response shape — only the bits we consume.
type certgetResponse struct {
	FetchedAt string `json:"fetched_at"`
	Host      string `json:"host"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	SNI       string `json:"sni"`
	Results   []struct {
		Client      string   `json:"client"`
		OK          bool     `json:"ok"`
		Error       string   `json:"error,omitempty"`
		Chain       []string `json:"chain,omitempty"`
		TLSVersion  string   `json:"tls_version,omitempty"`
		CipherSuite string   `json:"cipher_suite,omitempty"`
		DurationMs  int64    `json:"duration_ms"`
	} `json:"results"`
}

func (h *handler) config(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"site_enabled": h.certgetURL != "",
		"is_admin":     h.isAdmin,
	})
}

func (h *handler) analyzeSite(w http.ResponseWriter, r *http.Request) {
	var req siteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	host, port, err := normalizeSiteURL(req.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.respondSite(w, r, host, port, host)
}

func (h *handler) analyzeSiteByHostPort(w http.ResponseWriter, r *http.Request) {
	hp := r.PathValue("hostport")
	if hp == "" {
		http.Error(w, "missing hostport", http.StatusBadRequest)
		return
	}
	host, port, err := splitHostPort(hp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.respondSite(w, r, host, port, host)
}

func (h *handler) respondSite(w http.ResponseWriter, r *http.Request, host string, port int, sni string) {
	if h.certgetURL == "" {
		http.Error(w, "site fetch not configured (CERTGET_URL empty)", http.StatusServiceUnavailable)
		return
	}
	if err := ssrfguard.Check(r.Context(), host); err != nil {
		http.Error(w, "blocked: "+err.Error(), http.StatusForbidden)
		return
	}

	// Cache + singleflight: parallel callers on the same (host,port,sni) wait
	// for one fetch+analyze pass; fresh entries are served without certget contact.
	var entry *siteCacheEntry
	if h.siteCache != nil {
		key := fmt.Sprintf("%s|%d|%s", host, port, sni)
		entry = h.siteCache.entryFor(key)
		entry.mu.Lock()
		if cached := entry.fresh(); cached != nil {
			entry.mu.Unlock()
			respCopy := *cached
			respCopy.Cached = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(respCopy)
			return
		}
		defer entry.mu.Unlock()
	}

	resp, err := h.doAnalyzeSite(r.Context(), host, port, sni)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if entry != nil {
		entry.store(resp, h.siteCache.ttl)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *handler) doAnalyzeSite(ctx context.Context, host string, port int, sni string) (*siteResponse, error) {
	rl := reqLog{id: reqCounter.Add(1)}
	rl.f("site: host=%s port=%d sni=%s", host, port, sni)

	cgResp, err := h.callCertget(ctx, host, port, sni)
	if err != nil {
		rl.f("site: certget call failed: %v", err)
		return nil, err
	}
	rl.f("site: certget returned %d results", len(cgResp.Results))

	out := &siteResponse{
		FetchedAt: cgResp.FetchedAt,
		Host:      cgResp.Host,
		IP:        cgResp.IP,
		Port:      cgResp.Port,
		SNI:       cgResp.SNI,
	}
	for _, r := range cgResp.Results {
		sr := siteResult{
			Client:      r.Client,
			OK:          r.OK,
			Error:       r.Error,
			TLSVersion:  r.TLSVersion,
			CipherSuite: r.CipherSuite,
			DurationMs:  r.DurationMs,
		}
		if !r.OK {
			rl.f("site: %s FAIL: %s", r.Client, r.Error)
			out.Results = append(out.Results, sr)
			continue
		}
		ders, err := decodePEMBundle(r.Chain)
		if err != nil {
			sr.OK = false
			sr.Error = err.Error()
			rl.f("site: %s decode chain failed: %v", r.Client, err)
			out.Results = append(out.Results, sr)
			continue
		}
		if len(ders) == 0 {
			sr.OK = false
			sr.Error = "empty chain"
			out.Results = append(out.Results, sr)
			continue
		}

		// Pre-cache intermediates so doAnalyze's resolveIssuer finds them in store.
		sourceURL := fmt.Sprintf("tls://%s:%d?via=%s", host, port, r.Client)
		for _, der := range ders[1:] {
			info, err := h.ctx.ParseCertInfo(der)
			if err != nil {
				rl.f("site: %s skip intermediate (parse): %v", r.Client, err)
				continue
			}
			if err := h.store.SaveCert(
				info.Subject, info.Issuer, info.Serial,
				info.SKI, info.AKI, info.SubjectNameDER,
				info.DER, info.IsCA, info.IsSelfSigned, sourceURL,
			); err != nil {
				rl.f("site: %s store.SaveCert intermediate: %v", r.Client, err)
			}
		}

		analysis := h.doAnalyze(ders[0])
		// Leaf came from TLS, not from an upload — label it for the UI.
		if len(analysis.Chain) > 0 {
			analysis.Chain[0].Source = "tls"
		}
		sr.Analysis = analysis
		out.Results = append(out.Results, sr)
		rl.f("site: %s analyzed (%d chain certs)", r.Client, len(analysis.Chain))
	}
	return out, nil
}

func (h *handler) callCertget(ctx context.Context, host string, port int, sni string) (*certgetResponse, error) {
	body, _ := json.Marshal(map[string]any{
		"url": "https://" + net.JoinHostPort(host, strconv.Itoa(port)),
		"sni": sni,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.certgetURL+"/fetch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.internalClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certget: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("certget HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	var cg certgetResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&cg); err != nil {
		return nil, fmt.Errorf("certget decode: %w", err)
	}
	return &cg, nil
}

func decodePEMBundle(blocks []string) ([][]byte, error) {
	var out [][]byte
	for _, block := range blocks {
		rest := []byte(block)
		for {
			b, r := pem.Decode(rest)
			if b == nil {
				break
			}
			rest = r
			if b.Type != "CERTIFICATE" {
				continue
			}
			out = append(out, b.Bytes)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM CERTIFICATE blocks")
	}
	return out, nil
}

func normalizeSiteURL(input string) (string, int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", 0, errors.New("empty url")
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

func splitHostPort(hp string) (string, int, error) {
	if hp == "" {
		return "", 0, errors.New("empty hostport")
	}
	// IPv6 literal with port: [::1]:443
	if strings.HasPrefix(hp, "[") {
		end := strings.LastIndex(hp, "]")
		if end < 0 {
			return "", 0, errors.New("malformed IPv6 literal")
		}
		addr, err := netip.ParseAddr(hp[1:end])
		if err != nil || !addr.Is6() {
			return "", 0, errors.New("malformed IPv6 literal")
		}
		host := addr.String()
		port := 443
		if end+1 < len(hp) {
			if hp[end+1] != ':' {
				return "", 0, errors.New("expected ':' after ']'")
			}
			v, err := strconv.Atoi(hp[end+2:])
			if err != nil || v < 1 || v > 65535 {
				return "", 0, fmt.Errorf("bad port %q", hp[end+2:])
			}
			port = v
		}
		return host, port, nil
	}
	host, port := hp, 443
	if i := strings.LastIndex(hp, ":"); i >= 0 {
		host = hp[:i]
		v, err := strconv.Atoi(hp[i+1:])
		if err != nil || v < 1 || v > 65535 {
			return "", 0, fmt.Errorf("bad port %q", hp[i+1:])
		}
		port = v
	}
	host, err := dnshost.Normalize(host)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

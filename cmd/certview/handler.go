package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PiDmitrius/certview/internal/limits"
	"github.com/PiDmitrius/certview/internal/pki"
	"github.com/PiDmitrius/certview/internal/store"
)

var reqCounter atomic.Uint64

// Objects larger than inlineDERMax are never embedded in API responses:
// the UI downloads them from /api/der/{sha256} when stored, or from their source URL.
const inlineDERMax = 256 << 10

type derJSON struct {
	B64  string `json:"der_b64,omitempty"`
	URL  string `json:"der_url,omitempty"`
	Size int    `json:"der_size"`
}

func (h *handler) derRef(der []byte) derJSON {
	if len(der) <= inlineDERMax {
		return derJSON{B64: base64.StdEncoding.EncodeToString(der), Size: len(der)}
	}
	ref := derJSON{Size: len(der)}
	if sha := store.SHA256Hex(der); h.store.HasDER(sha) {
		ref.URL = "/api/der/" + sha
	}
	return ref
}

type handler struct {
	ctx            *pki.Context
	store          *store.Store
	client         *http.Client // guarded: SSRF-checked, used for AIA/CRL/OCSP/etc on the open internet
	internalClient *http.Client // unguarded: only for trusted in-cluster endpoints (e.g. certget on docker network)
	isAdmin        bool
	certgetURL     string
	siteCache      *respCache[siteResponse]
	analysisCache  *respCache[analyzeResponse]
}

type certJSON struct {
	Subject            string     `json:"subject"`
	Issuer             string     `json:"issuer"`
	Serial             string     `json:"serial"`
	SKI                string     `json:"ski,omitempty"`
	AKI                string     `json:"aki,omitempty"`
	NotBefore          string     `json:"not_before"`
	NotAfter           string     `json:"not_after"`
	IsCA               bool       `json:"is_ca"`
	IsSelfSigned       bool       `json:"is_self_signed"`
	IsCrossSigned      bool       `json:"is_cross_signed"`
	Trusted            bool       `json:"trusted"`
	KeyAlgorithm       string     `json:"key_algorithm,omitempty"`
	SignatureAlgorithm string     `json:"signature_algorithm,omitempty"`
	KeyBits            int        `json:"key_bits,omitempty"`
	KeyCurve           string     `json:"key_curve,omitempty"`
	KeyUsage           []string   `json:"key_usage,omitempty"`
	EKUs               []string   `json:"ekus,omitempty"`
	SANs               []string   `json:"sans,omitempty"`
	PathLen            int        `json:"path_len"`
	AIAURLs            []string   `json:"aia_urls,omitempty"`
	OCSPURLs           []string   `json:"ocsp_urls,omitempty"`
	CDPURLs            []string   `json:"cdp_urls,omitempty"`
	Revocation         *revJSON   `json:"revocation,omitempty"`
	IssuedCRLs         []crlJSON  `json:"issued_crls,omitempty"`
	IssuedOCSPs        []ocspJSON `json:"issued_ocsps,omitempty"`
	ThumbprintSHA1     string     `json:"thumbprint_sha1"`
	ThumbprintSHA256   string     `json:"thumbprint_sha256"`
	derJSON
	Source string `json:"source,omitempty"`
}

type ocspJSON struct {
	URL         string `json:"url"`
	Status      string `json:"status"`
	Verified    bool   `json:"verified"`
	ThisUpdate  string `json:"this_update,omitempty"`
	NextUpdate  string `json:"next_update,omitempty"`
	ProducedAt  string `json:"produced_at,omitempty"`
	CertSubject string `json:"cert_subject"`
	CertSerial  string `json:"cert_serial"`
	Source      string `json:"source,omitempty"`
	derJSON
}

type crlJSON struct {
	URLs            []string `json:"urls"`
	Issuer          string   `json:"issuer,omitempty"`
	AKI             string   `json:"aki,omitempty"`
	ThisUpdate      string   `json:"this_update,omitempty"`
	NextUpdate      string   `json:"next_update,omitempty"`
	RevokedCount    int      `json:"revoked_count"`
	CertRevoked     bool     `json:"cert_revoked"`
	Source          string   `json:"source,omitempty"`
	SignatureStatus string   `json:"signature_status,omitempty"` // "verified" | "bad" | "unchecked"
	SignatureMsg    string   `json:"signature_msg,omitempty"`
	HasIDP          bool     `json:"has_idp,omitempty"`
	derJSON
	Errors []string `json:"errors,omitempty"`
}

type revJSON struct {
	Status string `json:"status"`
	Via    string `json:"via"`
}

type verifyJSON struct {
	Status           string `json:"status"`
	Message          string `json:"message,omitempty"`
	Trusted          bool   `json:"trusted"`
	TrustVia         string `json:"trust_via,omitempty"`
	RevocationStatus string `json:"revocation_status"` // "checked" | "incomplete" | "na"
	RevocationMsg    string `json:"revocation_msg,omitempty"`
}

type analyzeResponse struct {
	Chain    []certJSON `json:"chain"`
	Verify   verifyJSON `json:"verify"`
	Warnings []string   `json:"warnings,omitempty"`
	IsAdmin  bool       `json:"is_admin"`
}

type reqLog struct {
	id uint64
}

func (r reqLog) f(format string, args ...any) {
	log.Printf("[r%04d] %s", r.id, fmt.Sprintf(format, args...))
}

func decodeKeyUsage(ku uint32) []string {
	if ku == 0xFFFFFFFF {
		return nil
	}
	type kuBit struct {
		mask uint32
		name string
	}
	bits := []kuBit{
		{0x0080, "Digital Signature"},
		{0x0040, "Non Repudiation"},
		{0x0020, "Key Encipherment"},
		{0x0010, "Data Encipherment"},
		{0x0008, "Key Agreement"},
		{0x0004, "Certificate Sign"},
		{0x0002, "CRL Sign"},
		{0x0001, "Encipher Only"},
		{0x8000, "Decipher Only"},
	}
	var result []string
	for _, b := range bits {
		if ku&b.mask != 0 {
			result = append(result, b.name)
		}
	}
	return result
}

func (h *handler) certToJSON(c *pki.CertInfo, source string) certJSON {
	s1 := sha1.Sum(c.DER)
	s256 := sha256.Sum256(c.DER)
	// Cross-signed: subject == issuer at byte level, but not actually self-signed.
	// This means another CA with the same name (typically same identity, different
	// key) signed this cert — common during CA key rotation.
	isCross := !c.IsSelfSigned &&
		len(c.SubjectNameDER) > 0 &&
		bytes.Equal(c.SubjectNameDER, c.IssuerNameDER)
	return certJSON{
		Subject:            c.Subject,
		Issuer:             c.Issuer,
		Serial:             c.Serial,
		SKI:                c.SKI,
		AKI:                c.AKI,
		NotBefore:          c.NotBefore.Format(time.RFC3339),
		NotAfter:           c.NotAfter.Format(time.RFC3339),
		IsCA:               c.IsCA,
		IsSelfSigned:       c.IsSelfSigned,
		IsCrossSigned:      isCross,
		KeyAlgorithm:       c.KeyAlgorithm,
		SignatureAlgorithm: certSignatureAlgorithm(c.DER),
		KeyBits:            c.KeyBits,
		KeyCurve:           c.KeyCurve,
		KeyUsage:           decodeKeyUsage(c.KeyUsage),
		EKUs:               c.EKUs,
		SANs:               c.SANs,
		PathLen:            c.PathLen,
		AIAURLs:            c.AIAURLs,
		OCSPURLs:           c.OCSPURLs,
		CDPURLs:            c.CDPURLs,
		ThumbprintSHA1:     strings.ToUpper(hex.EncodeToString(s1[:])),
		ThumbprintSHA256:   strings.ToUpper(hex.EncodeToString(s256[:])),
		derJSON:            h.derRef(c.DER),
		Source:             source,
	}
}

func certSignatureAlgorithm(der []byte) string {
	var cert struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &cert)
	if err != nil || len(rest) != 0 || len(cert.SignatureAlgorithm.Algorithm) == 0 {
		if len(der) > 0 {
			parseErr := err
			if parseErr == nil && len(rest) != 0 {
				parseErr = fmt.Errorf("trailing DER data: %d bytes", len(rest))
			}
			if parseErr == nil {
				parseErr = errors.New("empty signature algorithm OID")
			}
			log.Printf("cert signature algorithm parse failed: %v", parseErr)
		}
		return ""
	}
	return cert.SignatureAlgorithm.Algorithm.String()
}

func logCert(rl reqLog, prefix string, c *pki.CertInfo) {
	flags := ""
	if c.IsCA {
		flags += " CA"
	}
	if c.IsSelfSigned {
		flags += " SELF-SIGNED"
	}
	rl.f("%s subject=%q issuer=%q serial=%s%s", prefix, c.Subject, c.Issuer, c.Serial, flags)
	if c.SKI != "" || c.AKI != "" {
		rl.f("%s ski=%s aki=%s", prefix, nvl(c.SKI, "-"), nvl(c.AKI, "-"))
	}
	if len(c.AIAURLs) > 0 {
		rl.f("%s aia=%s", prefix, strings.Join(c.AIAURLs, " "))
	}
	if len(c.CDPURLs) > 0 {
		rl.f("%s cdp=%s", prefix, strings.Join(c.CDPURLs, " "))
	}
}

func nvl(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func (h *handler) analyze(w http.ResponseWriter, r *http.Request) {
	releaseIO, err := acquireBigIO(r.Context(), r.ContentLength)
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	defer releaseIO()
	data, err := readLimited(r.Body, r.ContentLength, maxCRLSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	if len(data) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	h.respondAnalysis(w, r, data, releaseIO)
}

// respondAnalysis calls done once the input is no longer needed, before the
// response is written.
func (h *handler) respondAnalysis(w http.ResponseWriter, r *http.Request, data []byte, done func()) {
	resp, _, err := h.analysisCache.get(r.Context(), store.SHA256Hex(data), func() (*analyzeResponse, error) {
		return h.doAnalyze(r.Context(), data)
	})
	done()
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *handler) doAnalyze(ctx context.Context, data []byte) (*analyzeResponse, error) {
	rl := reqLog{id: reqCounter.Add(1)}
	ctx, release, err := guardAnalysis(ctx, rl)
	if err != nil {
		return nil, err
	}
	defer release()
	return h.analyzeData(ctx, rl, data)
}

// analyzeData runs one analysis within a context from guardAnalysis.
func (h *handler) analyzeData(ctx context.Context, rl reqLog, data []byte) (*analyzeResponse, error) {
	start := time.Now()
	resp := &analyzeResponse{}

	rl.f("analyze: %d bytes", len(data))

	// Try CRL first — if it parses, treat as CRL upload
	if crl, closeCRL, err := h.openCRL(ctx, data); err == nil {
		defer closeCRL()
		rl.f("detected as CRL: issuer=%q", crl.Info.Issuer)
		return h.doAnalyzeCRL(rl, start, data, crl), nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	leaf, err := h.ctx.ParseCertInfo(data)
	if err != nil {
		rl.f("PARSE FAILED: %v", err)
		resp.Verify = verifyJSON{Status: "error", Message: "Failed to parse: " + err.Error()}
		return resp, nil
	}

	logCert(rl, "leaf:", leaf)
	if len(leaf.DER) > limits.CertSize {
		resp.Verify = verifyJSON{Status: "error", Message: fmt.Sprintf("Certificate too large: %d bytes, limit %d", len(leaf.DER), limits.CertSize)}
		return resp, nil
	}

	// Save all parsed certs — needed for shareable links via thumbprint
	if err := h.store.SaveCert(
		leaf.Subject, leaf.Issuer, leaf.Serial,
		leaf.SKI, leaf.AKI, leaf.SubjectNameDER,
		leaf.DER, leaf.IsCA, leaf.IsSelfSigned, "",
	); err != nil {
		rl.f("store.SaveCert(leaf): %v", err)
	}

	type chainEntry struct {
		info   *pki.CertInfo
		source string
	}

	chain := []chainEntry{{info: leaf, source: "upload"}}
	var aiaBag []bagCert
	seen := map[string]bool{store.SHA256Hex(leaf.DER): true}

	current := leaf
	for !current.IsSelfSigned && len(chain) < maxChainDepth {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		depth := len(chain)
		rl.f("chain[%d]: resolving issuer of %q", depth, current.Subject)

		info, source := h.resolveIssuer(ctx, rl, current, resp, &aiaBag)
		if info == nil {
			rl.f("chain[%d]: ISSUER NOT FOUND", depth)
			break
		}
		if seen[store.SHA256Hex(info.DER)] {
			rl.f("chain[%d]: LOOP detected serial=%s", depth, info.Serial)
			resp.Warnings = append(resp.Warnings, "Loop detected at: "+info.Subject)
			break
		}
		seen[store.SHA256Hex(info.DER)] = true
		chain = append(chain, chainEntry{info: info, source: source})
		logCert(rl, fmt.Sprintf("chain[%d]:", depth), info)
		current = info
	}
	if len(chain) >= maxChainDepth {
		rl.f("chain: DEPTH LIMIT reached (%d)", maxChainDepth)
		resp.Warnings = append(resp.Warnings, "Chain depth limit reached")
	}

	rl.f("chain: %d certs total", len(chain))
	for _, entry := range chain {
		c := entry.info
		if len(c.AIAURLs) > maxAIAURLs || len(c.CDPURLs) > maxCDPURLs || len(c.OCSPURLs) > maxOCSPURLs {
			resp.Warnings = append(resp.Warnings, fmt.Sprintf(
				"Only the first %d AIA, %d CDP and %d OCSP http(s) URLs are used for: %s",
				maxAIAURLs, maxCDPURLs, maxOCSPURLs, c.Subject))
		}
	}

	type revResult struct {
		status  string
		revoked bool
		via     string // "CRL" | "OCSP"
	}
	certRevocations := make([]revResult, len(chain))
	issuerCRLs := make(map[int][]crlJSON)
	issuerOCSPs := make(map[int][]ocspJSON)
	type pendingCRL struct {
		info   *pki.CRLInfo
		url    string
		der    []byte
		issuer *pki.CertInfo
	}
	var verifiedCRLs []pendingCRL

	for i, entry := range chain {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Self-signed root revocation is not meaningful in PKI:
		// if root is compromised, you can't trust its own CRL anyway.
		if entry.info.IsSelfSigned {
			continue
		}
		// Skip if no revocation source at all
		if len(entry.info.CDPURLs) == 0 && len(entry.info.OCSPURLs) == 0 {
			continue
		}

		issuerIdx := -1
		for j := i + 1; j < len(chain); j++ {
			if chain[j].info.IsCA {
				issuerIdx = j
				break
			}
		}

		crlIndex := map[string]int{}
		crlChecked := false

		// Find issuer cert for this CRL: match CRL's IssuerNameDER (and AKI if present)
		// against chain entries. Falls back to chain[issuerIdx] if name match fails.
		findCRLIssuer := func(crlInfo *pki.CRLInfo) *pki.CertInfo {
			if len(crlInfo.IssuerNameDER) > 0 {
				for j := range chain {
					c := chain[j].info
					if !bytes.Equal(c.SubjectNameDER, crlInfo.IssuerNameDER) {
						continue
					}
					if crlInfo.AKI != "" && c.SKI != "" && crlInfo.AKI != c.SKI {
						continue
					}
					return c
				}
			}
			if issuerIdx >= 0 {
				return chain[issuerIdx].info
			}
			return nil
		}

		processCRL := func(crl *pki.CRL, crlDER []byte, source string, url string) {
			crlInfo := crl.Info
			sigStatus, sigMsg := "unchecked", ""
			var sigWarn string

			crlIssuer := findCRLIssuer(crlInfo)
			if crlIssuer == nil {
				sigMsg = "issuer CA not in chain — signature not verified"
				sigWarn = fmt.Sprintf("CRL %q: %s", crlInfo.Issuer, sigMsg)
			} else if err := crl.Verify(h.ctx, crlIssuer.DER); err != nil {
				if errors.Is(err, pki.ErrCRLBadSignature) {
					sigStatus = "bad"
					sigMsg = "signature does not match issuer public key"
				} else {
					sigMsg = err.Error()
				}
				sigWarn = fmt.Sprintf("CRL %q: %s", crlInfo.Issuer, sigMsg)
			} else {
				sigStatus = "verified"
			}

			now := time.Now().UTC()
			freshOK := true
			if !crlInfo.ThisUpdate.IsZero() && now.Before(crlInfo.ThisUpdate) {
				freshOK = false
				sigWarn = fmt.Sprintf("CRL %q: thisUpdate %s is in the future",
					crlInfo.Issuer, crlInfo.ThisUpdate.Format(time.RFC3339))
			} else if !crlInfo.NextUpdate.IsZero() && now.After(crlInfo.NextUpdate) {
				freshOK = false
				sigWarn = fmt.Sprintf("CRL %q: expired at %s",
					crlInfo.Issuer, crlInfo.NextUpdate.Format(time.RFC3339))
			}

			if sigWarn != "" {
				resp.Warnings = append(resp.Warnings, sigWarn)
			}
			if crlInfo.HasIDP {
				resp.Warnings = append(resp.Warnings,
					fmt.Sprintf("CRL %q has issuingDistributionPoint — scope not analyzed, revocation decision may be incomplete",
						crlInfo.Issuer))
			}

			// Only trust the revocation decision if signature verified AND CRL is fresh.
			// Otherwise we still record the CRL (for UI display) but do not count it.
			authoritative := sigStatus == "verified" && freshOK

			var revoked bool
			if authoritative {
				var err error
				revoked, err = crl.IsRevoked(h.ctx, entry.info.DER)
				if err != nil {
					rl.f("crl[%d]: revocation check error: %v", i, err)
					authoritative = false
				}
			}

			if authoritative && !crlChecked {
				status := "not_revoked"
				if revoked {
					status = "revoked"
				}
				certRevocations[i] = revResult{status: status, revoked: revoked, via: "CRL"}
				crlChecked = true
			}

			// Fetched CRLs are persisted once their issuer is known to chain to a trusted anchor.
			if authoritative && source == "fetched" {
				verifiedCRLs = append(verifiedCRLs, pendingCRL{crlInfo, url, crlDER, crlIssuer})
			}

			thisFmt := crlInfo.ThisUpdate.Format(time.RFC3339)
			nextFmt := crlInfo.NextUpdate.Format(time.RFC3339)

			rl.f("crl[%d]: %s url=%s issuer=%q next=%s sig=%s authoritative=%v revoked=%v",
				i, source, url, crlInfo.Issuer,
				crlInfo.NextUpdate.Format("2006-01-02"), sigStatus, authoritative, revoked)

			target := issuerIdx
			if target < 0 {
				target = i
			}

			key := fmt.Sprintf("%d|%s|%s", target, crlInfo.Issuer, nextFmt)
			if idx, ok := crlIndex[key]; ok {
				if url != "" {
					issuerCRLs[target][idx].URLs = append(issuerCRLs[target][idx].URLs, url)
				}
			} else {
				crlIndex[key] = len(issuerCRLs[target])
				urls := []string{}
				if url != "" {
					urls = []string{url}
				}
				issuerCRLs[target] = append(issuerCRLs[target], crlJSON{
					URLs: urls, Issuer: crlInfo.Issuer, AKI: crlInfo.AKI,
					ThisUpdate: thisFmt, NextUpdate: nextFmt,
					RevokedCount: crlInfo.RevokedCount,
					CertRevoked:  revoked, Source: source,
					SignatureStatus: sigStatus, SignatureMsg: sigMsg,
					HasIDP:  crlInfo.HasIDP,
					derJSON: h.derRef(crlDER),
				})
			}
		}

		// CDP URLs are mirrors: the first authoritative CRL decides, cached copies first.
		var fetchErrors []string
		cdpURLs := usableURLs(entry.info.CDPURLs, maxCDPURLs)
		for _, url := range cdpURLs {
			if crlChecked || ctx.Err() != nil {
				break
			}
			if crl, der, closeCRL := h.cachedCRL(ctx, rl, url); crl != nil {
				processCRL(crl, der, "cache", url)
				closeCRL()
			}
		}
		for _, url := range cdpURLs {
			if crlChecked || ctx.Err() != nil {
				break
			}
			crl, der, closeCRL, err := h.fetchCRL(ctx, rl, url)
			if err != nil {
				rl.f("crl[%d]: FAILED url=%s err=%v", i, url, err)
				fetchErrors = append(fetchErrors, fmt.Sprintf("%s: %v", url, err))
				continue
			}
			processCRL(crl, der, "fetched", url)
			closeCRL()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Fallback: if no CRL found via CDPs, try store lookup by issuer
		if !crlChecked {
			rl.f("crl[%d]: no CDP-fetched CRL, trying store lookup by issuer=%q",
				i, entry.info.Issuer)
			der, err := h.store.FindFreshCRLByIssuer(entry.info.Issuer)
			if err == nil && der != nil {
				crl, closeCRL, err := h.openCRL(ctx, der)
				if err == nil {
					rl.f("crl[%d]: found CRL in store by issuer", i)
					processCRL(crl, der, "store", "")
					closeCRL()
					fetchErrors = nil
				}
			}
		}

		// OCSP fallback: if CRL didn't determine status and cert has OCSP URL
		if !crlChecked && len(entry.info.OCSPURLs) > 0 && issuerIdx >= 0 {
			ocspRes, source, url := h.resolveOCSP(ctx, rl, i, entry.info, chain[issuerIdx].info)
			if ocspRes != nil {
				ocspStatus := "not_revoked"
				ocspRevoked := false
				if ocspRes.Status == "revoked" {
					ocspStatus = "revoked"
					ocspRevoked = true
				}

				// OCSP response is authoritative only if signature verified against
				// issuer (or a delegated OCSP signer chained to issuer).
				// Unverified responses are still displayed in UI but do not count.
				if ocspRes.Verified {
					certRevocations[i] = revResult{status: ocspStatus, revoked: ocspRevoked, via: "OCSP"}
					crlChecked = true
					fetchErrors = nil
				} else {
					rl.f("ocsp[%d]: signature NOT verified — response ignored as authoritative", i)
					resp.Warnings = append(resp.Warnings,
						"OCSP response for "+entry.info.Subject+" failed signature verification — not trusted")
				}

				oj := ocspJSON{
					URL:         url,
					Status:      ocspRes.Status,
					Verified:    ocspRes.Verified,
					CertSubject: entry.info.Subject,
					CertSerial:  entry.info.Serial,
					Source:      source,
					derJSON:     h.derRef(ocspRes.DER),
				}
				if !ocspRes.ThisUpdate.IsZero() {
					oj.ThisUpdate = ocspRes.ThisUpdate.Format(time.RFC3339)
				}
				if !ocspRes.NextUpdate.IsZero() {
					oj.NextUpdate = ocspRes.NextUpdate.Format(time.RFC3339)
				}
				if !ocspRes.ProducedAt.IsZero() {
					oj.ProducedAt = ocspRes.ProducedAt.Format(time.RFC3339)
				}
				issuerOCSPs[issuerIdx] = append(issuerOCSPs[issuerIdx], oj)
			}
		}

		if !crlChecked && len(fetchErrors) > 0 && issuerIdx >= 0 {
			issuerCRLs[issuerIdx] = append(issuerCRLs[issuerIdx],
				crlJSON{URLs: entry.info.CDPURLs, Errors: fetchErrors})
		}
	}

	var roots, intermediates [][]byte
	seenDER := map[string]bool{}
	addCert := func(target *[][]byte, der []byte) {
		key := string(der)
		if seenDER[key] {
			return
		}
		seenDER[key] = true
		*target = append(*target, der)
	}

	// If leaf itself is a self-signed root, treat it as trust anchor
	if leaf.IsSelfSigned {
		addCert(&roots, leaf.DER)
	}

	for _, entry := range chain[1:] {
		if entry.info.IsSelfSigned {
			addCert(&roots, entry.info.DER)
		} else {
			addCert(&intermediates, entry.info.DER)
		}
	}

	// Add ALL alternate cert candidates from store with same subject as any chain entry's issuer.
	// Same CA can have multiple certs (cross-signed, re-issued with same key) — let OpenSSL pick.
	for _, entry := range chain {
		if len(entry.info.IssuerNameDER) == 0 {
			continue
		}
		ders, _ := h.store.FindAllCertsByNameDER(entry.info.IssuerNameDER, maxAltCandidates)
		for _, der := range ders {
			info, err := h.ctx.ParseCertInfo(der)
			if err != nil {
				continue
			}
			if info.IsSelfSigned {
				addCert(&roots, der)
			} else {
				addCert(&intermediates, der)
			}
		}
	}

	rl.f("verify candidates: %d roots, %d intermediates", len(roots), len(intermediates))

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	vr, err := h.ctx.Verify(leaf.DER, roots, intermediates)
	if err != nil {
		rl.f("verify: ERROR %v", err)
		resp.Verify = verifyJSON{Status: "error", Message: err.Error()}
	} else {
		chainMsg := vr.ChainMessage
		if vr.ChainErrMsg != "" {
			chainMsg = fmt.Sprintf("%s (X509: %s at depth %d)", vr.ChainMessage, vr.ChainErrMsg, vr.ChainErrAt)
		}
		resp.Verify = verifyJSON{Status: vr.ChainStatus, Message: chainMsg}

		if vr.ChainStatus == "ok" {
			rl.f("verify chain: ok")
		} else {
			rl.f("verify chain: %s — %s [X509_V_ERR=%d at depth %d: %s]",
				vr.ChainStatus, vr.ChainMessage, vr.ChainErrCode, vr.ChainErrAt, vr.ChainErrMsg)
		}

		// Revocation status — CRL has priority, OCSP fallback.
		// Self-signed root excluded.
		anyMethod := false
		anyRevoked := false
		var notChecked []string
		for i, entry := range chain {
			if entry.info.IsSelfSigned {
				continue
			}
			if len(entry.info.CDPURLs) == 0 && len(entry.info.OCSPURLs) == 0 {
				continue
			}
			anyMethod = true
			if certRevocations[i].revoked {
				anyRevoked = true
			}
			if certRevocations[i].status == "" {
				notChecked = append(notChecked, entry.info.Subject)
			}
		}
		switch {
		case anyRevoked:
			resp.Verify.RevocationStatus = "revoked"
			if resp.Verify.Status == "ok" {
				resp.Verify.Status = "error"
				resp.Verify.Message = "Certificate is revoked"
			}
		case !anyMethod:
			resp.Verify.RevocationStatus = "na"
			resp.Verify.RevocationMsg = "No CDP or OCSP declared in any non-root certificate"
		case len(notChecked) == 0:
			resp.Verify.RevocationStatus = "checked"
		default:
			resp.Verify.RevocationStatus = "incomplete"
			resp.Verify.RevocationMsg = "Revocation not determined for: " + strings.Join(notChecked, "; ")
			if resp.Verify.Status == "ok" {
				resp.Verify.Status = "warn"
				resp.Verify.Message = "Chain valid but revocation status incomplete"
			}
		}
		rl.f("verify revocation: status=%s msg=%s",
			resp.Verify.RevocationStatus, resp.Verify.RevocationMsg)

		if vr.ChainStatus == "ok" {
			if via, ok := h.trustedPath(leaf.DER, roots, intermediates); ok {
				resp.Verify.Trusted = true
				resp.Verify.TrustVia = via
				rl.f("verify: trusted via %q", via)
			} else {
				rl.f("verify: chain ok but no trusted anchor found")
			}
		}
	}

	for _, c := range verifiedCRLs {
		if !h.chainsToTrust(c.issuer) {
			rl.f("crl: not saved, issuer has no trusted anchor: %s", c.url)
			continue
		}
		if err := h.store.SaveCRL(c.info.Issuer, c.url, c.der, c.info.ThisUpdate, c.info.NextUpdate); err != nil {
			rl.f("crl: store.SaveCRL: %v", err)
		} else {
			rl.f("crl: saved to store: %s", c.url)
		}
	}

	for i, entry := range chain {
		cj := h.certToJSON(entry.info, entry.source)
		if certRevocations[i].status != "" {
			cj.Revocation = &revJSON{
				Status: certRevocations[i].status,
				Via:    certRevocations[i].via,
			}
		}
		cj.IssuedCRLs = issuerCRLs[i]
		cj.IssuedOCSPs = issuerOCSPs[i]
		cj.Trusted = h.trusted(entry.info)
		resp.Chain = append(resp.Chain, cj)
	}

	resp.IsAdmin = h.isAdmin

	rl.f("done in %dms", time.Since(start).Milliseconds())
	return resp, nil
}

func (h *handler) doAnalyzeCRL(rl reqLog, start time.Time, data []byte, crl *pki.CRL) *analyzeResponse {
	resp := &analyzeResponse{IsAdmin: h.isAdmin}
	crlInfo := crl.Info

	thisFmt := crlInfo.ThisUpdate.Format(time.RFC3339)
	nextFmt := crlInfo.NextUpdate.Format(time.RFC3339)

	crlJ := crlJSON{
		URLs:         []string{},
		Issuer:       crlInfo.Issuer,
		AKI:          crlInfo.AKI,
		ThisUpdate:   thisFmt,
		NextUpdate:   nextFmt,
		RevokedCount: crlInfo.RevokedCount,
		HasIDP:       crlInfo.HasIDP,
		Source:       "upload",
		derJSON:      h.derRef(data),
	}

	// Freshness check
	now := time.Now().UTC()
	if !crlInfo.ThisUpdate.IsZero() && now.Before(crlInfo.ThisUpdate) {
		resp.Warnings = append(resp.Warnings,
			"CRL thisUpdate "+thisFmt+" is in the future")
	} else if !crlInfo.NextUpdate.IsZero() && now.After(crlInfo.NextUpdate) {
		resp.Warnings = append(resp.Warnings, "CRL expired at "+nextFmt)
	}
	if crlInfo.HasIDP {
		resp.Warnings = append(resp.Warnings,
			"CRL has issuingDistributionPoint — scope not analyzed")
	}

	// Find the CA cert that issued this CRL and verify signature against it.
	// Only then persist CRL — an unverified CRL must not poison the store.
	var caInfo *pki.CertInfo
	if len(crlInfo.IssuerNameDER) > 0 {
		ders, _ := h.store.FindAllCertsByNameDER(crlInfo.IssuerNameDER, maxAltCandidates)
		for _, der := range ders {
			info, err := h.ctx.ParseCertInfo(der)
			if err != nil {
				continue
			}
			if crlInfo.AKI != "" && info.SKI != "" && crlInfo.AKI != info.SKI {
				continue
			}
			caInfo = info
			break
		}
	}

	if caInfo != nil {
		if err := crl.Verify(h.ctx, caInfo.DER); err != nil {
			if errors.Is(err, pki.ErrCRLBadSignature) {
				crlJ.SignatureStatus = "bad"
				crlJ.SignatureMsg = "signature does not match issuer public key"
				resp.Warnings = append(resp.Warnings,
					"CRL signature verification FAILED against "+caInfo.Subject)
			} else {
				crlJ.SignatureMsg = err.Error()
				resp.Warnings = append(resp.Warnings,
					"CRL signature check error: "+err.Error())
			}
			rl.f("CRL signature check failed: %v", err)

			cj := h.certToJSON(caInfo, "cache")
			cj.Trusted = h.trusted(caInfo)
			cj.IssuedCRLs = []crlJSON{crlJ}
			resp.Chain = append(resp.Chain, cj)
			resp.Verify = verifyJSON{
				Status:  "error",
				Message: "CRL signature invalid — not saved",
			}
			rl.f("done in %dms", time.Since(start).Milliseconds())
			return resp
		}

		crlJ.SignatureStatus = "verified"
		rl.f("CRL signature verified against %s", caInfo.Subject)

		if !h.chainsToTrust(caInfo) {
			rl.f("uploaded CRL not saved: issuer chain has no trusted anchor")
		} else if err := h.store.SaveCRL(crlInfo.Issuer, "", data, crlInfo.ThisUpdate, crlInfo.NextUpdate); err != nil {
			rl.f("store.SaveCRL(uploaded): %v", err)
		} else {
			rl.f("uploaded CRL saved to store: issuer=%q next=%s", crlInfo.Issuer, nextFmt)
		}
		crlJ.derJSON = h.derRef(data)

		cj := h.certToJSON(caInfo, "cache")
		cj.Trusted = h.trusted(caInfo)
		cj.IssuedCRLs = []crlJSON{crlJ}
		resp.Chain = append(resp.Chain, cj)
		resp.Verify = verifyJSON{Status: "ok"}
		rl.f("done in %dms", time.Since(start).Milliseconds())
		return resp
	}

	// CA not found — show CRL standalone with warning; do NOT save (signature unchecked)
	crlJ.SignatureStatus = "unchecked"
	crlJ.SignatureMsg = "issuer CA not in trust store — signature not verified"
	rl.f("CRL issuer not found in store, showing CRL alone (NOT persisted)")
	resp.Warnings = append(resp.Warnings,
		"Issuer CA not in store: "+crlInfo.Issuer+" — signature NOT verified, CRL not saved")

	// Fake "CA" entry to host the CRL block
	resp.Chain = append(resp.Chain, certJSON{
		Subject:    crlInfo.Issuer,
		Issuer:     crlInfo.Issuer,
		Serial:     "(unknown)",
		IsCA:       true,
		Source:     "missing",
		IssuedCRLs: []crlJSON{crlJ},
	})
	resp.Verify = verifyJSON{Status: "warn", Message: "CRL parsed, but issuing CA not found in trust store — signature not verified"}

	rl.f("done in %dms", time.Since(start).Milliseconds())
	return resp
}

// trustedPath verifies der with only the trusted roots among roots as
// anchors, so trust follows the path OpenSSL verified rather than the chain
// certview resolved; it returns the anchor's subject.
func (h *handler) trustedPath(der []byte, roots, intermediates [][]byte) (string, bool) {
	var anchors [][]byte
	for _, r := range roots {
		if t, _ := h.store.IsCertTrusted(store.SHA256Hex(r)); t {
			anchors = append(anchors, r)
		}
	}
	if len(anchors) == 0 {
		return "", false
	}
	vr, err := h.ctx.Verify(der, anchors, intermediates)
	if err != nil || vr.ChainStatus != "ok" || len(vr.Chain) == 0 {
		return "", false
	}
	return vr.Chain[len(vr.Chain)-1].Subject, true
}

// chainsToTrust reports whether cert verifies, through stored certificates,
// to a trusted root.
func (h *handler) chainsToTrust(cert *pki.CertInfo) bool {
	if h.trusted(cert) {
		return true
	}
	var roots, intermediates [][]byte
	names := [][]byte{cert.IssuerNameDER}
	seen := map[string]bool{}
	for depth := 0; depth < maxChainDepth && len(names) > 0; depth++ {
		name := names[0]
		names = names[1:]
		if seen[string(name)] {
			continue
		}
		seen[string(name)] = true
		ders, _ := h.store.FindAllCertsByNameDER(name, maxAltCandidates)
		for _, der := range ders {
			info, err := h.ctx.ParseCertInfo(der)
			if err != nil {
				continue
			}
			if info.IsSelfSigned {
				roots = append(roots, der)
			} else {
				intermediates = append(intermediates, der)
				names = append(names, info.IssuerNameDER)
			}
		}
	}
	_, ok := h.trustedPath(cert.DER, roots, intermediates)
	return ok
}

func (h *handler) trusted(c *pki.CertInfo) bool {
	t, _ := h.store.IsCertTrusted(store.SHA256Hex(c.DER))
	return t
}

// bagCert is a certificate from an AIA response, a candidate issuer for the
// rest of the analysis; only certificates chosen as issuers are stored.
type bagCert struct {
	info *pki.CertInfo
	url  string
}

func (h *handler) saveIssuer(rl reqLog, c bagCert) {
	i := c.info
	if err := h.store.SaveCert(i.Subject, i.Issuer, i.Serial, i.SKI, i.AKI, i.SubjectNameDER,
		i.DER, i.IsCA, i.IsSelfSigned, c.url); err != nil {
		rl.f("  store.SaveCert: %v", err)
	}
}

func (h *handler) resolveIssuer(ctx context.Context, rl reqLog, cert *pki.CertInfo, resp *analyzeResponse, bag *[]bagCert) (*pki.CertInfo, string) {
	// Validate that a candidate issuer actually matches: SKI must equal cert's AKI
	tryCandidate := func(der []byte, hint string) *pki.CertInfo {
		info, err := h.ctx.ParseCertInfo(der)
		if err != nil {
			rl.f("  cache: %s parse failed: %v", hint, err)
			return nil
		}
		if cert.AKI != "" && info.SKI != "" && cert.AKI != info.SKI {
			rl.f("  cache: %s SKI=%s ≠ AKI=%s — wrong cert, skipping",
				hint, info.SKI, cert.AKI)
			return nil
		}
		return info
	}

	// 1. AKI → SKI
	if cert.AKI != "" {
		if der, err := h.store.FindCertBySKI(cert.AKI); err == nil && der != nil {
			rl.f("  cache: SKI=%s → HIT", cert.AKI)
			if info := tryCandidate(der, "SKI"); info != nil {
				return info, "cache"
			}
		} else {
			rl.f("  cache: SKI=%s → miss", cert.AKI)
		}
	}

	// 2. DER name
	if len(cert.IssuerNameDER) > 0 {
		if der, err := h.store.FindCertByNameDER(cert.IssuerNameDER); err == nil && der != nil {
			rl.f("  cache: NameDER → HIT")
			if info := tryCandidate(der, "NameDER"); info != nil {
				return info, "cache"
			}
		} else {
			rl.f("  cache: NameDER → miss")
		}
	}

	// 3. String subject fallback
	if der, err := h.store.FindCertBySubject(cert.Issuer); err == nil && der != nil {
		rl.f("  cache: subject=%q → HIT", cert.Issuer)
		if info := tryCandidate(der, "subject"); info != nil {
			return info, "cache"
		}
	} else {
		rl.f("  cache: subject=%q → miss", cert.Issuer)
	}

	// 4. Certificates from AIA responses earlier in this analysis
	for _, c := range *bag {
		if (cert.AKI != "" && c.info.SKI == cert.AKI) ||
			(cert.AKI == "" && bytes.Equal(c.info.SubjectNameDER, cert.IssuerNameDER)) {
			rl.f("  AIA bag: matched %q", c.info.Subject)
			h.saveIssuer(rl, c)
			return c.info, "fetched"
		}
	}

	// 5. Fetch via AIA
	if len(cert.AIAURLs) == 0 {
		rl.f("  NO AIA URLs")
		resp.Warnings = append(resp.Warnings, "No AIA URL in: "+cert.Subject)
		return nil, ""
	}

	for _, url := range usableURLs(cert.AIAURLs, maxAIAURLs) {
		rl.f("  fetch AIA: %s", url)
		data, contentType, err := h.fetchWithInfo(ctx, fetchAIA, url)
		if err != nil {
			rl.f("  fetch AIA: FAILED %v", err)
			resp.Warnings = append(resp.Warnings, "AIA fetch failed ("+url+"): "+err.Error())
			continue
		}
		rl.f("  fetch AIA: %d bytes, content-type=%s", len(data), contentType)

		ders, err := h.ctx.ParseAllCerts(data)
		if err != nil {
			rl.f("  fetch AIA: PARSE FAILED %v", err)
			resp.Warnings = append(resp.Warnings, "Failed to parse AIA: "+err.Error())
			continue
		}
		rl.f("  fetch AIA: extracted %d cert(s)", len(ders))
		if len(ders) > maxAIACerts {
			resp.Warnings = append(resp.Warnings, fmt.Sprintf("AIA %s: %d certificates, limit %d", url, len(ders), maxAIACerts))
			continue
		}

		// Pick the matching cert for chain continuation; the rest stay in the bag.
		// Prefer self-signed cert when multiple match by SKI (shortest chain).
		var match *pki.CertInfo
		var allParsed []*pki.CertInfo
		for _, der := range ders {
			if len(der) > limits.CertSize {
				continue
			}
			info, err := h.ctx.ParseCertInfo(der)
			if err != nil {
				continue
			}
			allParsed = append(allParsed, info)
			*bag = append(*bag, bagCert{info, url})
		}

		// Selection priority: self-signed SKI match > any SKI match > any cert
		for _, info := range allParsed {
			if cert.AKI != "" && info.SKI == cert.AKI && info.IsSelfSigned {
				match = info
				rl.f("  AIA: matched self-signed by SKI=%s serial=%s", info.SKI, info.Serial)
				break
			}
		}
		if match == nil {
			for _, info := range allParsed {
				if cert.AKI != "" && info.SKI == cert.AKI {
					match = info
					rl.f("  AIA: matched by SKI=%s serial=%s", info.SKI, info.Serial)
					break
				}
			}
		}
		if match == nil && len(allParsed) > 0 {
			match = allParsed[0]
		}

		if match != nil {
			if cert.AKI != "" && match.SKI != "" && cert.AKI != match.SKI {
				rl.f("  AIA: WARNING — no SKI match, using first cert (AKI=%s, got SKI=%s)",
					cert.AKI, match.SKI)
			}
			h.saveIssuer(rl, bagCert{match, url})
			return match, "fetched"
		}
	}

	resp.Warnings = append(resp.Warnings, "Could not fetch issuer for: "+cert.Subject)
	return nil, ""
}

// openCRL parses under the CRL memory gate; close releases both.
func (h *handler) openCRL(ctx context.Context, der []byte) (*pki.CRL, func(), error) {
	release, err := acquireCRLMemory(ctx, len(der))
	if err != nil {
		return nil, nil, err
	}
	crl, err := h.ctx.ParseCRL(der)
	if err != nil {
		release()
		return nil, nil, err
	}
	return crl, func() { crl.Close(); release() }, nil
}

func (h *handler) cachedCRL(ctx context.Context, rl reqLog, url string) (*pki.CRL, []byte, func()) {
	size, err := h.store.FreshCRLSize(url)
	if err != nil || size == 0 {
		rl.f("  crl cache: %s → miss", url)
		return nil, nil, nil
	}
	release, err := acquireCRLMemory(ctx, size)
	if err != nil {
		return nil, nil, nil
	}
	der, err := h.store.FindFreshCRL(url)
	if err != nil || der == nil {
		release()
		rl.f("  crl cache: %s → miss", url)
		return nil, nil, nil
	}
	rl.f("  crl cache: %s → HIT", url)
	crl, err := h.ctx.ParseCRL(der)
	if err != nil {
		release()
		rl.f("  crl cache: hit but parse failed: %v", err)
		return nil, nil, nil
	}
	return crl, der, func() { crl.Close(); release() }
}

// fetchCRL does not persist: processCRL saves only after signature verification.
func (h *handler) fetchCRL(ctx context.Context, rl reqLog, url string) (*pki.CRL, []byte, func(), error) {
	rl.f("  crl fetch: %s", url)
	der, contentType, err := h.fetchWithInfo(ctx, fetchCRL, url)
	if err != nil {
		return nil, nil, nil, err
	}
	rl.f("  crl fetch: %d bytes, content-type=%s", len(der), contentType)

	crl, closeCRL, err := h.openCRL(ctx, der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CRL: %w", err)
	}
	return crl, der, closeCRL, nil
}

func (h *handler) derBySHA256(w http.ResponseWriter, r *http.Request) {
	size, err := h.store.DERSize(r.PathValue("sha256"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	release, err := acquireBigIO(r.Context(), int64(size))
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	defer release()
	der, err := h.store.FindDERBySHA256(r.PathValue("sha256"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if der == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(derWriteTime))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(der)
}

func (h *handler) analyzeByThumbprint(w http.ResponseWriter, r *http.Request) {
	tp := r.PathValue("thumbprint")
	if tp == "" {
		http.Error(w, "missing thumbprint", http.StatusBadRequest)
		return
	}
	der, err := h.store.FindCertByThumbprint(tp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if der == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h.respondAnalysis(w, r, der, func() {})
}

func (h *handler) trust(w http.ResponseWriter, r *http.Request) {
	h.toggleTrust(w, r, true)
}

func (h *handler) untrust(w http.ResponseWriter, r *http.Request) {
	h.toggleTrust(w, r, false)
}

func (h *handler) toggleTrust(w http.ResponseWriter, r *http.Request, trusted bool) {
	var req struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SHA256 == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.store.SetTrusted(req.SHA256, trusted); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	log.Printf("[admin] cert sha256=%s → trusted=%v", req.SHA256, trusted)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true, "trusted": trusted})
}

func (h *handler) resolveOCSP(ctx context.Context, rl reqLog, i int, cert *pki.CertInfo, issuer *pki.CertInfo) (*pki.OCSPResult, string, string) {
	s1 := sha1.Sum(cert.DER)
	thumb := strings.ToUpper(hex.EncodeToString(s1[:]))

	// 1. Cache lookup
	if der, err := h.store.FindFreshOCSP(thumb); err == nil && der != nil {
		rl.f("  ocsp[%d]: cache HIT for thumbprint=%s", i, thumb[:16])
		res, err := h.ctx.ParseOCSPResponse(cert.DER, issuer.DER, der)
		if err == nil {
			return res, "cache", ""
		}
		rl.f("  ocsp[%d]: cache hit but parse failed: %v", i, err)
	}

	// 2. Build request, POST to responder
	reqBody, err := h.ctx.BuildOCSPRequest(cert.DER, issuer.DER)
	if err != nil {
		rl.f("  ocsp[%d]: build request failed: %v", i, err)
		return nil, "", ""
	}

	for _, url := range usableURLs(cert.OCSPURLs, maxOCSPURLs) {
		rl.f("  ocsp[%d]: POST %s (%d bytes)", i, url, len(reqBody))
		respBody, err := h.postOCSP(ctx, url, reqBody)
		if err != nil {
			rl.f("  ocsp[%d]: %v", i, err)
			continue
		}
		rl.f("  ocsp[%d]: response %d bytes", i, len(respBody))

		res, err := h.ctx.ParseOCSPResponse(cert.DER, issuer.DER, respBody)
		if err != nil {
			rl.f("  ocsp[%d]: parse failed: %v", i, err)
			continue
		}
		rl.f("  ocsp[%d]: status=%s verified=%v this=%s next=%s",
			i, res.Status, res.Verified,
			res.ThisUpdate.Format("2006-01-02"),
			res.NextUpdate.Format("2006-01-02"))

		if res.Verified && !res.NextUpdate.IsZero() {
			if err := h.store.SaveOCSP(thumb, url, res.Status, res.DER,
				res.ThisUpdate, res.NextUpdate, res.ProducedAt); err != nil {
				rl.f("  ocsp[%d]: store save: %v", i, err)
			}
		}
		return res, "fetched", url
	}
	return nil, "", ""
}

func (h *handler) fetchWithInfo(ctx context.Context, kind fetchKind, url string) ([]byte, string, error) {
	return inflight.do(ctx, kind, kind.name+" "+url, urlEndpoint(url), func(fctx context.Context) ([]byte, string, error) {
		req, err := http.NewRequestWithContext(fctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, "", err
		}
		return h.doFetch(req, kind)
	})
}

// urlEndpoint returns scheme://host:port with the scheme's default port.
func urlEndpoint(rawURL string) string {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[scheme]
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

func (h *handler) postOCSP(ctx context.Context, url string, body []byte) ([]byte, error) {
	key := "OCSP " + url + " " + store.SHA256Hex(body)
	data, _, err := inflight.do(ctx, fetchOCSP, key, urlEndpoint(url), func(fctx context.Context) ([]byte, string, error) {
		req, err := http.NewRequestWithContext(fctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		return h.doFetch(req, fetchOCSP)
	})
	return data, err
}

func (h *handler) doFetch(req *http.Request, kind fetchKind) ([]byte, string, error) {
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if resp.StatusCode != http.StatusOK {
		return nil, contentType, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := readLimited(resp.Body, resp.ContentLength, kind.maxBytes)
	return data, contentType, err
}

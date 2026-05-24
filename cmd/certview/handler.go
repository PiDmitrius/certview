package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PiDmitrius/certview/internal/pki"
	"github.com/PiDmitrius/certview/internal/store"
)

var reqCounter atomic.Uint64

type handler struct {
	ctx            *pki.Context
	store          *store.Store
	client         *http.Client // guarded: SSRF-checked, used for AIA/CRL/OCSP/etc on the open internet
	internalClient *http.Client // unguarded: only for trusted in-cluster endpoints (e.g. certget on docker network)
	isAdmin        bool
	certgetURL     string
	siteCache      *siteCache
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
	DER                string     `json:"der_b64,omitempty"`
	Source             string     `json:"source,omitempty"`
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
	DER         string `json:"der_b64,omitempty"`
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
	DER             string   `json:"der_b64,omitempty"`
	Errors          []string `json:"errors,omitempty"`
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

func certToJSON(c *pki.CertInfo, source string) certJSON {
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
		DER:                base64.StdEncoding.EncodeToString(c.DER),
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
	data, err := io.ReadAll(io.LimitReader(r.Body, 100<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(data) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	resp := h.doAnalyze(data)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *handler) doAnalyze(data []byte) *analyzeResponse {
	rl := reqLog{id: reqCounter.Add(1)}
	start := time.Now()
	resp := &analyzeResponse{}

	rl.f("analyze: %d bytes", len(data))

	// Try CRL first — if it parses, treat as CRL upload
	if crlInfo, err := h.ctx.ParseCRLInfo(data); err == nil {
		rl.f("detected as CRL: issuer=%q", crlInfo.Issuer)
		return h.doAnalyzeCRL(rl, start, data, crlInfo)
	}

	leaf, err := h.ctx.ParseCertInfo(data)
	if err != nil {
		rl.f("PARSE FAILED: %v", err)
		resp.Verify = verifyJSON{Status: "error", Message: "Failed to parse: " + err.Error()}
		return resp
	}

	logCert(rl, "leaf:", leaf)

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

	const maxChainDepth = 10

	chain := []chainEntry{{info: leaf, source: "upload"}}
	seen := map[string]bool{leaf.Serial: true}

	current := leaf
	for !current.IsSelfSigned && len(chain) < maxChainDepth {
		depth := len(chain)
		rl.f("chain[%d]: resolving issuer of %q", depth, current.Subject)

		info, source := h.resolveIssuer(rl, current, resp)
		if info == nil {
			rl.f("chain[%d]: ISSUER NOT FOUND", depth)
			break
		}
		if seen[info.Serial] {
			rl.f("chain[%d]: LOOP detected serial=%s", depth, info.Serial)
			resp.Warnings = append(resp.Warnings, "Loop detected at: "+info.Subject)
			break
		}
		seen[info.Serial] = true
		chain = append(chain, chainEntry{info: info, source: source})
		logCert(rl, fmt.Sprintf("chain[%d]:", depth), info)
		current = info
	}
	if len(chain) >= maxChainDepth {
		rl.f("chain: DEPTH LIMIT reached (%d)", maxChainDepth)
		resp.Warnings = append(resp.Warnings, "Chain depth limit reached")
	}

	rl.f("chain: %d certs total", len(chain))

	type revResult struct {
		status  string
		revoked bool
		via     string // "CRL" | "OCSP"
	}
	certRevocations := make([]revResult, len(chain))
	issuerCRLs := make(map[int][]crlJSON)
	issuerOCSPs := make(map[int][]ocspJSON)
	var crlDERs [][]byte

	for i, entry := range chain {
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

		processCRL := func(crlDER []byte, crlInfo *pki.CRLInfo, source string, url string) {
			sigStatus, sigMsg := "unchecked", ""
			var sigWarn string

			crlIssuer := findCRLIssuer(crlInfo)
			if crlIssuer == nil {
				sigMsg = "issuer CA not in chain — signature not verified"
				sigWarn = fmt.Sprintf("CRL %q: %s", crlInfo.Issuer, sigMsg)
			} else if err := h.ctx.VerifyCRL(crlDER, crlIssuer.DER); err != nil {
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
				revoked, err = h.ctx.CheckRevocation(entry.info.DER, crlDER)
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

			// Persist to store only after signature+freshness pass, and only for
			// CRLs we actually fetched fresh (cache hits are already saved).
			if authoritative && source == "fetched" {
				if err := h.store.SaveCRL(crlInfo.Issuer, url, crlDER,
					crlInfo.ThisUpdate, crlInfo.NextUpdate); err != nil {
					rl.f("crl[%d]: store.SaveCRL: %v", i, err)
				} else {
					rl.f("crl[%d]: saved to store (verified)", i)
				}
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
					HasIDP: crlInfo.HasIDP,
					DER:    base64.StdEncoding.EncodeToString(crlDER),
				})
				if authoritative {
					crlDERs = append(crlDERs, crlDER)
				}
			}
		}

		var fetchErrors []string
		for _, url := range entry.info.CDPURLs {
			crlDER, crlInfo, source, err := h.resolveCRL(rl, url)
			if err != nil {
				rl.f("crl[%d]: FAILED url=%s err=%v", i, url, err)
				fetchErrors = append(fetchErrors, fmt.Sprintf("%s: %v", url, err))
				continue
			}
			processCRL(crlDER, crlInfo, source, url)
		}

		// Fallback: if no CRL found via CDPs, try store lookup by issuer
		if !crlChecked {
			rl.f("crl[%d]: no CDP-fetched CRL, trying store lookup by issuer=%q",
				i, entry.info.Issuer)
			der, err := h.store.FindFreshCRLByIssuer(entry.info.Issuer)
			if err == nil && der != nil {
				crlInfo, err := h.ctx.ParseCRLInfo(der)
				if err == nil {
					rl.f("crl[%d]: found CRL in store by issuer", i)
					processCRL(der, crlInfo, "store", "")
					fetchErrors = nil
				}
			}
		}

		// OCSP fallback: if CRL didn't determine status and cert has OCSP URL
		if !crlChecked && len(entry.info.OCSPURLs) > 0 && issuerIdx >= 0 {
			ocspRes, source, url := h.resolveOCSP(rl, i, entry.info, chain[issuerIdx].info)
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
					DER:         base64.StdEncoding.EncodeToString(ocspRes.DER),
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
		ders, _ := h.store.FindAllCertsByNameDER(entry.info.IssuerNameDER)
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

	rl.f("verify: %d roots, %d intermediates, %d crls", len(roots), len(intermediates), len(crlDERs))

	vr, err := h.ctx.Verify(leaf.DER, roots, intermediates, crlDERs)
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
			for i := len(chain) - 1; i >= 0; i-- {
				trusted, _ := h.store.IsCertTrusted(chain[i].info.Serial)
				if trusted {
					resp.Verify.Trusted = true
					resp.Verify.TrustVia = chain[i].info.Subject
					rl.f("verify: trusted via %q", chain[i].info.Subject)
					break
				}
			}
			if !resp.Verify.Trusted {
				rl.f("verify: chain ok but no trusted anchor found")
			}
		}
	}

	for i, entry := range chain {
		cj := certToJSON(entry.info, entry.source)
		if certRevocations[i].status != "" {
			cj.Revocation = &revJSON{
				Status: certRevocations[i].status,
				Via:    certRevocations[i].via,
			}
		}
		cj.IssuedCRLs = issuerCRLs[i]
		cj.IssuedOCSPs = issuerOCSPs[i]
		if t, _ := h.store.IsCertTrusted(entry.info.Serial); t {
			cj.Trusted = true
		}
		resp.Chain = append(resp.Chain, cj)
	}

	resp.IsAdmin = h.isAdmin

	rl.f("done in %dms", time.Since(start).Milliseconds())
	return resp
}

func (h *handler) doAnalyzeCRL(rl reqLog, start time.Time, data []byte, crlInfo *pki.CRLInfo) *analyzeResponse {
	resp := &analyzeResponse{IsAdmin: h.isAdmin}

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
		DER:          base64.StdEncoding.EncodeToString(data),
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
		ders, _ := h.store.FindAllCertsByNameDER(crlInfo.IssuerNameDER)
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
		if err := h.ctx.VerifyCRL(data, caInfo.DER); err != nil {
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

			cj := certToJSON(caInfo, "cache")
			if t, _ := h.store.IsCertTrusted(caInfo.Serial); t {
				cj.Trusted = true
			}
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

		// Signature OK — now safe to persist
		if err := h.store.SaveCRL(crlInfo.Issuer, "", data, crlInfo.ThisUpdate, crlInfo.NextUpdate); err != nil {
			rl.f("store.SaveCRL(uploaded): %v", err)
		} else {
			rl.f("uploaded CRL saved to store: issuer=%q next=%s", crlInfo.Issuer, nextFmt)
		}

		cj := certToJSON(caInfo, "cache")
		if t, _ := h.store.IsCertTrusted(caInfo.Serial); t {
			cj.Trusted = true
		}
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

func (h *handler) resolveIssuer(rl reqLog, cert *pki.CertInfo, resp *analyzeResponse) (*pki.CertInfo, string) {
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

	// 4. Fetch via AIA
	if len(cert.AIAURLs) == 0 {
		rl.f("  NO AIA URLs")
		resp.Warnings = append(resp.Warnings, "No AIA URL in: "+cert.Subject)
		return nil, ""
	}

	for _, url := range cert.AIAURLs {
		rl.f("  fetch AIA: %s", url)
		data, contentType, err := h.fetchWithInfo(url)
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

		// Save all CA certs from bag, then pick the matching one for chain continuation.
		// Prefer self-signed cert when multiple match by SKI (shortest chain).
		var match *pki.CertInfo
		var allParsed []*pki.CertInfo
		for _, der := range ders {
			info, err := h.ctx.ParseCertInfo(der)
			if err != nil {
				continue
			}
			if err := h.store.SaveCert(
				info.Subject, info.Issuer, info.Serial,
				info.SKI, info.AKI, info.SubjectNameDER,
				info.DER, info.IsCA, info.IsSelfSigned, url,
			); err != nil {
				rl.f("  store.SaveCert: %v", err)
			}
			allParsed = append(allParsed, info)
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
			return match, "fetched"
		}
	}

	resp.Warnings = append(resp.Warnings, "Could not fetch issuer for: "+cert.Subject)
	return nil, ""
}

func (h *handler) resolveCRL(rl reqLog, url string) ([]byte, *pki.CRLInfo, string, error) {
	// 1. Check store
	if der, err := h.store.FindFreshCRL(url); err == nil && der != nil {
		rl.f("  crl cache: %s → HIT", url)
		info, err := h.ctx.ParseCRLInfo(der)
		if err == nil {
			return der, info, "cache", nil
		}
		rl.f("  crl cache: hit but parse failed: %v", err)
	} else {
		rl.f("  crl cache: %s → miss", url)
	}

	// 2. Fetch
	rl.f("  crl fetch: %s", url)
	der, contentType, err := h.fetchWithInfo(url)
	if err != nil {
		return nil, nil, "", err
	}
	rl.f("  crl fetch: %d bytes, content-type=%s", len(der), contentType)

	info, err := h.ctx.ParseCRLInfo(der)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse CRL: %w", err)
	}

	// Do NOT persist here — caller (processCRL) decides whether to cache
	// after signature verification against the issuer CA.
	return der, info, "fetched", nil
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
	resp := h.doAnalyze(der)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *handler) trust(w http.ResponseWriter, r *http.Request) {
	h.toggleTrust(w, r, true)
}

func (h *handler) untrust(w http.ResponseWriter, r *http.Request) {
	h.toggleTrust(w, r, false)
}

func (h *handler) toggleTrust(w http.ResponseWriter, r *http.Request, trusted bool) {
	var req struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Serial == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.store.SetTrusted(req.Serial, trusted); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	log.Printf("[admin] cert %s → trusted=%v", req.Serial, trusted)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true, "trusted": trusted})
}

func (h *handler) resolveOCSP(rl reqLog, i int, cert *pki.CertInfo, issuer *pki.CertInfo) (*pki.OCSPResult, string, string) {
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

	for _, url := range cert.OCSPURLs {
		rl.f("  ocsp[%d]: POST %s (%d bytes)", i, url, len(reqBody))
		resp, err := h.client.Post(url, "application/ocsp-request", bytes.NewReader(reqBody))
		if err != nil {
			rl.f("  ocsp[%d]: HTTP error: %v", i, err)
			continue
		}
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 100<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			rl.f("  ocsp[%d]: HTTP %d: %v", i, resp.StatusCode, err)
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

func (h *handler) fetchWithInfo(url string) ([]byte, string, error) {
	resp, err := h.client.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")

	if resp.StatusCode != http.StatusOK {
		return nil, contentType, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 100<<20))
	return data, contentType, err
}

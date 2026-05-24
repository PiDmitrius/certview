package pki

/*
#include <minipki.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"time"
	"unsafe"
)

type Context struct {
	c C.MP_CTX
}

type CertInfo struct {
	Subject      string
	Issuer       string
	Serial       string
	NotBefore    time.Time
	NotAfter     time.Time
	IsCA         bool
	IsSelfSigned bool
	KeyAlgorithm   string
	KeyBits        int
	KeyCurve       string
	KeyUsage       uint32
	EKUs           []string
	SANs           []string
	PathLen        int
	SKI            string
	AKI            string
	SubjectNameDER []byte
	IssuerNameDER  []byte
	AIAURLs        []string
	OCSPURLs       []string
	CDPURLs        []string
	DER            []byte
}

type OCSPResult struct {
	Status       string // "good" | "revoked" | "unknown"
	Verified     bool
	ThisUpdate   time.Time
	NextUpdate   time.Time
	ProducedAt   time.Time
	RevokedAt    time.Time
	RevokeReason int
	DER          []byte
}

func (ctx *Context) BuildOCSPRequest(certDER, issuerDER []byte) ([]byte, error) {
	if len(certDER) == 0 || len(issuerDER) == 0 {
		return nil, errors.New("empty cert or issuer")
	}

	var cert C.MP_CERT
	rc := C.mp_cert_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&certDER[0])), C.size_t(len(certDER)), &cert)
	if rc != C.MP_OK {
		return nil, rcError("mp_cert_parse(cert)", rc)
	}
	defer C.mp_cert_close(cert)

	var issuer C.MP_CERT
	rc = C.mp_cert_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&issuerDER[0])), C.size_t(len(issuerDER)), &issuer)
	if rc != C.MP_OK {
		return nil, rcError("mp_cert_parse(issuer)", rc)
	}
	defer C.mp_cert_close(issuer)

	var req C.MP_OCSP_REQ
	rc = C.mp_ocsp_request_new(ctx.c, cert, issuer, &req)
	if rc != C.MP_OK {
		return nil, rcError("mp_ocsp_request_new", rc)
	}
	defer C.mp_ocsp_request_close(req)

	var der *C.uint8_t
	var derlen C.size_t
	if C.mp_ocsp_request_der(req, &der, &derlen) != C.MP_OK {
		return nil, errors.New("mp_ocsp_request_der failed")
	}
	return C.GoBytes(unsafe.Pointer(der), C.int(derlen)), nil
}

func (ctx *Context) ParseOCSPResponse(certDER, issuerDER, respDER []byte) (*OCSPResult, error) {
	if len(certDER) == 0 || len(issuerDER) == 0 || len(respDER) == 0 {
		return nil, errors.New("empty data")
	}

	var cert C.MP_CERT
	rc := C.mp_cert_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&certDER[0])), C.size_t(len(certDER)), &cert)
	if rc != C.MP_OK {
		return nil, rcError("mp_cert_parse(cert)", rc)
	}
	defer C.mp_cert_close(cert)

	var issuer C.MP_CERT
	rc = C.mp_cert_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&issuerDER[0])), C.size_t(len(issuerDER)), &issuer)
	if rc != C.MP_OK {
		return nil, rcError("mp_cert_parse(issuer)", rc)
	}
	defer C.mp_cert_close(issuer)

	var resp C.MP_OCSP_RESP
	rc = C.mp_ocsp_response_parse(ctx.c, cert, issuer,
		(*C.uint8_t)(unsafe.Pointer(&respDER[0])), C.size_t(len(respDER)), &resp)
	if rc != C.MP_OK {
		return nil, rcError("mp_ocsp_response_parse", rc)
	}
	defer C.mp_ocsp_response_close(resp)

	result := &OCSPResult{}
	var st, ver, reason C.int32_t
	var t C.int64_t

	C.mp_ocsp_status(resp, &st)
	switch st {
	case C.MP_OCSP_GOOD:
		result.Status = "good"
	case C.MP_OCSP_REVOKED:
		result.Status = "revoked"
	default:
		result.Status = "unknown"
	}

	C.mp_ocsp_verified(resp, &ver)
	result.Verified = ver == 1

	if C.mp_ocsp_this_update(resp, &t) == C.MP_OK && t > 0 {
		result.ThisUpdate = time.Unix(int64(t), 0).UTC()
	}
	if C.mp_ocsp_next_update(resp, &t) == C.MP_OK && t > 0 {
		result.NextUpdate = time.Unix(int64(t), 0).UTC()
	}
	if C.mp_ocsp_produced_at(resp, &t) == C.MP_OK && t > 0 {
		result.ProducedAt = time.Unix(int64(t), 0).UTC()
	}
	if C.mp_ocsp_revoked_at(resp, &t) == C.MP_OK && t > 0 {
		result.RevokedAt = time.Unix(int64(t), 0).UTC()
	}
	if C.mp_ocsp_revoke_reason(resp, &reason) == C.MP_OK {
		result.RevokeReason = int(reason)
	}

	var der *C.uint8_t
	var derlen C.size_t
	if C.mp_ocsp_der(resp, &der, &derlen) == C.MP_OK && derlen > 0 {
		result.DER = C.GoBytes(unsafe.Pointer(der), C.int(derlen))
	}

	return result, nil
}

type CRLInfo struct {
	Issuer        string
	IssuerNameDER []byte
	AKI           string
	ThisUpdate    time.Time
	NextUpdate    time.Time
	RevokedCount  int
	HasIDP        bool
	DER           []byte
}

// ErrCRLBadSignature is returned by VerifyCRL when CRL signature does not
// validate against the provided issuer's public key.
var ErrCRLBadSignature = errors.New("CRL signature verification failed")

type VerifyResult struct {
	// Chain validity (signatures, dates, structure)
	ChainStatus  string // "ok" | "expired" | "no_chain" | "verify_failed" | "error"
	ChainMessage string
	ChainErrCode int
	ChainErrMsg  string
	ChainErrAt   int

	// Revocation status (separate pass)
	RevocationStatus  string // "ok" | "revoked" | "no_crl" | "skipped"
	RevocationMessage string

	Chain []CertInfo
}

func rcError(fn string, rc C.int32_t) error {
	names := map[C.int32_t]string{
		C.MP_ERR_INVALID_ARG: "invalid argument",
		C.MP_ERR_PARSE:       "parse error",
		C.MP_ERR_VERIFY:      "verification failed",
		C.MP_ERR_EXPIRED:     "certificate expired",
		C.MP_ERR_REVOKED:     "certificate revoked",
		C.MP_ERR_NO_CHAIN:    "incomplete chain",
		C.MP_ERR_NO_CRL:      "CRL not available",
		C.MP_ERR_OPENSSL:     "OpenSSL error",
		C.MP_ERR_UNEXPECTED:  "unexpected error",
	}
	if msg, ok := names[rc]; ok {
		return fmt.Errorf("%s: %s", fn, msg)
	}
	return fmt.Errorf("%s: error %d", fn, rc)
}

func rcStatus(rc C.int32_t) (string, string) {
	switch rc {
	case C.MP_OK:
		return "ok", ""
	case C.MP_ERR_EXPIRED:
		return "expired", "Certificate expired or not yet valid"
	case C.MP_ERR_REVOKED:
		return "revoked", "Certificate has been revoked"
	case C.MP_ERR_NO_CHAIN:
		return "no_chain", "Could not build complete trust chain"
	case C.MP_ERR_NO_CRL:
		return "no_crl", "CRL required but not available"
	case C.MP_ERR_VERIFY:
		return "verify_failed", "Signature verification failed"
	default:
		return "error", fmt.Sprintf("Verification error: %d", rc)
	}
}

func Open() (*Context, error) {
	var c C.MP_CTX
	rc := C.mp_open(C.MP_TYPE_OPENSSL, &c)
	if rc != C.MP_OK {
		return nil, rcError("mp_open", rc)
	}
	return &Context{c: c}, nil
}

func (ctx *Context) Close() error {
	if ctx.c == nil {
		return nil
	}
	rc := C.mp_close(ctx.c)
	ctx.c = nil
	if rc != C.MP_OK {
		return rcError("mp_close", rc)
	}
	return nil
}

func (ctx *Context) ParseCertInfo(data []byte) (*CertInfo, error) {
	if len(data) == 0 {
		return nil, errors.New("empty certificate data")
	}

	var cert C.MP_CERT
	rc := C.mp_cert_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&cert)
	if rc != C.MP_OK {
		return nil, rcError("mp_cert_parse", rc)
	}
	defer C.mp_cert_close(cert)

	return extractCertInfo(cert)
}

func extractCertInfo(cert C.MP_CERT) (*CertInfo, error) {
	info := &CertInfo{}
	var out *C.uint8_t
	var outlen C.size_t

	if C.mp_cert_subject(cert, &out, &outlen) == C.MP_OK {
		info.Subject = C.GoStringN((*C.char)(unsafe.Pointer(out)), C.int(outlen))
	}
	if C.mp_cert_issuer(cert, &out, &outlen) == C.MP_OK {
		info.Issuer = C.GoStringN((*C.char)(unsafe.Pointer(out)), C.int(outlen))
	}
	if C.mp_cert_serial(cert, &out, &outlen) == C.MP_OK {
		info.Serial = C.GoStringN((*C.char)(unsafe.Pointer(out)), C.int(outlen))
	}

	var t C.int64_t
	if C.mp_cert_not_before(cert, &t) == C.MP_OK {
		info.NotBefore = time.Unix(int64(t), 0).UTC()
	}
	if C.mp_cert_not_after(cert, &t) == C.MP_OK {
		info.NotAfter = time.Unix(int64(t), 0).UTC()
	}

	var flag C.int32_t
	if C.mp_cert_is_ca(cert, &flag) == C.MP_OK {
		info.IsCA = flag == 1
	}
	if C.mp_cert_is_self_signed(cert, &flag) == C.MP_OK {
		info.IsSelfSigned = flag == 1
	}

	if C.mp_cert_key_algorithm(cert, &out, &outlen) == C.MP_OK && outlen > 0 {
		info.KeyAlgorithm = C.GoStringN((*C.char)(unsafe.Pointer(out)), C.int(outlen))
	}
	var bits C.int32_t
	if C.mp_cert_key_bits(cert, &bits) == C.MP_OK {
		info.KeyBits = int(bits)
	}
	if C.mp_cert_key_curve(cert, &out, &outlen) == C.MP_OK && outlen > 0 {
		info.KeyCurve = C.GoStringN((*C.char)(unsafe.Pointer(out)), C.int(outlen))
	}

	var ku C.uint32_t
	if C.mp_cert_key_usage(cert, &ku) == C.MP_OK {
		info.KeyUsage = uint32(ku)
	}

	var ekuCount C.size_t
	if C.mp_cert_eku_count(cert, &ekuCount) == C.MP_OK {
		for i := C.size_t(0); i < ekuCount; i++ {
			var oid *C.uint8_t
			var oidlen C.size_t
			if C.mp_cert_eku_oid(cert, i, &oid, &oidlen) == C.MP_OK {
				info.EKUs = append(info.EKUs,
					C.GoStringN((*C.char)(unsafe.Pointer(oid)), C.int(oidlen)))
			}
		}
	}

	var pathlen C.int32_t
	if C.mp_cert_pathlen(cert, &pathlen) == C.MP_OK {
		info.PathLen = int(pathlen)
	} else {
		info.PathLen = -1
	}

	var sanCount C.size_t
	if C.mp_cert_san_count(cert, &sanCount) == C.MP_OK {
		for i := C.size_t(0); i < sanCount; i++ {
			var v *C.uint8_t
			var vlen C.size_t
			if C.mp_cert_san_entry(cert, i, &v, &vlen) == C.MP_OK {
				info.SANs = append(info.SANs,
					C.GoStringN((*C.char)(unsafe.Pointer(v)), C.int(vlen)))
			}
		}
	}

	if C.mp_cert_ski(cert, &out, &outlen) == C.MP_OK && outlen > 0 {
		info.SKI = C.GoStringN((*C.char)(unsafe.Pointer(out)), C.int(outlen))
	}
	if C.mp_cert_aki(cert, &out, &outlen) == C.MP_OK && outlen > 0 {
		info.AKI = C.GoStringN((*C.char)(unsafe.Pointer(out)), C.int(outlen))
	}

	var nameDER *C.uint8_t
	var nameDERLen C.size_t
	if C.mp_cert_subject_name_der(cert, &nameDER, &nameDERLen) == C.MP_OK && nameDERLen > 0 {
		info.SubjectNameDER = C.GoBytes(unsafe.Pointer(nameDER), C.int(nameDERLen))
	}
	if C.mp_cert_issuer_name_der(cert, &nameDER, &nameDERLen) == C.MP_OK && nameDERLen > 0 {
		info.IssuerNameDER = C.GoBytes(unsafe.Pointer(nameDER), C.int(nameDERLen))
	}

	var count C.size_t
	if C.mp_cert_aia_count(cert, &count) == C.MP_OK {
		for i := C.size_t(0); i < count; i++ {
			var url *C.uint8_t
			var urllen C.size_t
			if C.mp_cert_aia_url(cert, i, &url, &urllen) == C.MP_OK {
				info.AIAURLs = append(info.AIAURLs,
					C.GoStringN((*C.char)(unsafe.Pointer(url)), C.int(urllen)))
			}
		}
	}
	if C.mp_cert_ocsp_count(cert, &count) == C.MP_OK {
		for i := C.size_t(0); i < count; i++ {
			var url *C.uint8_t
			var urllen C.size_t
			if C.mp_cert_ocsp_url(cert, i, &url, &urllen) == C.MP_OK {
				info.OCSPURLs = append(info.OCSPURLs,
					C.GoStringN((*C.char)(unsafe.Pointer(url)), C.int(urllen)))
			}
		}
	}
	if C.mp_cert_cdp_count(cert, &count) == C.MP_OK {
		for i := C.size_t(0); i < count; i++ {
			var url *C.uint8_t
			var urllen C.size_t
			if C.mp_cert_cdp_url(cert, i, &url, &urllen) == C.MP_OK {
				info.CDPURLs = append(info.CDPURLs,
					C.GoStringN((*C.char)(unsafe.Pointer(url)), C.int(urllen)))
			}
		}
	}

	var der *C.uint8_t
	var derlen C.size_t
	if C.mp_cert_der(cert, &der, &derlen) == C.MP_OK {
		info.DER = C.GoBytes(unsafe.Pointer(der), C.int(derlen))
	}

	return info, nil
}

// ParseAllCerts extracts all DER-encoded X.509 certs from data.
// Handles single DER, single/multi PEM, and PKCS#7 containers.
func (ctx *Context) ParseAllCerts(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	var bag C.MP_BAG
	rc := C.mp_bag_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&bag)
	if rc != C.MP_OK {
		return nil, rcError("mp_bag_parse", rc)
	}
	defer C.mp_bag_close(bag)

	var count C.size_t
	C.mp_bag_count(bag, &count)

	result := make([][]byte, 0, count)
	for i := C.size_t(0); i < count; i++ {
		var der *C.uint8_t
		var derlen C.size_t
		if C.mp_bag_cert_der(bag, i, &der, &derlen) == C.MP_OK {
			result = append(result, C.GoBytes(unsafe.Pointer(der), C.int(derlen)))
		}
	}
	return result, nil
}

func (ctx *Context) ParseCRLInfo(data []byte) (*CRLInfo, error) {
	if len(data) == 0 {
		return nil, errors.New("empty CRL data")
	}

	var crl C.MP_CRL
	rc := C.mp_crl_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&crl)
	if rc != C.MP_OK {
		return nil, rcError("mp_crl_parse", rc)
	}
	defer C.mp_crl_close(crl)

	info := &CRLInfo{}
	var out *C.uint8_t
	var outlen C.size_t
	if C.mp_crl_issuer(crl, &out, &outlen) == C.MP_OK {
		info.Issuer = C.GoStringN((*C.char)(unsafe.Pointer(out)), C.int(outlen))
	}

	var t C.int64_t
	if C.mp_crl_this_update(crl, &t) == C.MP_OK {
		info.ThisUpdate = time.Unix(int64(t), 0).UTC()
	}
	if C.mp_crl_next_update(crl, &t) == C.MP_OK {
		info.NextUpdate = time.Unix(int64(t), 0).UTC()
	}

	var cnt C.size_t
	if C.mp_crl_revoked_count(crl, &cnt) == C.MP_OK {
		info.RevokedCount = int(cnt)
	}

	var nameDER *C.uint8_t
	var nameDERLen C.size_t
	if C.mp_crl_issuer_name_der(crl, &nameDER, &nameDERLen) == C.MP_OK && nameDERLen > 0 {
		info.IssuerNameDER = C.GoBytes(unsafe.Pointer(nameDER), C.int(nameDERLen))
	}

	var akiOut *C.uint8_t
	var akiLen C.size_t
	if C.mp_crl_aki(crl, &akiOut, &akiLen) == C.MP_OK && akiLen > 0 {
		info.AKI = C.GoStringN((*C.char)(unsafe.Pointer(akiOut)), C.int(akiLen))
	}

	var hasIDP C.int32_t
	if C.mp_crl_has_idp(crl, &hasIDP) == C.MP_OK {
		info.HasIDP = hasIDP == 1
	}

	info.DER = make([]byte, len(data))
	copy(info.DER, data)

	return info, nil
}

// VerifyCRL checks CRL signature against issuer's public key.
// Returns ErrCRLBadSignature if signature is invalid, other errors on
// parse/internal failure, nil on success.
func (ctx *Context) VerifyCRL(crlDER, issuerDER []byte) error {
	if len(crlDER) == 0 || len(issuerDER) == 0 {
		return errors.New("empty CRL or issuer data")
	}

	var issuer C.MP_CERT
	rc := C.mp_cert_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&issuerDER[0])),
		C.size_t(len(issuerDER)),
		&issuer)
	if rc != C.MP_OK {
		return rcError("mp_cert_parse(issuer)", rc)
	}
	defer C.mp_cert_close(issuer)

	var crl C.MP_CRL
	rc = C.mp_crl_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&crlDER[0])),
		C.size_t(len(crlDER)),
		&crl)
	if rc != C.MP_OK {
		return rcError("mp_crl_parse", rc)
	}
	defer C.mp_crl_close(crl)

	rc = C.mp_crl_verify(crl, issuer)
	switch rc {
	case C.MP_OK:
		return nil
	case C.MP_ERR_VERIFY:
		return ErrCRLBadSignature
	default:
		return rcError("mp_crl_verify", rc)
	}
}

func (ctx *Context) CheckRevocation(certDER, crlDER []byte) (bool, error) {
	if len(certDER) == 0 || len(crlDER) == 0 {
		return false, errors.New("empty data")
	}

	var cert C.MP_CERT
	rc := C.mp_cert_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&certDER[0])),
		C.size_t(len(certDER)),
		&cert)
	if rc != C.MP_OK {
		return false, rcError("mp_cert_parse", rc)
	}
	defer C.mp_cert_close(cert)

	var crl C.MP_CRL
	rc = C.mp_crl_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&crlDER[0])),
		C.size_t(len(crlDER)),
		&crl)
	if rc != C.MP_OK {
		return false, rcError("mp_crl_parse", rc)
	}
	defer C.mp_crl_close(crl)

	var result C.int32_t
	rc = C.mp_crl_is_revoked(crl, cert, &result)
	if rc != C.MP_OK {
		return false, rcError("mp_crl_is_revoked", rc)
	}
	return result == 1, nil
}

// Verify does chain validation (signatures, dates, structure).
// Revocation check is performed manually by the caller via CheckRevocation
// per-cert, because OpenSSL's CRL_CHECK_ALL is too strict — it requires
// a CRL for every cert in chain, but real-world certs (e.g., Sectigo leaf)
// often have only OCSP and no CDP, which we shouldn't treat as failure.
func (ctx *Context) Verify(leafDER []byte, roots, intermediates, crls [][]byte) (*VerifyResult, error) {
	if len(leafDER) == 0 {
		return nil, errors.New("empty leaf certificate")
	}

	var cert C.MP_CERT
	rc := C.mp_cert_parse(ctx.c,
		(*C.uint8_t)(unsafe.Pointer(&leafDER[0])),
		C.size_t(len(leafDER)),
		&cert)
	if rc != C.MP_OK {
		return nil, rcError("mp_cert_parse", rc)
	}
	defer C.mp_cert_close(cert)

	var store C.MP_STORE
	rc = C.mp_store_new(ctx.c, &store)
	if rc != C.MP_OK {
		return nil, rcError("mp_store_new", rc)
	}
	defer C.mp_store_close(store)

	for i, r := range roots {
		rc := C.mp_store_add_root(store,
			(*C.uint8_t)(unsafe.Pointer(&r[0])),
			C.size_t(len(r)))
		if rc != C.MP_OK {
			return nil, fmt.Errorf("add_root[%d]: %w", i, rcError("mp_store_add_root", rc))
		}
	}
	for i, im := range intermediates {
		rc := C.mp_store_add_intermediate(store,
			(*C.uint8_t)(unsafe.Pointer(&im[0])),
			C.size_t(len(im)))
		if rc != C.MP_OK {
			return nil, fmt.Errorf("add_intermediate[%d]: %w", i, rcError("mp_store_add_intermediate", rc))
		}
	}
	for i, cr := range crls {
		rc := C.mp_store_add_crl(store,
			(*C.uint8_t)(unsafe.Pointer(&cr[0])),
			C.size_t(len(cr)))
		if rc != C.MP_OK {
			return nil, fmt.Errorf("add_crl[%d]: %w", i, rcError("mp_store_add_crl", rc))
		}
	}

	result := &VerifyResult{RevocationStatus: "skipped"}

	// Chain validity check (CRL flags off — caller does revocation manually)
	C.mp_store_set_crl_check(store, 0)
	var chain1 C.MP_CHAIN
	rc = C.mp_verify(store, cert, &chain1)
	if rc != C.MP_OK {
		status, msg := rcStatus(rc)
		errCode, errDepth, errMsg := getLastVerifyError(store)
		result.ChainStatus = status
		result.ChainMessage = msg
		result.ChainErrCode = errCode
		result.ChainErrAt = errDepth
		result.ChainErrMsg = errMsg
		return result, nil
	}
	defer C.mp_chain_close(chain1)

	result.ChainStatus = "ok"

	var count C.size_t
	if C.mp_chain_count(chain1, &count) == C.MP_OK {
		for i := C.size_t(0); i < count; i++ {
			var cc C.MP_CERT
			if C.mp_chain_cert(chain1, i, &cc) == C.MP_OK {
				ci, err := extractCertInfo(cc)
				if err == nil {
					result.Chain = append(result.Chain, *ci)
				}
			}
		}
	}

	return result, nil
}

func getLastVerifyError(store C.MP_STORE) (code, depth int, msg string) {
	var c, d C.int32_t
	var m *C.uint8_t
	var mlen C.size_t
	C.mp_verify_last_error(store, &c, &d, &m, &mlen)
	if mlen > 0 {
		msg = C.GoStringN((*C.char)(unsafe.Pointer(m)), C.int(mlen))
	}
	return int(c), int(d), msg
}

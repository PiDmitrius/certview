package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/PiDmitrius/certview/internal/pki"
	"github.com/PiDmitrius/certview/internal/store"
)

func issue(t *testing.T, cn string, serial int64, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestChainsToTrustByContent(t *testing.T) {
	ctx, err := pki.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "certview.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := &handler{ctx: ctx, store: st}

	save := func(c *x509.Certificate, trusted bool) *pki.CertInfo {
		info, err := ctx.ParseCertInfo(c.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if trusted {
			_, err = st.ImportTrustedCert(info.Subject, info.Issuer, info.Serial, info.SKI, info.AKI, info.SubjectNameDER, info.DER, true, info.IsSelfSigned, "test")
		} else {
			err = st.SaveCert(info.Subject, info.Issuer, info.Serial, info.SKI, info.AKI, info.SubjectNameDER, info.DER, true, info.IsSelfSigned, "")
		}
		if err != nil {
			t.Fatal(err)
		}
		return info
	}

	root, rootKey := issue(t, "Root", 1, nil, nil)
	inter, _ := issue(t, "Inter", 2, root, rootKey)
	save(root, true)
	interInfo := save(inter, false)
	if !h.chainsToTrust(interInfo) {
		t.Fatal("intermediate under a trusted root not trusted")
	}

	lookalike, lookalikeKey := issue(t, "Root", 7, nil, nil)
	save(lookalike, false)
	signed, _ := issue(t, "Signed by lookalike", 8, lookalike, lookalikeKey)
	if _, ok := h.trustedPath(signed.Raw, [][]byte{root.Raw, lookalike.Raw}, nil); ok {
		t.Fatal("path to an untrusted root named like a trusted one was trusted")
	}
	if via, ok := h.trustedPath(inter.Raw, [][]byte{root.Raw, lookalike.Raw}, nil); !ok || via == "" {
		t.Fatal("path to the trusted root not trusted")
	}
	if ders := h.poolIssuers(inter.RawSubject); len(ders) != 1 || !bytes.Equal(ders[0], inter.Raw) {
		t.Fatal("CA on a verified path did not join the issuer pool")
	}
	if ders := h.poolIssuers(lookalike.RawSubject); len(ders) != 1 || !bytes.Equal(ders[0], root.Raw) {
		t.Fatal("lookalike root joined the issuer pool")
	}

	forged, forgedKey := issue(t, "Forged", 1, nil, nil)
	victim, _ := issue(t, "Victim", 3, forged, forgedKey)
	save(forged, false)
	if h.chainsToTrust(save(victim, false)) {
		t.Fatal("chain to an untrusted root sharing a trusted root's serial was trusted")
	}
}

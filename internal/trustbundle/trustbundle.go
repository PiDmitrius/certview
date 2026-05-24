package trustbundle

import (
	"bytes"
	_ "embed"
	"log"

	"github.com/PiDmitrius/certview/internal/pki"
	"github.com/PiDmitrius/certview/internal/store"
)

//go:embed mozilla.pem
var mozillaPEM []byte

//go:embed russian.pem
var russianPEM []byte

// ImportDefaults imports bundled CA certs as trusted roots.
// Only self-signed certs are marked trusted; intermediates from the bundle
// go to the regular cache (will be discovered via AIA chain anyway).
// Idempotent — uses ON CONFLICT to avoid duplicates.
func ImportDefaults(ctx *pki.Context, st *store.Store) error {
	count, err := st.CountTrusted()
	if err != nil {
		return err
	}
	if count > 0 {
		log.Printf("trustbundle: %d trusted certs already in store, skipping import", count)
		return nil
	}

	mozTrust, mozInter := importBundle(ctx, st, mozillaPEM, "mozilla")
	ruTrust, ruInter := importBundle(ctx, st, russianPEM, "ru-gov")

	log.Printf("trustbundle: imported %d trusted roots, %d intermediates from Mozilla bundle",
		mozTrust, mozInter)
	log.Printf("trustbundle: imported %d trusted roots, %d intermediates from Russian bundle",
		ruTrust, ruInter)
	return nil
}

func importBundle(ctx *pki.Context, st *store.Store, data []byte, source string) (trustedCount, interCount int) {
	for _, block := range splitPEM(data) {
		info, err := ctx.ParseCertInfo(block)
		if err != nil {
			continue
		}
		if info.IsSelfSigned {
			if err := st.ImportTrustedCert(
				info.Subject, info.Issuer, info.Serial,
				info.SKI, info.AKI, info.SubjectNameDER,
				info.DER, info.IsCA, info.IsSelfSigned, source,
			); err != nil {
				log.Printf("trustbundle: import trusted %s: %v", info.Subject, err)
				continue
			}
			trustedCount++
		} else {
			if err := st.SaveCert(
				info.Subject, info.Issuer, info.Serial,
				info.SKI, info.AKI, info.SubjectNameDER,
				info.DER, info.IsCA, info.IsSelfSigned, source,
			); err != nil {
				log.Printf("trustbundle: import intermediate %s: %v", info.Subject, err)
				continue
			}
			interCount++
		}
	}
	return
}

func splitPEM(data []byte) [][]byte {
	var blocks [][]byte
	begin := []byte("-----BEGIN CERTIFICATE-----")
	end := []byte("-----END CERTIFICATE-----")
	for {
		i := bytes.Index(data, begin)
		if i < 0 {
			break
		}
		j := bytes.Index(data[i:], end)
		if j < 0 {
			break
		}
		blocks = append(blocks, data[i:i+j+len(end)])
		data = data[i+j+len(end):]
	}
	return blocks
}

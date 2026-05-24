package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
)

type OpensslGostFetcher struct{}

func (OpensslGostFetcher) Name() string { return "openssl-gost" }

var (
	opensslGostOnce  sync.Once
	opensslGostAvail bool
)

func (OpensslGostFetcher) Available() bool {
	opensslGostOnce.Do(func() {
		cmd := exec.Command("openssl", "engine", "-t", "gost")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return
		}
		// `openssl engine -t gost` prints "[ available ]" when the engine
		// loads successfully, "[ unavailable ]" otherwise.
		if !bytes.Contains(out, []byte("[ available ]")) {
			return
		}
		opensslGostAvail = true
	})
	return opensslGostAvail
}

// Stable line emitted by s_client right after the handshake, e.g.:
//	New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
//	New, TLSv1.2, Cipher is GOST2012-KUZNYECHIK-KUZNYECHIKOMAC
var rxNewCipher = regexp.MustCompile(`(?m)^New, (TLS\S+), Cipher is (\S+)`)

// GOST-only cipher list. gost-engine exposes both the IANA-registered codes
// (RFC 9189: KUZNYECHIK/MAGMA/28147) and the older CryptoPro legacy names
// (0xFF85, 0x0081). We offer all of them so the widest range of GOST servers
// (Минцифры, ФНС, ЦБ, etc.) can pick whatever they understand, but RSA/ECDSA
// suites are excluded — this plugin's only job is to produce a GOST handshake.
const gostCipherList = "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC:" +
	"GOST2012-MAGMA-MAGMAOMAC:" +
	"IANA-GOST2012-GOST8912-GOST8912:" +
	"LEGACY-GOST2012-GOST8912-GOST8912:" +
	"GOST2001-GOST89-GOST89"

func (OpensslGostFetcher) Fetch(ctx context.Context, host, ip string, port int, sni string) (*Result, error) {
	args := []string{
		"s_client",
		"-engine", "gost",
		"-tls1_2",
		"-cipher", gostCipherList,
		"-connect", net.JoinHostPort(ip, strconv.Itoa(port)),
		"-servername", sni,
		"-showcerts",
	}
	cmd := exec.CommandContext(ctx, "openssl", args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	// stdin is /dev/null by default; s_client sees EOF and exits after handshake.

	runErr := cmd.Run()
	data := out.Bytes()

	var chain [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if len(block.Bytes) > MaxCertSize {
			return nil, fmt.Errorf("cert too big: %d > %d", len(block.Bytes), MaxCertSize)
		}
		chain = append(chain, block.Bytes)
		if len(chain) > MaxChainLen {
			return nil, fmt.Errorf("chain too long: > %d", MaxChainLen)
		}
	}
	if len(chain) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("openssl: %w (stderr: %s)", runErr, trimErr(errBuf.String()))
		}
		return nil, fmt.Errorf("no certificates in openssl output (stderr: %s)", trimErr(errBuf.String()))
	}

	res := &Result{Chain: chain}
	if m := rxNewCipher.FindSubmatch(data); m != nil {
		res.TLSVersion = string(m[1])
		res.CipherSuite = string(m[2])
	}
	return res, nil
}

func trimErr(s string) string {
	const max = 512
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

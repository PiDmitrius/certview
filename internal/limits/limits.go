// Package limits holds the bounds shared by certview and certget.
package limits

import (
	"net/http"
	"time"
)

// CertSize bounds a single DER certificate from any source.
const CertSize = 64 << 10

// ListenAndServe serves h with timeouts that stop slow clients from holding
// connections open.
func ListenAndServe(addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	return srv.ListenAndServe()
}

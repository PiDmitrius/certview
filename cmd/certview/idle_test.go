package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIdleTimeoutTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 3; i++ {
			w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			time.Sleep(60 * time.Millisecond)
		}
		if r.URL.Path == "/stall" {
			<-r.Context().Done()
		}
	}))
	defer srv.Close()

	client := &http.Client{Transport: idleTimeoutTransport{idle: 100 * time.Millisecond, base: http.DefaultTransport}}
	get := func(path string) error {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		return err
	}

	if err := get("/slow"); err != nil {
		t.Fatalf("progressing download longer than idle: %v", err)
	}
	if err := get("/stall"); !errors.Is(err, errIdleTimeout) {
		t.Fatalf("stalled download: got %v, want errIdleTimeout", err)
	}
}

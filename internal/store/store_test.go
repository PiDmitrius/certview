package store

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestSHA256BackfillAndLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certview.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	crl := []byte("legacy crl der")
	_, err = legacy.Exec(`
		CREATE TABLE crls (
			id          INTEGER PRIMARY KEY,
			issuer      TEXT    NOT NULL,
			url         TEXT    NOT NULL UNIQUE,
			der         BLOB   NOT NULL,
			this_update INTEGER NOT NULL,
			next_update INTEGER NOT NULL,
			created_at  INTEGER NOT NULL
		);
		INSERT INTO crls (issuer, url, der, this_update, next_update, created_at)
		VALUES ('CA', 'http://example.test/ca.crl', ?, 0, 0, 0);`, crl)
	legacy.Close()
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got, err := s.FindDERBySHA256(SHA256Hex(crl))
	if err != nil || !bytes.Equal(got, crl) {
		t.Fatalf("backfilled CRL: got %q, %v", got, err)
	}

	ocsp := []byte("ocsp der")
	if err := s.SaveOCSP("AB", "http://example.test/ocsp", "good", ocsp, time.Now(), time.Time{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !s.HasDER(SHA256Hex(ocsp)) {
		t.Fatal("saved OCSP response not found by sha256")
	}
	if s.HasDER(SHA256Hex([]byte("missing"))) {
		t.Fatal("unexpected hit for unknown sha256")
	}
}

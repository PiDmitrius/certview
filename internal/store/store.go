package store

import (
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func sha1hex(der []byte) string {
	s := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

// SHA256Hex is the content address used by FindDERBySHA256.
func SHA256Hex(der []byte) string {
	s := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

var derTables = []string{"certs", "crls", "ocsp_responses"}

// A certificate is identified by the SHA-256 of its DER: serials are unique
// only per issuer, so trust and deduplication never go by serial. Every
// certificate seen is archived. FindIssuers returns the candidate issuers of
// a certificate: matches in the pool (poolCond) — trusted certificates
// and those flagged pool, i.e. bundled intermediates and CAs verified on a
// path to a trusted root — and a bounded sample of the oldest and newest
// other archived matches, which callers use only as a last resort.
// CRLs are stored once per content, with fetch URLs mapped to it in
// crl_urls.
const certsDDL = `CREATE TABLE IF NOT EXISTS %s (
	id               INTEGER PRIMARY KEY,
	subject          TEXT    NOT NULL,
	issuer           TEXT    NOT NULL,
	serial           TEXT    NOT NULL,
	ski              TEXT    NOT NULL DEFAULT '',
	aki              TEXT    NOT NULL DEFAULT '',
	subject_name_der BLOB,
	trusted          INTEGER NOT NULL DEFAULT 0,
	pool             INTEGER NOT NULL DEFAULT 0,
	thumbprint_sha1  TEXT    NOT NULL DEFAULT '',
	sha256           TEXT    NOT NULL DEFAULT '',
	der              BLOB    NOT NULL,
	is_ca            INTEGER NOT NULL DEFAULT 0,
	is_self_signed   INTEGER NOT NULL DEFAULT 0,
	source_url       TEXT,
	created_at       INTEGER NOT NULL
)`

const certsColumns = "id, subject, issuer, serial, ski, aki, subject_name_der, trusted, pool, thumbprint_sha1, sha256, der, is_ca, is_self_signed, source_url, created_at"

const poolCond = "(trusted = 1 OR pool = 1)"

const crlsDDL = `CREATE TABLE IF NOT EXISTS %s (
	id          INTEGER PRIMARY KEY,
	issuer      TEXT    NOT NULL,
	sha256      TEXT    NOT NULL DEFAULT '',
	der         BLOB    NOT NULL,
	this_update INTEGER NOT NULL,
	next_update INTEGER NOT NULL,
	created_at  INTEGER NOT NULL
)`

const crlsColumns = "id, issuer, sha256, der, this_update, next_update, created_at"

var serialUnique = regexp.MustCompile(`serial\s+TEXT\s+NOT NULL\s+UNIQUE`)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(fmt.Sprintf(certsDDL, "certs")); err != nil {
		return err
	}
	if _, err := s.db.Exec(fmt.Sprintf(crlsDDL, "crls")); err != nil {
		return err
	}
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS crl_urls (
			url    TEXT PRIMARY KEY,
			sha256 TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS ocsp_responses (
			id              INTEGER PRIMARY KEY,
			cert_thumbprint TEXT    NOT NULL,
			responder_url   TEXT    NOT NULL,
			status          TEXT    NOT NULL,
			this_update     INTEGER NOT NULL,
			next_update     INTEGER,
			produced_at     INTEGER NOT NULL,
			der             BLOB    NOT NULL,
			created_at      INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_ocsp_thumbprint ON ocsp_responses(cert_thumbprint);
	`)
	if err != nil {
		return err
	}

	s.db.Exec("ALTER TABLE certs ADD COLUMN ski TEXT NOT NULL DEFAULT ''")
	s.db.Exec("ALTER TABLE certs ADD COLUMN aki TEXT NOT NULL DEFAULT ''")
	s.db.Exec("ALTER TABLE certs ADD COLUMN subject_name_der BLOB")
	s.db.Exec("ALTER TABLE certs ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0")
	s.db.Exec("ALTER TABLE certs ADD COLUMN thumbprint_sha1 TEXT NOT NULL DEFAULT ''")
	s.db.Exec("ALTER TABLE certs ADD COLUMN pool INTEGER NOT NULL DEFAULT 0")
	for _, t := range derTables {
		s.db.Exec("ALTER TABLE " + t + " ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''")
		if err := s.backfillSHA256(t); err != nil {
			return fmt.Errorf("backfill %s.sha256: %w", t, err)
		}
	}
	if err := s.dropSerialUnique(); err != nil {
		return fmt.Errorf("certs: drop serial uniqueness: %w", err)
	}
	if err := s.splitCRLURLs(); err != nil {
		return fmt.Errorf("crls: split urls: %w", err)
	}
	if err := s.repairSHA1(); err != nil {
		return fmt.Errorf("certs: repair sha1: %w", err)
	}

	for _, stmt := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_sha256 ON certs(sha256)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_crls_sha256 ON crls(sha256)",
		"CREATE INDEX IF NOT EXISTS idx_crls_issuer ON crls(issuer)",
		"CREATE INDEX IF NOT EXISTS idx_ocsp_responses_sha256 ON ocsp_responses(sha256)",
		"DROP INDEX IF EXISTS idx_certs_subject",
		"DROP INDEX IF EXISTS idx_certs_serial",
		"DROP INDEX IF EXISTS idx_certs_ski",
		"DROP INDEX IF EXISTS idx_certs_trusted",
		"CREATE INDEX IF NOT EXISTS idx_certs_subject_name_der ON certs(subject_name_der)",
		"CREATE INDEX IF NOT EXISTS idx_certs_name_ski ON certs(subject_name_der, ski)",
		"CREATE INDEX IF NOT EXISTS idx_certs_pool ON certs(subject_name_der, ski) WHERE " + poolCond,
		"CREATE INDEX IF NOT EXISTS idx_certs_thumbprint_sha1 ON certs(thumbprint_sha1)",
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// dropSerialUnique rebuilds a certs table created with a UNIQUE serial.
func (s *Store) dropSerialUnique() error {
	var ddl string
	if err := s.db.QueryRow("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'certs'").Scan(&ddl); err != nil {
		return err
	}
	if !serialUnique.MatchString(ddl) {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		fmt.Sprintf(certsDDL, "certs_new"),
		"INSERT INTO certs_new (" + certsColumns + ") SELECT " + certsColumns + " FROM certs",
		"DROP TABLE certs",
		"ALTER TABLE certs_new RENAME TO certs",
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// repairSHA1 recomputes thumbprints once (user_version 1): serial-keyed
// imports once wrote another certificate's thumbprint on a shared serial.
func (s *Store) repairSHA1() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v >= 1 {
		return err
	}
	ids, err := s.ids("SELECT id FROM certs")
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		var der []byte
		if err := tx.QueryRow("SELECT der FROM certs WHERE id = ?", id).Scan(&der); err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE certs SET thumbprint_sha1 = ? WHERE id = ?", sha1hex(der), id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("PRAGMA user_version = 1"); err != nil {
		return err
	}
	return tx.Commit()
}

// splitCRLURLs rebuilds a crls table keyed by URL into content rows plus
// crl_urls, keeping the newest row per content.
func (s *Store) splitCRLURLs() error {
	var n int
	if err := s.db.QueryRow("SELECT count(*) FROM pragma_table_info('crls') WHERE name = 'url'").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		"INSERT OR REPLACE INTO crl_urls (url, sha256) SELECT url, sha256 FROM crls WHERE url NOT LIKE 'upload://%' ORDER BY id",
		fmt.Sprintf(crlsDDL, "crls_new"),
		"INSERT INTO crls_new (" + crlsColumns + ") SELECT " + crlsColumns + " FROM crls WHERE id IN (SELECT max(id) FROM crls GROUP BY sha256)",
		"DROP TABLE crls",
		"ALTER TABLE crls_new RENAME TO crls",
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ids(query string) ([]int64, error) {
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) backfillSHA256(table string) error {
	ids, err := s.ids("SELECT id FROM " + table + " WHERE sha256 = ''")
	if err != nil {
		return err
	}
	for _, id := range ids {
		var der []byte
		if err := s.db.QueryRow("SELECT der FROM "+table+" WHERE id = ?", id).Scan(&der); err != nil {
			return err
		}
		if _, err := s.db.Exec("UPDATE "+table+" SET sha256 = ? WHERE id = ?", SHA256Hex(der), id); err != nil {
			return err
		}
	}
	return nil
}

// FindDERBySHA256 returns a stored certificate, CRL or OCSP response by content hash.
func (s *Store) FindDERBySHA256(sha256Hex string) ([]byte, error) {
	sha256Hex = strings.ToUpper(sha256Hex)
	for _, t := range derTables {
		var der []byte
		err := s.db.QueryRow("SELECT der FROM "+t+" WHERE sha256 = ? LIMIT 1", sha256Hex).Scan(&der)
		if err == nil {
			return der, nil
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	return nil, nil
}

// DERSize returns the size of the stored object with the hash, 0 if none.
func (s *Store) DERSize(sha256Hex string) (int, error) {
	sha256Hex = strings.ToUpper(sha256Hex)
	for _, t := range derTables {
		var n int
		err := s.db.QueryRow("SELECT length(der) FROM "+t+" WHERE sha256 = ? LIMIT 1", sha256Hex).Scan(&n)
		if err == nil {
			return n, nil
		}
		if err != sql.ErrNoRows {
			return 0, err
		}
	}
	return 0, nil
}

func (s *Store) HasDER(sha256Hex string) bool {
	sha256Hex = strings.ToUpper(sha256Hex)
	for _, t := range derTables {
		var one int
		if s.db.QueryRow("SELECT 1 FROM "+t+" WHERE sha256 = ? LIMIT 1", sha256Hex).Scan(&one) == nil {
			return true
		}
	}
	return false
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SaveCert(subject, issuer, serial, ski, aki string, subjectNameDER, der []byte, isCA, isSelfSigned bool, sourceURL string) error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO certs
			(subject, issuer, serial, ski, aki, subject_name_der, thumbprint_sha1, sha256, der,
			 is_ca, is_self_signed, source_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		subject, issuer, serial, ski, aki, subjectNameDER, sha1hex(der), SHA256Hex(der), der,
		btoi(isCA), btoi(isSelfSigned),
		sourceURL, time.Now().Unix(),
	)
	return err
}

// FindCertByThumbprint finds a certificate by its SHA-1 or SHA-256 thumbprint.
func (s *Store) FindCertByThumbprint(hexDigest string) ([]byte, error) {
	column := "thumbprint_sha1"
	switch len(hexDigest) {
	case 40:
	case 64:
		column = "sha256"
	default:
		return nil, nil
	}
	var der []byte
	err := s.db.QueryRow(
		"SELECT der FROM certs WHERE "+column+" = ? LIMIT 1",
		strings.ToUpper(hexDigest),
	).Scan(&der)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return der, err
}

// FreshCRLSize returns the size of the fresh CRL stored for url, 0 if none.
func (s *Store) FreshCRLSize(url string) (int, error) {
	var n int
	err := s.db.QueryRow(
		"SELECT length(c.der) FROM crl_urls u JOIN crls c ON c.sha256 = u.sha256 WHERE u.url = ? AND c.next_update > ?",
		url, time.Now().Unix(),
	).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}

func (s *Store) FindFreshCRL(url string) ([]byte, error) {
	var der []byte
	err := s.db.QueryRow(
		"SELECT c.der FROM crl_urls u JOIN crls c ON c.sha256 = u.sha256 WHERE u.url = ? AND c.next_update > ?",
		url, time.Now().Unix(),
	).Scan(&der)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return der, err
}

// FindFreshCRLByIssuer returns latest non-expired CRL whose issuer matches.
// Used as fallback when CDP URL fetch fails or for manually uploaded CRLs.
func (s *Store) FindFreshCRLByIssuer(issuer string) ([]byte, error) {
	if issuer == "" {
		return nil, nil
	}
	var der []byte
	err := s.db.QueryRow(
		"SELECT der FROM crls WHERE issuer = ? AND next_update > ? ORDER BY this_update DESC LIMIT 1",
		issuer, time.Now().Unix(),
	).Scan(&der)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return der, err
}

// SaveCRL stores the CRL once per content, maps url (if any) to it, and
// drops expired CRLs.
func (s *Store) SaveCRL(issuer, url string, der []byte, thisUpdate, nextUpdate time.Time) error {
	for _, stmt := range []string{
		"DELETE FROM crls WHERE next_update < ?",
		"DELETE FROM crl_urls WHERE sha256 NOT IN (SELECT sha256 FROM crls WHERE next_update >= ?)",
	} {
		if _, err := s.db.Exec(stmt, time.Now().Unix()); err != nil {
			return err
		}
	}
	sha := SHA256Hex(der)
	if _, err := s.db.Exec(`
		INSERT OR IGNORE INTO crls
			(issuer, sha256, der, this_update, next_update, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		issuer, sha, der, thisUpdate.Unix(), nextUpdate.Unix(), time.Now().Unix(),
	); err != nil {
		return err
	}
	if url == "" {
		return nil
	}
	_, err := s.db.Exec("INSERT OR REPLACE INTO crl_urls (url, sha256) VALUES (?, ?)", url, sha)
	return err
}

// ImportTrustedCert trusts a bundled cert unless it was already imported from
// the same source; reports whether it was added or newly trusted.
func (s *Store) ImportTrustedCert(subject, issuer, serial, ski, aki string, subjectNameDER, der []byte, isCA, isSelfSigned bool, sourceURL string) (bool, error) {
	if _, err := s.db.Exec("UPDATE certs SET pool = 1 WHERE sha256 = ?", SHA256Hex(der)); err != nil {
		return false, err
	}
	res, err := s.db.Exec(`
		INSERT INTO certs
			(subject, issuer, serial, ski, aki, subject_name_der, trusted, pool, thumbprint_sha1, sha256, der,
			 is_ca, is_self_signed, source_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(sha256) DO UPDATE SET trusted = 1, source_url = excluded.source_url
		WHERE certs.source_url IS NOT excluded.source_url`,
		subject, issuer, serial, ski, aki, subjectNameDER, sha1hex(der), SHA256Hex(der), der,
		btoi(isCA), btoi(isSelfSigned),
		sourceURL, time.Now().Unix(),
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Candidate is a stored certificate that may have issued another.
type Candidate struct {
	DER  []byte
	Pool bool
}

// FindIssuers returns the certificates whose subject is issuerNameDER and,
// unless aki is empty, whose SKI is aki: up to pool pool matches (self-signed
// and trusted first), then up to archive oldest and archive newest other
// archived matches. Each branch is an index seek, so its cost does not grow
// with the number of archived certificates sharing the name.
func (s *Store) FindIssuers(issuerNameDER []byte, aki string, pool, archive int) ([]Candidate, error) {
	match, args := "subject_name_der = ?", []any{issuerNameDER}
	if aki != "" {
		match, args = match+" AND ski = ?", append(args, aki)
	}
	query := `SELECT id, der, 1 FROM (SELECT id, der FROM certs INDEXED BY idx_certs_pool WHERE ` + match + ` AND ` + poolCond + `
		ORDER BY is_self_signed DESC, trusted DESC, id LIMIT ?)`
	all := append(append([]any{}, args...), pool)
	if archive > 0 {
		for _, order := range []string{"", " DESC"} {
			query += `
		UNION ALL
		SELECT id, der, 0 FROM (SELECT id, der FROM certs WHERE ` + match + ` AND NOT ` + poolCond + `
			ORDER BY id` + order + ` LIMIT ?)`
			all = append(append(all, args...), archive)
		}
	}
	rows, err := s.db.Query(query, all...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[int64]bool{}
	var out []Candidate
	for rows.Next() {
		var id int64
		var c Candidate
		if err := rows.Scan(&id, &c.DER, &c.Pool); err != nil {
			return nil, err
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// SavePoolCert stores a candidate issuer: a bundled intermediate or a CA
// verified on a path to a trusted root.
func (s *Store) SavePoolCert(subject, issuer, serial, ski, aki string, subjectNameDER, der []byte, isCA, isSelfSigned bool, sourceURL string) error {
	_, err := s.db.Exec(`
		INSERT INTO certs
			(subject, issuer, serial, ski, aki, subject_name_der, pool, thumbprint_sha1, sha256, der,
			 is_ca, is_self_signed, source_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(sha256) DO UPDATE SET pool = 1`,
		subject, issuer, serial, ski, aki, subjectNameDER, sha1hex(der), SHA256Hex(der), der,
		btoi(isCA), btoi(isSelfSigned), sourceURL, time.Now().Unix(),
	)
	return err
}

func (s *Store) SetTrusted(sha256Hex string, trusted bool) error {
	v := 0
	if trusted {
		v = 1
	}
	res, err := s.db.Exec("UPDATE certs SET trusted = ? WHERE sha256 = ?", v, strings.ToUpper(sha256Hex))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) IsCertTrusted(sha256Hex string) (bool, error) {
	var trusted int
	err := s.db.QueryRow("SELECT trusted FROM certs WHERE sha256 = ?", strings.ToUpper(sha256Hex)).Scan(&trusted)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return trusted == 1, nil
}

func (s *Store) FindFreshOCSP(certThumbprint string) ([]byte, error) {
	if certThumbprint == "" {
		return nil, nil
	}
	var der []byte
	err := s.db.QueryRow(`
		SELECT der FROM ocsp_responses
		WHERE cert_thumbprint = ?
		  AND (next_update IS NULL OR next_update > ?)
		ORDER BY this_update DESC LIMIT 1`,
		strings.ToUpper(certThumbprint), time.Now().Unix(),
	).Scan(&der)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return der, err
}

func (s *Store) SaveOCSP(certThumbprint, responderURL, status string, der []byte,
	thisUpdate, nextUpdate, producedAt time.Time) error {

	var nextU *int64
	if !nextUpdate.IsZero() {
		v := nextUpdate.Unix()
		nextU = &v
	}
	_, err := s.db.Exec(`
		INSERT INTO ocsp_responses
			(cert_thumbprint, responder_url, status, this_update, next_update,
			 produced_at, sha256, der, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.ToUpper(certThumbprint), responderURL, status,
		thisUpdate.Unix(), nextU, producedAt.Unix(), SHA256Hex(der), der, time.Now().Unix(),
	)
	return err
}

func (s *Store) Stats() (certs, crls int, err error) {
	err = s.db.QueryRow("SELECT COUNT(*) FROM certs").Scan(&certs)
	if err != nil {
		return
	}
	err = s.db.QueryRow("SELECT COUNT(*) FROM crls").Scan(&crls)
	return
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

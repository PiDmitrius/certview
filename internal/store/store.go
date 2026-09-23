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
// only per issuer, so trust and deduplication never go by serial.
const certsDDL = `CREATE TABLE IF NOT EXISTS %s (
	id               INTEGER PRIMARY KEY,
	subject          TEXT    NOT NULL,
	issuer           TEXT    NOT NULL,
	serial           TEXT    NOT NULL,
	ski              TEXT    NOT NULL DEFAULT '',
	aki              TEXT    NOT NULL DEFAULT '',
	subject_name_der BLOB,
	trusted          INTEGER NOT NULL DEFAULT 0,
	thumbprint_sha1  TEXT    NOT NULL DEFAULT '',
	sha256           TEXT    NOT NULL DEFAULT '',
	der              BLOB    NOT NULL,
	is_ca            INTEGER NOT NULL DEFAULT 0,
	is_self_signed   INTEGER NOT NULL DEFAULT 0,
	source_url       TEXT,
	created_at       INTEGER NOT NULL
)`

const certsColumns = "id, subject, issuer, serial, ski, aki, subject_name_der, trusted, thumbprint_sha1, sha256, der, is_ca, is_self_signed, source_url, created_at"

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
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS crls (
			id          INTEGER PRIMARY KEY,
			issuer      TEXT    NOT NULL,
			url         TEXT    NOT NULL UNIQUE,
			der         BLOB   NOT NULL,
			this_update INTEGER NOT NULL,
			next_update INTEGER NOT NULL,
			created_at  INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_crls_url ON crls(url);

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
	for _, t := range derTables {
		s.db.Exec("ALTER TABLE " + t + " ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''")
		if err := s.backfillSHA256(t); err != nil {
			return fmt.Errorf("backfill %s.sha256: %w", t, err)
		}
	}
	if err := s.dropSerialUnique(); err != nil {
		return fmt.Errorf("certs: drop serial uniqueness: %w", err)
	}

	for _, stmt := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_sha256 ON certs(sha256)",
		"CREATE INDEX IF NOT EXISTS idx_crls_sha256 ON crls(sha256)",
		"CREATE INDEX IF NOT EXISTS idx_ocsp_responses_sha256 ON ocsp_responses(sha256)",
		"CREATE INDEX IF NOT EXISTS idx_certs_subject ON certs(subject)",
		"CREATE INDEX IF NOT EXISTS idx_certs_serial ON certs(serial)",
		"CREATE INDEX IF NOT EXISTS idx_certs_ski ON certs(ski)",
		"CREATE INDEX IF NOT EXISTS idx_certs_subject_name_der ON certs(subject_name_der)",
		"CREATE INDEX IF NOT EXISTS idx_certs_trusted ON certs(trusted)",
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

func (s *Store) backfillSHA256(table string) error {
	rows, err := s.db.Query("SELECT id FROM " + table + " WHERE sha256 = ''")
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
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

func (s *Store) FindCertBySKI(ski string) ([]byte, error) {
	if ski == "" {
		return nil, nil
	}
	var der []byte
	err := s.db.QueryRow(
		"SELECT der FROM certs WHERE ski = ? ORDER BY is_self_signed DESC LIMIT 1", ski,
	).Scan(&der)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return der, err
}

func (s *Store) FindCertByNameDER(subjectNameDER []byte) ([]byte, error) {
	if len(subjectNameDER) == 0 {
		return nil, nil
	}
	var der []byte
	err := s.db.QueryRow(
		"SELECT der FROM certs WHERE subject_name_der = ? ORDER BY is_self_signed DESC LIMIT 1", subjectNameDER,
	).Scan(&der)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return der, err
}

// FindAllCertsByNameDER returns up to limit certs with the subject, trusted first.
func (s *Store) FindAllCertsByNameDER(subjectNameDER []byte, limit int) ([][]byte, error) {
	if len(subjectNameDER) == 0 {
		return nil, nil
	}
	rows, err := s.db.Query(
		"SELECT der FROM certs WHERE subject_name_der = ? ORDER BY trusted DESC, id LIMIT ?",
		subjectNameDER, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result [][]byte
	for rows.Next() {
		var der []byte
		if err := rows.Scan(&der); err != nil {
			return nil, err
		}
		result = append(result, der)
	}
	return result, rows.Err()
}

func (s *Store) FindCertBySubject(subject string) ([]byte, error) {
	var der []byte
	err := s.db.QueryRow(
		"SELECT der FROM certs WHERE subject = ? ORDER BY is_self_signed DESC LIMIT 1", subject,
	).Scan(&der)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return der, err
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

func (s *Store) FindCertByThumbprint(sha1Hex string) ([]byte, error) {
	if sha1Hex == "" {
		return nil, nil
	}
	var der []byte
	err := s.db.QueryRow(
		"SELECT der FROM certs WHERE thumbprint_sha1 = ? LIMIT 1",
		strings.ToUpper(sha1Hex),
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
		"SELECT length(der) FROM crls WHERE url = ? AND next_update > ?",
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
		"SELECT der FROM crls WHERE url = ? AND next_update > ?",
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

// SaveCRL stores the CRL and drops expired ones.
func (s *Store) SaveCRL(issuer, url string, der []byte, thisUpdate, nextUpdate time.Time) error {
	if _, err := s.db.Exec("DELETE FROM crls WHERE next_update < ?", time.Now().Unix()); err != nil {
		return err
	}
	if url == "" {
		// Generate stable synthetic URL for uploaded CRLs (one per issuer+next_update)
		url = fmt.Sprintf("upload://%s|%d", issuer, nextUpdate.Unix())
	}
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO crls
			(issuer, url, sha256, der, this_update, next_update, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		issuer, url, SHA256Hex(der), der,
		thisUpdate.Unix(), nextUpdate.Unix(),
		time.Now().Unix(),
	)
	return err
}

// ImportTrustedCert trusts a bundled cert unless it was already imported from
// the same source; reports whether it was added or newly trusted.
func (s *Store) ImportTrustedCert(subject, issuer, serial, ski, aki string, subjectNameDER, der []byte, isCA, isSelfSigned bool, sourceURL string) (bool, error) {
	res, err := s.db.Exec(`
		INSERT INTO certs
			(subject, issuer, serial, ski, aki, subject_name_der, trusted, thumbprint_sha1, sha256, der,
			 is_ca, is_self_signed, source_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
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

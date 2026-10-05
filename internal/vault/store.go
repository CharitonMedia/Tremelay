package vault

import (
	"database/sql"
	"errors"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite; no cgo so Windows CI matches Linux.
)

const schemaSQL = `
CREATE TABLE vault (
  id TEXT PRIMARY KEY,
  format_version INTEGER NOT NULL,
  root TEXT NOT NULL,
  kdf_algorithm TEXT NOT NULL,
  kdf_salt BLOB NOT NULL,
  kdf_time INTEGER NOT NULL,
  kdf_memory INTEGER NOT NULL,
  kdf_threads INTEGER NOT NULL,
  kdf_key_len INTEGER NOT NULL,
  wrap_nonce BLOB NOT NULL,
  wrapped_dek BLOB NOT NULL,
  data_nonce BLOB NOT NULL,
  encrypted_document BLOB NOT NULL,
  audit_head TEXT NOT NULL,
  audit_seq INTEGER NOT NULL
);
CREATE TABLE audit (
  seq INTEGER PRIMARY KEY,
  time TEXT NOT NULL,
  action TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  credential_type TEXT NOT NULL,
  result TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  FOREIGN KEY (vault_id) REFERENCES vault(id)
);`

func sqliteDSN(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", ErrInvalid
	}
	slash := filepath.ToSlash(abs)
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	q := url.Values{}
	q.Set("mode", "rw")
	q.Set("_busy_timeout", "5000")
	q.Set("_defensive", "1")
	q.Set("_foreign_keys", "on")
	q.Set("_journal_mode", "DELETE")
	q.Set("_synchronous", "FULL")
	q.Set("_txlock", "immediate")
	return (&url.URL{Scheme: "file", Path: slash, RawQuery: q.Encode()}).String(), nil
}

func createDB(path string) (*sql.DB, error) {
	if path == "" {
		return nil, ErrInvalid
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrInvalid
		}
		return nil, ErrIO
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, ErrIO
	}
	db, err := openDB(path)
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		os.Remove(path)
		return nil, ErrIO
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		os.Remove(path)
		return nil, ErrIO
	}
	return db, nil
}

func openDB(path string) (*sql.DB, error) {
	if path == "" {
		return nil, ErrInvalid
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrInvalid
		}
		return nil, ErrIO
	}
	dsn, err := sqliteDSN(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, ErrIO
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, ErrCorrupt
	}
	if err := assertDurable(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func assertDurable(db *sql.DB) error {
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		return ErrCorrupt
	}
	if !strings.EqualFold(mode, "delete") {
		return ErrIO
	}
	var syncMode int
	if err := db.QueryRow(`PRAGMA synchronous`).Scan(&syncMode); err != nil {
		return ErrCorrupt
	}
	if syncMode != 2 {
		return ErrIO
	}
	var fk int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		return ErrCorrupt
	}
	if fk != 1 {
		return ErrIO
	}
	var check string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&check); err != nil || check != "ok" {
		return ErrCorrupt
	}
	return nil
}

func loadVault(path string) (*sql.DB, fileHeader, []auditEvent, error) {
	db, err := openDB(path)
	if err != nil {
		return nil, fileHeader{}, nil, err
	}
	header, err := readVaultRow(db)
	if err != nil {
		db.Close()
		return nil, fileHeader{}, nil, err
	}
	if err := validateHeader(header); err != nil {
		db.Close()
		return nil, fileHeader{}, nil, err
	}
	events, err := readAuditRows(db)
	if err != nil {
		db.Close()
		return nil, fileHeader{}, nil, err
	}
	if len(events) == 0 || verifyChain(events) != nil || suffixAllows(events, header) != nil {
		db.Close()
		return nil, fileHeader{}, nil, ErrAudit
	}
	return db, header, events, nil
}

func readVaultRow(db *sql.DB) (fileHeader, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vault`).Scan(&n); err != nil {
		return fileHeader{}, ErrCorrupt
	}
	if n != 1 {
		return fileHeader{}, ErrCorrupt
	}
	var h fileHeader
	var timeCost, memory, threads, keyLen, seq int64
	err := db.QueryRow(`SELECT id, format_version, root, kdf_algorithm, kdf_salt, kdf_time, kdf_memory, kdf_threads, kdf_key_len, wrap_nonce, wrapped_dek, data_nonce, encrypted_document, audit_head, audit_seq FROM vault`).Scan(
		&h.ID, &h.Version, &h.Root, &h.KDF.Algorithm, &h.KDF.Salt, &timeCost, &memory, &threads, &keyLen,
		&h.WrapNonce, &h.WrappedDEK, &h.DataNonce, &h.Data, &h.AuditHead, &seq,
	)
	if err != nil {
		return fileHeader{}, ErrCorrupt
	}
	if timeCost < 0 || timeCost > math.MaxUint32 || memory < 0 || memory > math.MaxUint32 || threads < 0 || threads > math.MaxUint8 || keyLen < 0 || keyLen > math.MaxUint32 || seq < 0 {
		return fileHeader{}, ErrCorrupt
	}
	h.KDF.Time = uint32(timeCost)
	h.KDF.Memory = uint32(memory)
	h.KDF.Threads = uint8(threads)
	h.KDF.KeyLen = uint32(keyLen)
	h.AuditSeq = uint64(seq)
	return h, nil
}

func readAuditRows(db *sql.DB) ([]auditEvent, error) {
	rows, err := db.Query(`SELECT seq, time, action, vault_id, credential_id, credential_type, result, prev_hash, hash FROM audit ORDER BY seq`)
	if err != nil {
		return nil, ErrCorrupt
	}
	defer rows.Close()
	var out []auditEvent
	var prev uint64
	for rows.Next() {
		var ev auditEvent
		var seq int64
		if err := rows.Scan(&seq, &ev.Time, &ev.Action, &ev.VaultID, &ev.CredID, &ev.CredType, &ev.Result, &ev.Prev, &ev.Hash); err != nil {
			return nil, ErrCorrupt
		}
		if seq <= 0 {
			return nil, ErrAudit
		}
		ev.V = auditVersion
		ev.Seq = uint64(seq)
		if prev != 0 && ev.Seq != prev+1 {
			return nil, ErrAudit
		}
		prev = ev.Seq
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, ErrCorrupt
	}
	return out, nil
}

// writeTx commits the encrypted vault row and one audit event together.
// fresh inserts the vault row; later calls update it. fault, when set, fails
// the transaction after both statements so tests can observe rollback.
func writeTx(db *sql.DB, h fileHeader, ev auditEvent, fresh bool, fault func() error) error {
	tx, err := db.Begin()
	if err != nil {
		return ErrIO
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if fresh {
		if err := insertVault(tx, h); err != nil {
			return err
		}
	} else if err := updateVault(tx, h); err != nil {
		return err
	}
	if err := insertAudit(tx, ev); err != nil {
		return err
	}
	if fault != nil {
		if err := fault(); err != nil {
			return ErrAudit
		}
	}
	if err := tx.Commit(); err != nil {
		return ErrIO
	}
	committed = true
	return nil
}

func insertVault(tx *sql.Tx, h fileHeader) error {
	_, err := tx.Exec(`INSERT INTO vault (
		id, format_version, root, kdf_algorithm, kdf_salt, kdf_time, kdf_memory, kdf_threads, kdf_key_len,
		wrap_nonce, wrapped_dek, data_nonce, encrypted_document, audit_head, audit_seq
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.Version, h.Root, h.KDF.Algorithm, h.KDF.Salt, h.KDF.Time, h.KDF.Memory, h.KDF.Threads, h.KDF.KeyLen,
		h.WrapNonce, h.WrappedDEK, h.DataNonce, h.Data, h.AuditHead, int64(h.AuditSeq),
	)
	if err != nil {
		return ErrIO
	}
	return nil
}

func updateVault(tx *sql.Tx, h fileHeader) error {
	res, err := tx.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=?, audit_head=?, audit_seq=? WHERE id=?`,
		h.DataNonce, h.Data, h.AuditHead, int64(h.AuditSeq), h.ID)
	if err != nil {
		return ErrIO
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return ErrCorrupt
	}
	return nil
}

func insertAudit(tx *sql.Tx, ev auditEvent) error {
	_, err := tx.Exec(`INSERT INTO audit (
		seq, time, action, vault_id, credential_id, credential_type, result, prev_hash, hash
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(ev.Seq), ev.Time, ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.Prev, ev.Hash)
	if err != nil {
		return ErrIO
	}
	return nil
}

// appendDenial records a locked-state unlock failure without the DEK.
// It does not update encrypted credential state. The next valid unlock
// checks this suffix and links the successful unlock after it.
func appendDenial(db *sql.DB, chain []auditEvent, vaultID string) error {
	ev, err := nextEvent(chain, actionUnlock, vaultID, "", "", resultDenied)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return ErrIO
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := insertAudit(tx, ev); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrIO
	}
	committed = true
	return nil
}

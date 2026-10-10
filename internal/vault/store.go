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
  agent_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  v INTEGER NOT NULL,
  class TEXT NOT NULL,
  ref_seq INTEGER NOT NULL,
  reasons TEXT NOT NULL DEFAULT '',
  cred_gen INTEGER NOT NULL DEFAULT 0,
  actor_id TEXT NOT NULL DEFAULT '',
  org_id TEXT NOT NULL DEFAULT '',
  target_id TEXT NOT NULL DEFAULT '',
  request_id TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL DEFAULT '',
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
	q.Set("_defensive", "1")
	q.Set("_txlock", "immediate")
	// modernc.org/sqlite runs each repeated _pragma value as one PRAGMA.
	// foreign_keys(ON) is the function-call form that driver accepts.
	for _, pragma := range []string{
		"busy_timeout(5000)",
		"foreign_keys(ON)",
		"journal_mode(DELETE)",
		"synchronous(FULL)",
	} {
		q.Add("_pragma", pragma)
	}
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
	return openSQLite(path, false)
}

func openDBRead(path string) (*sql.DB, error) {
	return openSQLite(path, true)
}

func openSQLite(path string, readonly bool) (*sql.DB, error) {
	if path == "" {
		return nil, ErrInvalid
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrInvalid
		}
		return nil, ErrIO
	}
	var dsn string
	var err error
	if readonly {
		dsn, err = sqliteReadDSN(path)
	} else {
		dsn, err = sqliteDSN(path)
	}
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

func sqliteReadDSN(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", ErrInvalid
	}
	slash := filepath.ToSlash(abs)
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Set("_defensive", "1")
	// No journal_mode or txlock setter. Those can write, and this connection
	// must not change the file. synchronous is read back by assertDurable.
	for _, pragma := range []string{
		"busy_timeout(5000)",
		"foreign_keys(ON)",
		"query_only(ON)",
	} {
		q.Add("_pragma", pragma)
	}
	return (&url.URL{Scheme: "file", Path: slash, RawQuery: q.Encode()}).String(), nil
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
	var busy int
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		return ErrCorrupt
	}
	if busy != 5000 {
		return ErrIO
	}
	var check string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&check); err != nil || check != "ok" {
		return ErrCorrupt
	}
	return nil
}

func loadVault(path string) (*sql.DB, fileHeader, []auditEvent, error) {
	return loadVaultMode(path, false)
}

func loadVaultRead(path string) (*sql.DB, fileHeader, []auditEvent, error) {
	return loadVaultMode(path, true)
}

func loadVaultMode(path string, readonly bool) (*sql.DB, fileHeader, []auditEvent, error) {
	var db *sql.DB
	var err error
	if readonly {
		db, err = openDBRead(path)
	} else {
		db, err = openDB(path)
	}
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
	// A read-only open must not migrate. M1–M5 files still unlock through
	// loadVault, which adds missing columns without rewriting hashes.
	if readonly {
		err = auditSchemaReady(db)
	} else {
		err = migrateAudit(db)
	}
	if err != nil {
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

func auditColumnSet(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info(audit)`)
	if err != nil {
		return nil, ErrCorrupt
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return nil, ErrCorrupt
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, ErrCorrupt
	}
	return cols, nil
}

func auditSchemaReady(db *sql.DB) error {
	cols, err := auditColumnSet(db)
	if err != nil {
		return err
	}
	for _, name := range []string{
		"seq", "time", "action", "vault_id", "credential_id", "credential_type", "result", "prev_hash", "hash",
		"agent_id", "grant_id", "operation", "v", "class", "ref_seq", "reasons", "cred_gen",
		"actor_id", "org_id", "target_id", "request_id", "decision",
	} {
		if !cols[name] {
			return ErrCorrupt
		}
	}
	return nil
}

// migrateAudit adds audit columns introduced after M1. Existing rows keep
// their hash preimage. v is derived from the action. class and ref_seq
// stay empty on rows that did not have those columns.
func migrateAudit(db *sql.DB) error {
	cols, err := auditColumnSet(db)
	if err != nil {
		return err
	}
	if len(cols) == 0 || !cols["seq"] || !cols["hash"] {
		return ErrCorrupt
	}
	type addCol struct {
		name string
		ddl  string
	}
	adds := []addCol{
		{"agent_id", `ALTER TABLE audit ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''`},
		{"grant_id", `ALTER TABLE audit ADD COLUMN grant_id TEXT NOT NULL DEFAULT ''`},
		{"operation", `ALTER TABLE audit ADD COLUMN operation TEXT NOT NULL DEFAULT ''`},
		{"v", `ALTER TABLE audit ADD COLUMN v INTEGER NOT NULL DEFAULT 1`},
		{"class", `ALTER TABLE audit ADD COLUMN class TEXT NOT NULL DEFAULT ''`},
		{"ref_seq", `ALTER TABLE audit ADD COLUMN ref_seq INTEGER NOT NULL DEFAULT 0`},
		{"reasons", `ALTER TABLE audit ADD COLUMN reasons TEXT NOT NULL DEFAULT ''`},
		{"cred_gen", `ALTER TABLE audit ADD COLUMN cred_gen INTEGER NOT NULL DEFAULT 0`},
		{"actor_id", `ALTER TABLE audit ADD COLUMN actor_id TEXT NOT NULL DEFAULT ''`},
		{"org_id", `ALTER TABLE audit ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`},
		{"target_id", `ALTER TABLE audit ADD COLUMN target_id TEXT NOT NULL DEFAULT ''`},
		{"request_id", `ALTER TABLE audit ADD COLUMN request_id TEXT NOT NULL DEFAULT ''`},
		{"decision", `ALTER TABLE audit ADD COLUMN decision TEXT NOT NULL DEFAULT ''`},
	}
	missing := false
	for _, col := range adds {
		if !cols[col.name] {
			missing = true
			break
		}
	}
	if !missing {
		return nil
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
	for _, col := range adds {
		if cols[col.name] {
			continue
		}
		if _, err := tx.Exec(col.ddl); err != nil {
			return ErrCorrupt
		}
	}
	if !cols["v"] {
		if err := backfillAuditVersion(tx); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return ErrIO
	}
	committed = true
	return nil
}

func backfillAuditVersion(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT seq, action FROM audit`)
	if err != nil {
		return ErrCorrupt
	}
	type versioned struct {
		seq int64
		v   int
	}
	var updates []versioned
	for rows.Next() {
		var seq int64
		var action string
		if err := rows.Scan(&seq, &action); err != nil {
			rows.Close()
			return ErrCorrupt
		}
		updates = append(updates, versioned{seq: seq, v: auditVersionFor(action)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ErrCorrupt
	}
	if err := rows.Close(); err != nil {
		return ErrCorrupt
	}
	for _, row := range updates {
		if _, err := tx.Exec(`UPDATE audit SET v=? WHERE seq=?`, row.v, row.seq); err != nil {
			return ErrCorrupt
		}
	}
	return nil
}

func readAuditRows(db *sql.DB) ([]auditEvent, error) {
	rows, err := db.Query(`SELECT seq, time, action, vault_id, credential_id, credential_type, result, prev_hash, hash, agent_id, grant_id, operation, v, class, ref_seq, reasons, cred_gen, actor_id, org_id, target_id, request_id, decision FROM audit ORDER BY seq`)
	if err != nil {
		return nil, ErrCorrupt
	}
	defer rows.Close()
	var out []auditEvent
	var prev uint64
	for rows.Next() {
		var ev auditEvent
		var seq, ref, gen int64
		if err := rows.Scan(&seq, &ev.Time, &ev.Action, &ev.VaultID, &ev.CredID, &ev.CredType, &ev.Result, &ev.Prev, &ev.Hash, &ev.AgentID, &ev.GrantID, &ev.Operation, &ev.V, &ev.Class, &ref, &ev.Reasons, &gen, &ev.ActorID, &ev.OrgID, &ev.TargetID, &ev.RequestID, &ev.Decision); err != nil {
			return nil, ErrCorrupt
		}
		if seq <= 0 || ref < 0 || gen < 0 || !knownAuditVersion(ev.V) {
			return nil, ErrAudit
		}
		ev.Seq = uint64(seq)
		ev.RefSeq = uint64(ref)
		ev.CredGen = uint64(gen)
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

// writeTx commits the encrypted vault row and the audit events together.
// fresh inserts the vault row; later calls update it. fault, when set, fails
// the transaction after the statements so tests can observe rollback.
// A failure rolls every event in the call back; callers put a security
// event, its response decision, and its containment row in one call.
func writeTx(db *sql.DB, h fileHeader, prevSeq uint64, events []auditEvent, fresh bool, fault func() error) error {
	if len(events) == 0 {
		return ErrAudit
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
	if fresh {
		if err := insertVault(tx, h); err != nil {
			return err
		}
	} else if err := updateVault(tx, h, prevSeq); err != nil {
		return err
	}
	for _, ev := range events {
		if err := insertAudit(tx, ev); err != nil {
			return err
		}
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

func updateVault(tx *sql.Tx, h fileHeader, prevSeq uint64) error {
	res, err := tx.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=?, audit_head=?, audit_seq=? WHERE id=? AND audit_seq=?`,
		h.DataNonce, h.Data, h.AuditHead, int64(h.AuditSeq), h.ID, int64(prevSeq))
	if err != nil {
		return ErrIO
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ErrCorrupt
	}
	if n != 1 {
		// A compare-and-swap miss, including a trigger that ignores the
		// update, leaves the previous document in place.
		return ErrCorrupt
	}
	return nil
}

func insertAudit(tx *sql.Tx, ev auditEvent) error {
	_, err := tx.Exec(`INSERT INTO audit (
		seq, time, action, vault_id, credential_id, credential_type, result, prev_hash, hash, agent_id, grant_id, operation, v, class, ref_seq, reasons, cred_gen,
		actor_id, org_id, target_id, request_id, decision
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(ev.Seq), ev.Time, ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.Prev, ev.Hash, ev.AgentID, ev.GrantID, ev.Operation, ev.V, ev.Class, int64(ev.RefSeq), ev.Reasons, int64(ev.CredGen),
		ev.ActorID, ev.OrgID, ev.TargetID, ev.RequestID, ev.Decision)
	if err != nil {
		return ErrIO
	}
	return nil
}

// appendDenial records a locked-state unlock failure without the DEK.
// It does not update encrypted credential state. The next valid unlock
// checks this suffix and links the successful unlock after it.
//
// The sequence is allocated inside the write transaction. The DSN starts
// that transaction with BEGIN IMMEDIATE, so the reserved lock covers the
// tip read and the insert. A concurrent denial waits, then observes the
// committed sequence instead of reusing it.
func appendDenial(db *sql.DB, vaultID string) error {
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
	tip, err := readAuditTip(tx)
	if err != nil {
		return err
	}
	if tip.VaultID != vaultID {
		return ErrAudit
	}
	ev, err := nextEvent([]auditEvent{tip}, actionUnlock, vaultID, "", "", resultDenied)
	if err != nil {
		return err
	}
	if err := insertAudit(tx, ev); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrIO
	}
	committed = true
	return nil
}

func readAuditTip(tx *sql.Tx) (auditEvent, error) {
	var ev auditEvent
	var seq, ref, gen int64
	err := tx.QueryRow(`SELECT seq, time, action, vault_id, credential_id, credential_type, result, prev_hash, hash, agent_id, grant_id, operation, v, class, ref_seq, reasons, cred_gen, actor_id, org_id, target_id, request_id, decision FROM audit ORDER BY seq DESC LIMIT 1`).Scan(
		&seq, &ev.Time, &ev.Action, &ev.VaultID, &ev.CredID, &ev.CredType, &ev.Result, &ev.Prev, &ev.Hash, &ev.AgentID, &ev.GrantID, &ev.Operation, &ev.V, &ev.Class, &ref, &ev.Reasons, &gen, &ev.ActorID, &ev.OrgID, &ev.TargetID, &ev.RequestID, &ev.Decision,
	)
	if err != nil || seq <= 0 || ref < 0 || gen < 0 || ev.V != auditVersionFor(ev.Action) {
		return auditEvent{}, ErrAudit
	}
	ev.Seq = uint64(seq)
	ev.RefSeq = uint64(ref)
	ev.CredGen = uint64(gen)
	return ev, nil
}

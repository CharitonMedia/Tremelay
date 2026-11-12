package vault

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ErrArchiveEmpty means the vault holds no more rows than the caller asked to
// keep, or that no row can leave without stranding a notice row's source.
var ErrArchiveEmpty = errors.New("no audit rows to archive")

// ErrArchiveIncomplete means the archive files given to a verification are
// this vault's rows but do not start at row 1: an older file is missing, or
// the front of one was removed.
var ErrArchiveIncomplete = errors.New("archive files do not reach back to row 1")

// ErrArchiveKept wraps the error of an archive call that failed and left its
// file in place, because the call could not show that the vault still holds
// the rows on it.
var ErrArchiveKept = errors.New("the archive file was written and left in place: it may be the only copy of those rows; see docs/vault-lifecycle.md before deleting it")

// archiveRetries bounds how often one archive call adopts a competing commit
// and tries again. The window is longer than an ordinary command's, because
// the file is written inside it.
const archiveRetries = 4

// AuditArchive describes the rows one archive call moved to its file.
type AuditArchive struct {
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
	LastHash string `json:"last_hash"`
	Rows     int    `json:"rows"`
	Kept     int    `json:"kept"`
}

// ArchiveAudit moves the oldest audit rows out of the vault into a new file at
// outPath and keeps at least the newest keep rows. See ADR 0029.
//
// The chain is not restarted. The rows that stay keep their sequence numbers
// and hashes, and the first of them still names the hash of the last archived
// row. That row's sequence and hash are sealed in the encrypted document in
// the same transaction that deletes the archived rows, so the cut can be made
// only with the DEK and is checked on every unlock, reload and verify.
//
// The file is written, flushed and read back before anything is deleted. It
// is one JSON row per line, exactly as stored, and VerifyArchive checks it
// without the vault. outPath must not exist and must not contain a symlink.
// When the call fails the file is removed if the rows are still in the vault,
// and left only when that cannot be established.
//
// Detection counts, pending notices and suspension facts are derived from the
// rows the vault holds, so after this call they reflect the rows that stay.
// A session in another process whose last verified row was archived cannot
// tell this cut from a rollback; it retires itself, and a daemon locks.
func (s *Session) ArchiveAudit(outPath string, keep int) (AuditArchive, error) {
	if err := s.begin(); err != nil {
		return AuditArchive{}, err
	}
	defer s.end()
	if err := s.live(); err != nil {
		return AuditArchive{}, err
	}
	if err := s.verified(); err != nil {
		return AuditArchive{}, err
	}
	refuse := func(cause error) (AuditArchive, error) {
		if err := s.persistEvent(actionArchive, "", "", resultDenied); err != nil {
			return AuditArchive{}, err
		}
		s.logf("audit_archive result=denied")
		return AuditArchive{}, cause
	}
	if keep < 0 {
		return refuse(ErrInvalid)
	}
	n := archiveCut(s.audit, keep)
	if n == 0 {
		return refuse(ErrArchiveEmpty)
	}
	out, err := cleanPath(outPath, true)
	if err != nil {
		return refuse(err)
	}
	if s.besideVault(out) {
		return refuse(ErrInvalid)
	}
	rows := s.audit[:n]
	info := AuditArchive{FirstSeq: rows[0].Seq, LastSeq: rows[n-1].Seq, LastHash: rows[n-1].Hash, Rows: n}
	cut := &auditBase{Seq: info.LastSeq, Hash: info.LastHash}
	events, err := s.archiveRows(*cut)
	if err != nil {
		return AuditArchive{}, err
	}
	if err := writeArchive(out, rows); err != nil {
		return refuse(err)
	}
	kept := func(err error) (AuditArchive, error) {
		return AuditArchive{}, fmt.Errorf("%w; %w", err, ErrArchiveKept)
	}
	for try := 0; ; try++ {
		if s.archiveAttempt != nil {
			s.archiveAttempt()
		}
		tip := s.audit[len(s.audit)-1].Seq
		mine := events[len(events)-1]
		err = s.commitBatchWrap(events, s.creds, s.agents, s.grants, false, nil, nil, nil, cut)
		if err == nil {
			break
		}
		// The error does not say which side of the commit the vault is on,
		// and the file's fate depends on exactly that. Bring the session up
		// to what is stored, then account for every row on file.
		aerr := s.adoptLocked()
		if aerr == nil {
			// The adopted chain still holds the row this session last
			// verified, and this call's archive row would come after that
			// one. It is in the chain exactly when this transaction
			// committed.
			if got, ok := rowAt(s.audit, mine.Seq); ok && got.Hash == mine.Hash {
				// Durable; only a step after the commit failed. The file is
				// the archive of its rows, whatever was cut after it.
				break
			}
		}
		cause := aerr
		if cause == nil {
			cause = err
		}
		// Rows at or before the base this session holds left in a cut made
		// with the DEK, so an archive file has them. They are the rows on
		// file: a base that moved was adopted with a chain that still holds
		// the row this session last verified, and that row's hash covers
		// every row before it. Every later row must still be in the audit
		// table, exactly as it is on file. Otherwise this file may be the
		// only copy of a row, and it stays.
		live := rows
		if s.base != nil && s.base.Seq >= info.FirstSeq {
			live = rows[min(int(s.base.Seq-info.FirstSeq)+1, len(rows)):]
		}
		if !s.tableHolds(live) {
			return kept(cause)
		}
		// The file is a spare. If another writer got in first, a commit or an
		// unlock denial behind the head, cut at the same row again: the rows
		// on file are history it could not change. That holds only while the
		// chain still starts where the file does. After a smaller archive by
		// someone else, cutting here would leave a file that overlaps theirs
		// and reports rows this call did not remove.
		moved := aerr == nil && s.audit[len(s.audit)-1].Seq != tip
		if moved && try < archiveRetries && len(live) == len(rows) && cutHolds(s.audit, *cut) {
			next, rerr := s.archiveRows(*cut)
			if rerr != nil {
				_ = os.Remove(out)
				return AuditArchive{}, rerr
			}
			events = next
			continue
		}
		_ = os.Remove(out)
		switch {
		case aerr != nil:
			return AuditArchive{}, aerr
		case moved:
			// A lost race, whatever the failed write called it.
			return AuditArchive{}, ErrStale
		}
		return AuditArchive{}, err
	}
	info.Kept = len(s.audit)
	s.logf("audit_archive result=allowed")
	return info, nil
}

// besideVault reports whether path names the vault's rollback journal, WAL or
// shared-memory file. SQLite creates and deletes those when it likes: an
// archive written under one of those names would be removed after the rows it
// holds had left the vault. The directory is compared as a file and the name
// without regard to case, so another spelling of the same name does not pass.
func (s *Session) besideVault(path string) bool {
	vault, err := filepath.Abs(s.path)
	if err != nil {
		return true
	}
	there, err := os.Stat(filepath.Dir(vault))
	if err != nil {
		return true
	}
	here, err := os.Stat(filepath.Dir(path))
	if err != nil || !os.SameFile(here, there) {
		// Another directory, or none: the write fails by itself.
		return false
	}
	for _, side := range sqliteSidecars(filepath.Base(vault)) {
		if strings.EqualFold(filepath.Base(path), side) {
			return true
		}
	}
	return false
}

// tableHolds reports whether every one of rows is in the audit table exactly
// as given. It reads the table, not the session's copy of it: rows deleted or
// changed by hand do not move the vault's head, and the copy would not show
// them.
//
// ponytail: reads the whole table once per failed attempt. A range query if
// failures on a very large vault get slow.
func (s *Session) tableHolds(rows []auditEvent) bool {
	if len(rows) == 0 {
		return true
	}
	stored, err := readAuditRows(s.db)
	if err != nil {
		return false
	}
	i := 0
	for _, ev := range stored {
		if i < len(rows) && ev == rows[i] {
			i++
		}
	}
	return i == len(rows)
}

// archiveCut returns how many rows from the front may leave: all but the
// newest keep, fewer when a row that stays is a notice about a row that would
// go. A notice row is verified against its source, so the two stay together.
// The newest row never leaves; the chain needs a row for the head to sit on.
func archiveCut(events []auditEvent, keep int) int {
	if keep < 1 {
		keep = 1
	}
	n := len(events) - keep
	if n <= 0 {
		return 0
	}
	first := events[0].Seq
	// One pass from the newest row down. Lowering n brings older rows into
	// the pass, and their sources are checked in turn.
	for i := len(events) - 1; i >= n; i-- {
		ev := events[i]
		if !noticeAction(ev.Action) || ev.RefSeq < first {
			continue
		}
		if src := int(ev.RefSeq - first); src < n {
			n = src
		}
	}
	return n
}

// cutHolds reports whether cut is still a row of this chain with rows after
// it, none of them a notice about a row at or before it.
func cutHolds(events []auditEvent, cut auditBase) bool {
	last, ok := rowAt(events, cut.Seq)
	if !ok || last.Hash != cut.Hash {
		return false
	}
	n := int(cut.Seq-events[0].Seq) + 1
	return n < len(events) && archiveCut(events, len(events)-n) == n
}

// archiveRows builds the rows an archive appends: the archive row itself and,
// before it, one row for each credential whose latest health row is about to
// leave. matchHealth binds a credential's stored assessment to that row, and
// it must stay in the vault to be checked. The row restates the stored
// generation and findings as health_refresh/unchanged. Nothing is reassessed.
func (s *Session) archiveRows(cut auditBase) ([]auditEvent, error) {
	latest := map[string]uint64{}
	for _, ev := range s.audit {
		if (ev.Action == actionHealth || ev.Action == actionRefresh) && ev.CredID != "" && (ev.Result == resultAllowed || ev.Result == resultUnchanged) {
			latest[ev.CredID] = ev.Seq
		}
	}
	chain := s.audit[len(s.audit)-1:]
	var out []auditEvent
	add := func(partial auditEvent) error {
		ev, err := nextAudit(chain, s.id, partial)
		if err != nil {
			return err
		}
		out = append(out, ev)
		chain = out[len(out)-1:]
		return nil
	}
	for _, c := range s.creds {
		seq, ok := latest[c.ID]
		if !ok || seq > cut.Seq {
			continue
		}
		if c.Health == nil {
			return nil, ErrCorrupt
		}
		if err := add(auditEvent{Action: actionRefresh, Result: resultUnchanged, CredID: c.ID, CredType: c.Type, Reasons: joinReasons(c.Health.Findings), CredGen: c.Gen}); err != nil {
			return nil, err
		}
	}
	if err := add(auditEvent{Action: actionArchive, Result: resultAllowed}); err != nil {
		return nil, err
	}
	return out, nil
}

// writeArchive creates path, owner-only, and writes rows to it one JSON
// object per line. It returns only after the file is flushed and reads back
// as the same rows: the vault's copy is deleted on the strength of this one.
func writeArchive(path string, rows []auditEvent) (err error) {
	f, err := openExclusiveOwnerOnly(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrInvalid
		}
		return ErrIO
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, ev := range rows {
		if enc.Encode(ev) != nil {
			return ErrIO
		}
	}
	if w.Flush() != nil || f.Sync() != nil || f.Close() != nil {
		return ErrIO
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return err
	}
	got, err := readArchive(path)
	if err != nil {
		return ErrIO
	}
	if !slices.Equal(got, rows) {
		return ErrIO
	}
	return nil
}

// readArchive decodes an archive file strictly: one row per line, each line
// byte for byte what this package writes for that row. encoding/json matches
// member names without regard to case and lets a repeated name win, so a line
// could otherwise carry one value for the hash check and show a reader
// another. It does not verify the chain.
func readArchive(path string) ([]auditEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrIO
	}
	defer f.Close()
	var out []auditEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	for sc.Scan() {
		var ev auditEvent
		if err := unmarshalStrict(sc.Bytes(), &ev); err != nil {
			return nil, ErrAudit
		}
		if canon, err := json.Marshal(ev); err != nil || !bytes.Equal(canon, sc.Bytes()) {
			return nil, ErrAudit
		}
		out = append(out, ev)
	}
	if sc.Err() != nil {
		return nil, ErrAudit
	}
	return out, nil
}

// VerifyArchive checks archive files without a vault or a passphrase. Each
// file must be a linked run of audit rows, and the files must follow one
// another in the order given: the first row of each names the last hash of
// the one before. A run that starts at row 1 must start with the vault's
// creation. The result describes the whole run. Whether its last row is the
// one a vault's chain now follows is VerifyAudit's question, which needs the
// passphrase.
func VerifyArchive(paths ...string) (AuditArchive, error) {
	info, _, err := verifyArchive(paths)
	return info, err
}

func verifyArchive(paths []string) (AuditArchive, string, error) {
	var all []auditEvent
	for _, p := range paths {
		abs, err := cleanPath(p, false)
		if err != nil {
			return AuditArchive{}, "", err
		}
		rows, err := readArchive(abs)
		if err != nil {
			return AuditArchive{}, "", err
		}
		if len(rows) == 0 {
			return AuditArchive{}, "", ErrAudit
		}
		all = append(all, rows...)
	}
	// verifyLinked requires contiguous sequences and each row's prev to be
	// the hash before it, so files out of order or from another vault fail.
	if len(all) == 0 || verifyChain(all) != nil {
		return AuditArchive{}, "", ErrAudit
	}
	last := all[len(all)-1]
	return AuditArchive{FirstSeq: all[0].Seq, LastSeq: last.Seq, LastHash: last.Hash, Rows: len(all)}, last.VaultID, nil
}

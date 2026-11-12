package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// archiveEnv is a broker vault with a weak password stored early, so its
// health row is among the oldest, and enough ordinary rows to cut.
type archiveEnv struct {
	brokerEnv
	dir  string
	pwID string
}

func newArchiveEnv(t *testing.T, rows int) archiveEnv {
	t.Helper()
	e := newBrokerEnv(t)
	pw, err := e.session.Put("login", "password", []byte("abc12345"), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for range rows {
		if _, err := e.session.List(); err != nil {
			t.Fatal(err)
		}
	}
	return archiveEnv{brokerEnv: e, dir: canonicalExisting(t, t.TempDir()), pwID: pw.ID}
}

func (e archiveEnv) out(name string) string { return filepath.Join(e.dir, name) }

func mustArchive(t *testing.T, s *Session, out string, keep int) AuditArchive {
	t.Helper()
	info, err := s.ArchiveAudit(out, keep)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func archiveActions(events []auditEvent, action, result string) int {
	n := 0
	for _, ev := range events {
		if ev.Action == action && ev.Result == result {
			n++
		}
	}
	return n
}

// The acceptance path: old rows leave for a file, the vault keeps working
// under the same chain, and everything that verified before still verifies.
func TestArchiveMovesOldRowsAndTheVaultStillVerifies(t *testing.T) {
	e := newArchiveEnv(t, 30)
	healthBefore := mustHealth(t, e.session, e.pwID)
	before := append([]auditEvent(nil), e.session.audit...)
	out := e.out("audit-1.jsonl")
	info := mustArchive(t, e.session, out, 5)

	if info.FirstSeq != 1 || info.Rows != len(before)-5 || info.LastSeq != uint64(info.Rows) || info.LastHash != before[info.Rows-1].Hash {
		t.Fatalf("archive %+v of %d rows", info, len(before))
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(out)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("archive file mode %v %v", fi, err)
		}
	}
	onFile, err := readArchive(out)
	if err != nil || len(onFile) != info.Rows {
		t.Fatalf("file holds %d rows, %v", len(onFile), err)
	}
	for i, ev := range onFile {
		if ev != before[i] {
			t.Fatalf("row %d on file differs from the row the vault held", ev.Seq)
		}
	}
	if got, err := VerifyArchive(out); err != nil || got.FirstSeq != 1 || got.LastSeq != info.LastSeq || got.LastHash != info.LastHash {
		t.Fatalf("VerifyArchive %+v %v", got, err)
	}

	// The vault holds the kept rows, the restated health rows and the archive
	// row, numbered as before, and nothing else.
	stored := mustAudit(t, e.path)
	if stored[0].Seq != info.LastSeq+1 || stored[0].Prev != info.LastHash || len(stored) != info.Kept {
		t.Fatalf("vault starts at %d with %d rows, want %d and %d", stored[0].Seq, len(stored), info.LastSeq+1, info.Kept)
	}
	for i := range 5 {
		if stored[i] != before[info.Rows+i] {
			t.Fatalf("kept row %d changed", stored[i].Seq)
		}
	}
	if archiveActions(stored, actionArchive, resultAllowed) != 1 || stored[len(stored)-1].Action != actionArchive {
		t.Fatal("the archive is not the last audited row")
	}
	if e.session.base == nil || e.session.base.Seq != info.LastSeq || len(e.session.audit) != len(stored) {
		t.Fatalf("session base %+v, %d rows cached", e.session.base, len(e.session.audit))
	}

	// The session that archived keeps serving.
	if _, err := e.session.List(); err != nil {
		t.Fatal(err)
	}
	if rows, err := e.session.AuditHistory(AuditFilter{}); err != nil || rows[0].Seq != info.LastSeq+1 {
		t.Fatalf("history after archive: %v", err)
	}
	if _, err := e.session.AuditBySeq(info.LastSeq, ""); !errors.Is(err, ErrAuditNotFound) {
		t.Fatalf("an archived row is still served: %v", err)
	}
	if rec, err := e.session.AuditBySeq(info.LastSeq+1, ""); err != nil || rec.Hash != stored[0].Hash {
		t.Fatalf("first kept row: %v", err)
	}
	e.session.Lock()

	// A fresh unlock, a verify, and a verify against the file all pass, and
	// the credential and its assessment are what they were.
	opened := mustUnlock(t, e.path, e.pass)
	got, err := opened.Get(e.apiID)
	if err != nil || string(got.Secret) != string(e.secret) {
		t.Fatalf("credential after archive: %v", err)
	}
	if h := mustHealth(t, opened, e.pwID); !h.AssessedAt.Equal(healthBefore.AssessedAt) || strings.Join(h.Findings, ",") != strings.Join(healthBefore.Findings, ",") {
		t.Fatalf("assessment changed: %+v, was %+v", h, healthBefore)
	}
	opened.Lock()
	tip, err := VerifyAudit(e.path, e.pass)
	if err != nil {
		t.Fatal(err)
	}
	if tip2, cover, err := VerifyAuditArchive(e.path, e.pass, out); err != nil || tip2 != tip || cover.FirstSeq != 1 || cover.LastSeq != info.LastSeq {
		t.Fatalf("VerifyAuditArchive %+v %v", cover, err)
	}
}

// A credential assessed long ago has its latest health row in the part that
// leaves. The archive restates it, so the strict binding still has a row.
func TestArchiveRestatesHealthThatWouldLeave(t *testing.T) {
	e := newArchiveEnv(t, 20)
	want := mustHealth(t, e.session, e.pwID)
	if len(want.Findings) == 0 {
		t.Fatal("the fixture password has no finding to carry")
	}
	oldSeq := healthSeq(t, e.session, e.pwID)
	info := mustArchive(t, e.session, e.out("a.jsonl"), 3)
	if oldSeq > info.LastSeq {
		t.Fatalf("health row %d was not archived (cut %d)", oldSeq, info.LastSeq)
	}
	var restated []auditEvent
	for _, ev := range e.session.audit {
		if ev.Action == actionRefresh && ev.CredID == e.pwID {
			restated = append(restated, ev)
		}
	}
	if len(restated) != 1 || restated[0].Result != resultUnchanged || restated[0].Reasons != joinReasons(want.Findings) || restated[0].CredGen == 0 {
		t.Fatalf("restated rows %+v", restated)
	}
	if err := matchHealth(e.session.audit, e.session.creds); err != nil {
		t.Fatal(err)
	}
	// A second archive right away has nothing old left to restate for it.
	for range 10 {
		if _, err := e.session.List(); err != nil {
			t.Fatal(err)
		}
	}
	second := mustArchive(t, e.session, e.out("b.jsonl"), 3)
	if second.FirstSeq != info.LastSeq+1 {
		t.Fatalf("second archive starts at %d, want %d", second.FirstSeq, info.LastSeq+1)
	}
	e.session.Lock()
	mustUnlock(t, e.path, e.pass).Lock()
}

// Two archives are two runs of one chain: in order they verify back to row 1,
// out of order or with one missing from the end they do not.
func TestSecondArchiveContinuesTheFirst(t *testing.T) {
	e := newArchiveEnv(t, 20)
	a, b := e.out("a.jsonl"), e.out("b.jsonl")
	first := mustArchive(t, e.session, a, 4)
	for range 15 {
		if _, err := e.session.List(); err != nil {
			t.Fatal(err)
		}
	}
	second := mustArchive(t, e.session, b, 4)
	e.session.Lock()

	if got, err := VerifyArchive(a, b); err != nil || got.FirstSeq != 1 || got.LastSeq != second.LastSeq || got.Rows != first.Rows+second.Rows {
		t.Fatalf("both files: %+v %v", got, err)
	}
	if _, err := VerifyArchive(b, a); !errors.Is(err, ErrAudit) {
		t.Fatalf("files out of order verified: %v", err)
	}
	if _, _, err := VerifyAuditArchive(e.path, e.pass, a, b); err != nil {
		t.Fatal(err)
	}
	// The newest file alone ends where the vault begins and is this vault's,
	// but the history before it is not shown.
	if _, _, err := VerifyAuditArchive(e.path, e.pass, b); !errors.Is(err, ErrArchiveIncomplete) {
		t.Fatalf("the newest file alone: %v", err)
	}
	if got, err := VerifyArchive(b); err != nil || got.FirstSeq != first.LastSeq+1 {
		t.Fatalf("the newest file as a run: %+v %v", got, err)
	}
	if _, _, err := VerifyAuditArchive(e.path, e.pass, a); !errors.Is(err, ErrAudit) {
		t.Fatalf("a file that stops short of the vault's base verified: %v", err)
	}
}

// A notice row is verified against its source, so a late delivery pins the cut
// in front of the row it is about.
func TestArchiveKeepsANoticeWithItsSource(t *testing.T) {
	// No weak password here: its health alert would be a second, older
	// pending source.
	e := archiveEnv{brokerEnv: newBrokerEnv(t)}
	e.dir = canonicalExisting(t, t.TempDir())
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://other.example/v1/ping"}, ErrDeniedOrigin)
	var source uint64
	for _, ev := range e.session.audit {
		if ev.Action == actionBroker && ev.Result == resultDeniedOrigin {
			source = ev.Seq
		}
	}
	for range 20 {
		if _, err := e.session.List(); err != nil {
			t.Fatal(err)
		}
	}
	sink := &MemoryNotifier{}
	if err := e.session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if err := e.session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 1 {
		t.Fatal("the late delivery did not happen")
	}
	info := mustArchive(t, e.session, e.out("a.jsonl"), 2)
	if info.LastSeq != source-1 {
		t.Fatalf("cut at %d, want just before the source at %d", info.LastSeq, source)
	}
	e.session.Lock()
	mustUnlock(t, e.path, e.pass).Lock()
}

func TestArchiveCut(t *testing.T) {
	chain := func(n int, notices map[int]int) []auditEvent {
		out := make([]auditEvent, n)
		for i := range out {
			out[i] = auditEvent{Seq: uint64(100 + i), Action: actionList}
			if src, ok := notices[i]; ok {
				out[i].Action, out[i].RefSeq = actionNotify, uint64(100+src)
			}
		}
		return out
	}
	for _, tc := range []struct {
		name    string
		n, keep int
		notices map[int]int
		want    int
	}{
		{"plain", 10, 3, nil, 7},
		{"keep everything", 10, 10, nil, 0},
		{"keep more than there is", 10, 50, nil, 0},
		{"keep zero still keeps the newest row", 10, 0, nil, 9},
		{"notice inside the kept part", 10, 3, map[int]int{9: 8}, 7},
		{"notice pulls the cut back", 10, 3, map[int]int{9: 4}, 4},
		{"pulled back onto another notice", 10, 3, map[int]int{9: 5, 6: 2}, 2},
		{"notice about the first row", 10, 3, map[int]int{8: 0}, 0},
		{"archived notice does not pin", 10, 3, map[int]int{5: 1}, 7},
		{"one row", 1, 0, nil, 0},
	} {
		events := chain(tc.n, tc.notices)
		if got := archiveCut(events, tc.keep); got != tc.want {
			t.Errorf("%s: cut %d, want %d", tc.name, got, tc.want)
		}
		if tc.want > 0 {
			cut := auditBase{Seq: events[tc.want-1].Seq, Hash: events[tc.want-1].Hash}
			if !cutHolds(events, cut) {
				t.Errorf("%s: its own cut does not hold", tc.name)
			}
		}
	}
	events := chain(10, map[int]int{9: 4})
	if cutHolds(events, auditBase{Seq: 105}) {
		t.Error("a cut behind a noticed source holds")
	}
	if cutHolds(events, auditBase{Seq: 109}) || cutHolds(events, auditBase{Seq: 99}) || cutHolds(events, auditBase{Seq: 103, Hash: "x"}) {
		t.Error("a cut at the tip, off the chain, or with another hash holds")
	}
}

// What is refused is audited, and leaves the vault and any existing file alone.
func TestArchiveRefusals(t *testing.T) {
	e := newArchiveEnv(t, 5)
	rows := len(e.session.audit)
	if _, err := e.session.ArchiveAudit(e.out("a.jsonl"), rows); !errors.Is(err, ErrArchiveEmpty) {
		t.Fatalf("nothing to archive: %v", err)
	}
	if _, err := e.session.ArchiveAudit(e.out("a.jsonl"), -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative keep: %v", err)
	}
	existing := e.out("taken.jsonl")
	if err := os.WriteFile(existing, []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.session.ArchiveAudit(existing, 2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("existing file: %v", err)
	}
	if got, err := os.ReadFile(existing); err != nil || string(got) != "mine\n" {
		t.Fatalf("existing file was touched: %q %v", got, err)
	}
	link := e.out("link.jsonl")
	if err := os.Symlink(e.out("elsewhere.jsonl"), link); err == nil {
		if _, err := e.session.ArchiveAudit(link, 2); !errors.Is(err, ErrInvalid) {
			t.Fatalf("symlink target: %v", err)
		}
	}
	// SQLite deletes its journal and WAL when it likes. An archive under one
	// of those names would vanish after its rows had left the vault.
	for _, side := range []string{"-journal", "-wal", "-shm", "-JOURNAL"} {
		name := canonicalExisting(t, e.path) + side
		if _, err := e.session.ArchiveAudit(name, 2); !errors.Is(err, ErrInvalid) {
			t.Fatalf("archive onto the vault's own %s file: %v", side, err)
		}
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the refused archive created %s", name)
		}
	}
	if _, err := os.Stat(e.out("a.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused archive left a file")
	}
	if e.session.base != nil || e.session.audit[0].Seq != 1 || len(e.session.audit) < rows {
		t.Fatal("a refused archive cut the chain")
	}
	if got := archiveActions(e.session.audit, actionArchive, resultDenied); got < 7 {
		t.Fatalf("%d refusals audited, want at least 7", got)
	}
	// The same file name in another directory is an ordinary file.
	mustArchive(t, e.session, e.out(filepath.Base(e.path)+"-journal"), 2)
	e.session.Lock()
	if _, err := VerifyAudit(e.path, e.pass); err != nil {
		t.Fatal(err)
	}
}

// Without the DEK the front of the chain cannot be moved in either direction,
// before or after an archive.
func TestArchiveCutIsTamperEvident(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, e archiveEnv, info AuditArchive, out string){
		"one more row removed": func(t *testing.T, e archiveEnv, info AuditArchive, _ string) {
			execArchiveSQL(t, e.path, `DELETE FROM audit WHERE seq=?`, int64(info.LastSeq+1))
		},
		"many more rows removed": func(t *testing.T, e archiveEnv, info AuditArchive, _ string) {
			execArchiveSQL(t, e.path, `DELETE FROM audit WHERE seq<=?`, int64(info.LastSeq+3))
		},
		"archived rows put back": func(t *testing.T, e archiveEnv, _ AuditArchive, out string) {
			rows, err := readArchive(out)
			if err != nil {
				t.Fatal(err)
			}
			db := mustOpen(t, e.path)
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			for _, ev := range rows {
				if err := insertAudit(tx, ev); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		},
		"last archived row put back": func(t *testing.T, e archiveEnv, _ AuditArchive, out string) {
			rows, err := readArchive(out)
			if err != nil {
				t.Fatal(err)
			}
			db := mustOpen(t, e.path)
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if err := insertAudit(tx, rows[len(rows)-1]); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newArchiveEnv(t, 20)
			out := e.out("a.jsonl")
			info := mustArchive(t, e.session, out, 8)
			e.session.Lock()
			if _, err := VerifyAudit(e.path, e.pass); err != nil {
				t.Fatal(err)
			}
			tamper(t, e, info, out)
			if _, err := VerifyAudit(e.path, e.pass); !errors.Is(err, ErrAudit) {
				t.Fatalf("verify after tampering: %v", err)
			}
			if _, err := Unlock(e.path, e.pass, nil); !errors.Is(err, ErrAudit) {
				t.Fatalf("unlock after tampering: %v", err)
			}
		})
	}
	t.Run("front removed from a vault never archived", func(t *testing.T) {
		e := newArchiveEnv(t, 10)
		e.session.Lock()
		execArchiveSQL(t, e.path, `DELETE FROM audit WHERE seq<=3`)
		if _, err := VerifyAudit(e.path, e.pass); !errors.Is(err, ErrAudit) {
			t.Fatalf("verify: %v", err)
		}
		if _, err := Unlock(e.path, e.pass, nil); !errors.Is(err, ErrAudit) {
			t.Fatalf("unlock: %v", err)
		}
	})
}

func execArchiveSQL(t *testing.T, path, query string, args ...any) {
	t.Helper()
	db := mustOpen(t, path)
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

// An archive file is checked like the chain it came from.
func TestVerifyArchiveRejectsAlteredFiles(t *testing.T) {
	e := newArchiveEnv(t, 20)
	out := e.out("a.jsonl")
	mustArchive(t, e.session, out, 4)
	e.session.Lock()
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(strings.TrimSuffix(string(raw), "\n"), "\n")
	write := func(name, body string) string {
		p := e.out(name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, body := range map[string]string{
		"result changed":   strings.Replace(string(raw), `"result":"allowed"`, `"result":"denied"`, 1),
		"row dropped":      strings.Join(append(append([]string{}, lines[:3]...), lines[4:]...), ""),
		"last row dropped": strings.Join(lines[:len(lines)-1], ""),
		"first row gone":   strings.Join(lines[1:2], "") + "{}\n",
		"unknown member":   strings.Replace(string(raw), `{"v":`, `{"extra":1,"v":`, 1),
		// encoding/json would take the second, hashed value and verify,
		// while a reader of the exact name sees the first.
		"shadowed by case": strings.Replace(string(raw), `"result":"allowed",`, `"result":"denied","Result":"allowed",`, 1),
		"repeated member":  strings.Replace(string(raw), `"result":"allowed",`, `"result":"denied","result":"allowed",`, 1),
		"unhashed member":  strings.Replace(string(raw), `"result":"allowed",`, `"result":"allowed","agent_id":"x","AGENT_ID":"",`, 1),
		"extra space":      strings.Replace(string(raw), `{"v":`, `{ "v":`, 1),
		"not rows":         "hello\n",
		"empty":            "",
	} {
		p := write(strings.ReplaceAll(name, " ", "-")+".jsonl", body)
		if name == "last row dropped" {
			// Still a valid run on its own. It is the vault that says the
			// file stops short.
			if _, err := VerifyArchive(p); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if _, _, err := VerifyAuditArchive(e.path, e.pass, p); !errors.Is(err, ErrAudit) {
				t.Fatalf("%s against the vault: %v", name, err)
			}
			continue
		}
		if _, err := VerifyArchive(p); !errors.Is(err, ErrAudit) {
			t.Fatalf("%s verified: %v", name, err)
		}
	}
	if _, err := VerifyArchive(e.out("missing.jsonl")); err == nil {
		t.Fatal("a missing file verified")
	}
	// A file with its front removed is still a linked run that ends at the
	// vault's base. It is not the history, and the vault's check says so.
	front := write("front-removed.jsonl", strings.Join(lines[5:], ""))
	if got, err := VerifyArchive(front); err != nil || got.FirstSeq != 6 {
		t.Fatalf("front removed, as a run: %+v %v", got, err)
	}
	if _, _, err := VerifyAuditArchive(e.path, e.pass, front); !errors.Is(err, ErrArchiveIncomplete) {
		t.Fatalf("front removed, against the vault: %v", err)
	}

	// Another vault's archive is a valid run, and not this vault's.
	other := newArchiveEnv(t, 20)
	otherOut := other.out("o.jsonl")
	mustArchive(t, other.session, otherOut, 4)
	other.session.Lock()
	if _, _, err := VerifyAuditArchive(e.path, e.pass, otherOut); !errors.Is(err, ErrAudit) {
		t.Fatalf("another vault's archive verified against this one: %v", err)
	}
	never := newArchiveEnv(t, 5)
	never.session.Lock()
	if _, _, err := VerifyAuditArchive(never.path, never.pass, out); !errors.Is(err, ErrAudit) {
		t.Fatalf("an archive verified against a vault that was never archived: %v", err)
	}
}

// A commit that fails leaves every row in the vault, and the archive asks the
// table before it decides about its file. The rows are still there, so the
// file goes: nothing is left that looks like an archive and is not one.
func TestArchiveCommitFailureLosesNothing(t *testing.T) {
	e := newArchiveEnv(t, 20)
	rows := len(e.session.audit)
	out := e.out("a.jsonl")
	e.session.commitFault = func() error { return errors.New("disk") }
	if _, err := e.session.ArchiveAudit(out, 4); err == nil {
		t.Fatal("the fault did not surface")
	}
	e.session.commitFault = nil
	if got := mustAudit(t, e.path); len(got) != rows || got[0].Seq != 1 {
		t.Fatalf("vault holds %d rows from %d after a failed archive, want %d from 1", len(got), got[0].Seq, rows)
	}
	if e.session.base != nil || len(e.session.audit) != rows {
		t.Fatal("the session adopted a cut that was not committed")
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed archive left a file for rows the vault still holds")
	}
	// The same cut, tried again under the same name, goes through.
	mustArchive(t, e.session, out, 4)
	e.session.Lock()
	if _, _, err := VerifyAuditArchive(e.path, e.pass, out); err != nil {
		t.Fatal(err)
	}
}

// The transaction lands and the step after it fails. The rows are gone from
// the vault, so the file is the only copy: it stays, and the call reports the
// archive it made instead of an error that invites deleting it.
func TestArchiveThatLandedIsReportedAsDone(t *testing.T) {
	e := newArchiveEnv(t, 20)
	out := e.out("a.jsonl")
	e.session.postCommitFault = func() error { return errors.New("after commit") }
	info, err := e.session.ArchiveAudit(out, 4)
	e.session.postCommitFault = nil
	if err != nil {
		t.Fatalf("an archive that is durable was reported as failed: %v", err)
	}
	if e.session.base == nil || e.session.base.Seq != info.LastSeq || e.session.audit[0].Seq != info.LastSeq+1 || info.Kept != len(e.session.audit) {
		t.Fatalf("session after a landed archive: base %+v, %d rows, info %+v", e.session.base, len(e.session.audit), info)
	}
	if _, err := e.session.List(); err != nil {
		t.Fatal(err)
	}
	e.session.Lock()
	if _, cover, err := VerifyAuditArchive(e.path, e.pass, out); err != nil || cover.LastSeq != info.LastSeq {
		t.Fatalf("the file from a landed archive: %+v %v", cover, err)
	}
}

// A failed unlock by someone else lands a denial row behind the head while
// the file is being written. That is a competing writer like any other.
func TestArchiveAdoptsAnUnlockDenialBehindTheHead(t *testing.T) {
	e := newArchiveEnv(t, 20)
	attempts := 0
	e.session.archiveAttempt = func() {
		attempts++
		if attempts > 1 {
			return
		}
		if _, err := Unlock(e.path, []byte("not the passphrase"), nil); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("wrong passphrase: %v", err)
		}
	}
	out := e.out("a.jsonl")
	info := mustArchive(t, e.session, out, 6)
	if attempts != 2 {
		t.Fatalf("%d commit attempts, want the lost one and the retry", attempts)
	}
	denied := 0
	for _, ev := range e.session.audit {
		if ev.Action == actionUnlock && ev.Result == resultDenied {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("%d unlock denials kept, want the one that raced", denied)
	}
	e.session.Lock()
	if _, cover, err := VerifyAuditArchive(e.path, e.pass, out); err != nil || cover.LastSeq != info.LastSeq {
		t.Fatalf("after adopting a denial: %+v %v", cover, err)
	}
}

// Two archives race. The one that loses finds its rows already gone into the
// other's file, and removes its own, which duplicates part of that.
func TestArchiveLosesToAnotherArchive(t *testing.T) {
	e := newArchiveEnv(t, 30)
	control := mustUnlock(t, e.path, e.pass)
	theirs := e.out("theirs.jsonl")
	var won AuditArchive
	e.session.archiveAttempt = func() {
		if won.Rows == 0 {
			won = mustArchive(t, control, theirs, 3)
		}
	}
	mine := e.out("mine.jsonl")
	if _, err := e.session.ArchiveAudit(mine, 15); !errors.Is(err, ErrStale) {
		t.Fatalf("the losing archive: %v", err)
	}
	if _, err := os.Stat(mine); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the losing archive left its duplicate file")
	}
	if e.session.base == nil || e.session.base.Seq != won.LastSeq {
		t.Fatalf("the loser did not adopt the winner's cut: %+v", e.session.base)
	}
	e.session.Lock()
	control.Lock()
	if _, _, err := VerifyAuditArchive(e.path, e.pass, theirs); err != nil {
		t.Fatal(err)
	}
}

// Another process commits while the file is being written. The archive adopts
// that commit and cuts at the same row; the rows on file did not change.
func TestArchiveAdoptsACompetingCommit(t *testing.T) {
	e := newArchiveEnv(t, 20)
	control := mustUnlock(t, e.path, e.pass)
	var added Agent
	attempts := 0
	e.session.archiveAttempt = func() {
		attempts++
		if attempts > 1 {
			return
		}
		var err error
		if added, err = control.CreateAgent("made during the archive"); err != nil {
			t.Error(err)
		}
	}
	out := e.out("a.jsonl")
	info := mustArchive(t, e.session, out, 6)
	if attempts != 2 {
		t.Fatalf("%d commit attempts, want the lost one and the retry", attempts)
	}
	if _, err := e.session.Agent(added.ID); err != nil {
		t.Fatalf("the competing commit was lost: %v", err)
	}
	if got, err := VerifyArchive(out); err != nil || got.LastSeq != info.LastSeq {
		t.Fatalf("file after a retried archive: %+v %v", got, err)
	}
	e.session.Lock()
	control.Lock()
	if _, _, err := VerifyAuditArchive(e.path, e.pass, out); err != nil {
		t.Fatal(err)
	}
}

// A competitor that never stops wins every round. The archive gives up, says
// the session is stale, and takes its file with it: nothing was cut.
func TestArchiveGivesUpUnderConstantCompetition(t *testing.T) {
	e := newArchiveEnv(t, 20)
	control := mustUnlock(t, e.path, e.pass)
	rounds := 0
	e.session.archiveAttempt = func() {
		rounds++
		if _, err := control.List(); err != nil {
			t.Error(err)
		}
	}
	out := e.out("a.jsonl")
	if _, err := e.session.ArchiveAudit(out, 6); !errors.Is(err, ErrStale) {
		t.Fatalf("archive under constant competition: %v", err)
	}
	if rounds != archiveRetries+1 {
		t.Fatalf("%d rounds, want %d", rounds, archiveRetries+1)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a given-up archive left its file")
	}
	if got := mustAudit(t, e.path); got[0].Seq != 1 {
		t.Fatal("a given-up archive cut the chain")
	}
	// The session is still good, and a quiet moment lets the archive through.
	e.session.archiveAttempt = nil
	mustArchive(t, e.session, out, 6)
}

// A resident session adopts an archive made by the control plane when the row
// it last verified is still there, and retires itself when it is not: from
// where it stands that cut cannot be told from a rollback.
func TestResidentSessionAndAControlPlaneArchive(t *testing.T) {
	t.Run("its row was kept", func(t *testing.T) {
		e := newArchiveEnv(t, 20)
		control := mustUnlock(t, e.path, e.pass)
		info := mustArchive(t, control, e.out("a.jsonl"), 10)
		if _, err := e.session.List(); err != nil {
			t.Fatalf("resident session after an archive: %v", err)
		}
		if e.session.base == nil || e.session.base.Seq != info.LastSeq || e.session.audit[0].Seq != info.LastSeq+1 {
			t.Fatalf("resident session did not adopt the cut: %+v", e.session.base)
		}
		e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://other.example/v1/ping"}, ErrDeniedOrigin)
	})
	t.Run("its row was archived", func(t *testing.T) {
		e := newArchiveEnv(t, 5)
		control := mustUnlock(t, e.path, e.pass)
		for range 10 {
			if _, err := control.List(); err != nil {
				t.Fatal(err)
			}
		}
		mustArchive(t, control, e.out("a.jsonl"), 2)
		if _, err := e.session.List(); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("resident session whose row was archived: %v", err)
		}
		if _, err := e.session.List(); !errors.Is(err, ErrStale) {
			t.Fatalf("that session is still serving: %v", err)
		}
	})
}

// A backup of an archived vault restores, and the artifact is held to the
// same cut.
func TestBackupAndRestoreAfterArchive(t *testing.T) {
	e := newArchiveEnv(t, 20)
	info := mustArchive(t, e.session, e.out("a.jsonl"), 5)
	e.session.Lock()
	art, cp := mustBackup(t, e.path, e.dir, e.pass, nil)
	dest := filepath.Join(e.dir, "restored.db")
	if err := Restore(art, dest, e.pass, cp, nil); err != nil {
		t.Fatal(err)
	}
	restored := mustUnlock(t, dest, e.pass)
	if restored.base == nil || restored.base.Seq != info.LastSeq {
		t.Fatalf("restored base %+v", restored.base)
	}
	restored.Lock()

	// Backup authenticates what it copied. A source whose front was cut
	// further, without the DEK, yields no artifact and no checkpoint.
	execArchiveSQL(t, e.path, `DELETE FROM audit WHERE seq=?`, int64(info.LastSeq+1))
	bad := filepath.Join(e.dir, "bad-art.db")
	if _, err := Backup(canonicalExisting(t, e.path), bad, e.pass, nil); !errors.Is(err, ErrAudit) {
		t.Fatalf("backup of a vault with its front cut further: %v", err)
	}
	if _, err := os.Stat(bad); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("that backup left an artifact")
	}
}

// Counts that feed repeated-denial detection come from the rows the vault
// holds. After an archive the sealed mirror agrees with those rows.
func TestDetectionMirrorFollowsTheKeptRows(t *testing.T) {
	e := newArchiveEnv(t, 2)
	// Ordinary denials: a credential this agent holds no grant for.
	for range 2 {
		e.deny(t, HTTPBrokerRequest{CredentialID: e.pwID, Method: http.MethodGet, Target: "https://svc.example/v1/ping"}, ErrDeniedCredential)
	}
	if n := e.session.denials.byID[e.agentID].count; n != 2 {
		t.Fatalf("%d denials counted before the archive", n)
	}
	for range 10 {
		if _, err := e.session.List(); err != nil {
			t.Fatal(err)
		}
	}
	mustArchive(t, e.session, e.out("a.jsonl"), 3)
	if w := e.session.denials.byID[e.agentID]; w != nil && w.count != 0 {
		t.Fatalf("%d denials counted from rows that left", w.count)
	}
	if err := e.session.verified(); err != nil {
		t.Fatal(err)
	}
	e.session.Lock()
	opened := mustUnlock(t, e.path, e.pass)
	if len(opened.detection.Denials) != 0 {
		t.Fatalf("sealed mirror %+v", opened.detection)
	}
}

// Another archive lands first and cuts less. The chain no longer starts where
// this call's file does, so cutting at the same row would leave two files that
// overlap and a report of rows this call did not remove. It gives way instead.
func TestArchiveLosesToASmallerArchive(t *testing.T) {
	e := newArchiveEnv(t, 30)
	control := mustUnlock(t, e.path, e.pass)
	theirs := e.out("theirs.jsonl")
	var won AuditArchive
	e.session.archiveAttempt = func() {
		if won.Rows == 0 {
			won = mustArchive(t, control, theirs, 25)
		}
	}
	mine := e.out("mine.jsonl")
	if _, err := e.session.ArchiveAudit(mine, 6); !errors.Is(err, ErrStale) {
		t.Fatalf("the losing archive: %v", err)
	}
	if _, err := os.Stat(mine); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the losing archive left a file that overlaps the winner's")
	}
	if e.session.base == nil || e.session.base.Seq != won.LastSeq {
		t.Fatalf("the loser did not adopt the winner's cut: %+v", e.session.base)
	}
	// Run again, it continues from the winner's file.
	next := mustArchive(t, e.session, mine, 6)
	if next.FirstSeq != won.LastSeq+1 {
		t.Fatalf("the second try starts at %d, want %d", next.FirstSeq, won.LastSeq+1)
	}
	e.session.Lock()
	control.Lock()
	if _, _, err := VerifyAuditArchive(e.path, e.pass, theirs, mine); err != nil {
		t.Fatal(err)
	}
}

// A competing commit writes notice rows about a source this cut would
// archive. The retry must not cut there: the notice would lose its source and
// no unlock would accept the chain.
func TestArchiveRetryRefusesACutUnderANewNotice(t *testing.T) {
	e := archiveEnv{brokerEnv: newBrokerEnv(t)}
	e.dir = canonicalExisting(t, t.TempDir())
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://other.example/v1/ping"}, ErrDeniedOrigin)
	for range 20 {
		if _, err := e.session.List(); err != nil {
			t.Fatal(err)
		}
	}
	control := mustUnlock(t, e.path, e.pass)
	fired := false
	e.session.archiveAttempt = func() {
		if fired {
			return
		}
		fired = true
		if err := control.SetNotifier(&MemoryNotifier{}); err != nil {
			t.Fatal(err)
		}
		if err := control.DeliverPending(); err != nil {
			t.Fatal(err)
		}
	}
	out := e.out("a.jsonl")
	if _, err := e.session.ArchiveAudit(out, 6); !errors.Is(err, ErrStale) {
		t.Fatalf("archive over a new notice's source: %v", err)
	}
	if !fired || archiveActions(e.session.audit, actionNotify, resultDelivered) == 0 {
		t.Fatal("the competing delivery did not happen; the test proves nothing")
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the refused archive left its file")
	}
	e.session.Lock()
	control.Lock()
	if _, err := VerifyAudit(e.path, e.pass); err != nil {
		t.Fatalf("vault after the refused archive: %v", err)
	}
}

type hookNotifier struct{ hook func() }

func (h *hookNotifier) Notify(Notification) error {
	if f := h.hook; f != nil {
		h.hook = nil
		f()
	}
	return nil
}

// While an alert's callback runs, the session lock is released. Other calls
// go on, another process archives the alert's source, and this session adopts
// the cut. The outcome row for that alert must not be written: it would name a
// row the vault no longer holds, and no unlock would accept the chain.
func TestNoticeAboutAnArchivedRowIsNotWritten(t *testing.T) {
	e := archiveEnv{brokerEnv: newBrokerEnv(t)}
	e.dir = canonicalExisting(t, t.TempDir())
	control := mustUnlock(t, e.path, e.pass)
	cutDone := false
	n := &hookNotifier{}
	n.hook = func() {
		for range 10 {
			if _, err := e.session.List(); err != nil {
				t.Error(err)
			}
		}
		mustArchive(t, control, e.out("a.jsonl"), 3)
		if _, err := e.session.List(); err != nil { // adopts the cut
			t.Error(err)
		}
		cutDone = true
	}
	if err := e.session.SetNotifier(n); err != nil {
		t.Fatal(err)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://other.example/v1/ping"}, ErrDeniedOrigin)
	if !cutDone || e.session.base == nil {
		t.Fatal("the archive did not happen inside the callback; the test proves nothing")
	}
	first := e.session.audit[0].Seq
	for _, ev := range e.session.audit {
		if noticeAction(ev.Action) && ev.RefSeq < first {
			t.Fatalf("row %d is a notice about archived row %d", ev.Seq, ev.RefSeq)
		}
	}
	if _, err := e.session.List(); err != nil {
		t.Fatalf("the session after the skipped notice: %v", err)
	}
	e.session.Lock()
	control.Lock()
	if _, _, err := VerifyAuditArchive(e.path, e.pass, e.out("a.jsonl")); err != nil {
		t.Fatalf("vault after the skipped notice: %v", err)
	}
	mustUnlock(t, e.path, e.pass).Lock()
}

// This archive's transaction lands, the step after it fails, and before the
// call can look, another archive cuts further. The vault's base is no longer
// this cut, but this call's archive row is in the chain: it committed, and
// its file is the only copy of its rows. It stays, and the call says done.
func TestArchiveThatLandedIsDoneUnderALaterCut(t *testing.T) {
	e := newArchiveEnv(t, 30)
	control := mustUnlock(t, e.path, e.pass)
	theirs := e.out("theirs.jsonl")
	var later AuditArchive
	e.session.postCommitFault = func() error {
		if later.Rows == 0 {
			later = mustArchive(t, control, theirs, 4)
		}
		return errors.New("after commit")
	}
	mine := e.out("mine.jsonl")
	info, err := e.session.ArchiveAudit(mine, 12)
	e.session.postCommitFault = nil
	if err != nil {
		t.Fatalf("an archive that committed was reported as failed: %v", err)
	}
	if info.FirstSeq != 1 || info.LastSeq+1 != later.FirstSeq || e.session.base == nil || e.session.base.Seq != later.LastSeq {
		t.Fatalf("mine %+v, theirs %+v, base %+v", info, later, e.session.base)
	}
	e.session.Lock()
	control.Lock()
	if _, _, err := VerifyAuditArchive(e.path, e.pass, mine, theirs); err != nil {
		t.Fatal(err)
	}
}

// Another archive lands first and cuts at the very same row. The vault's base
// is this call's cut, but the transaction that put it there was not this
// one: the row in the chain is theirs. This file is a duplicate and goes.
func TestArchiveLosesToAnArchiveOfTheSameRows(t *testing.T) {
	e := newArchiveEnv(t, 30)
	control := mustUnlock(t, e.path, e.pass)
	if _, err := e.session.List(); err != nil { // adopt the unlock row, so both cut the same chain
		t.Fatal(err)
	}
	theirs := e.out("theirs.jsonl")
	var won AuditArchive
	e.session.archiveAttempt = func() {
		if won.Rows == 0 {
			won = mustArchive(t, control, theirs, 6)
		}
	}
	mine := e.out("mine.jsonl")
	if _, err := e.session.ArchiveAudit(mine, 6); !errors.Is(err, ErrStale) {
		t.Fatalf("the losing archive: %v", err)
	}
	if e.session.base == nil || e.session.base.Seq != won.LastSeq {
		t.Fatalf("base %+v, winner %+v", e.session.base, won)
	}
	if _, err := os.Stat(mine); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the losing archive left its duplicate file")
	}
	e.session.Lock()
	control.Lock()
	if _, _, err := VerifyAuditArchive(e.path, e.pass, theirs); err != nil {
		t.Fatal(err)
	}
}

// Someone without the passphrase removes or changes rows this archive has on
// file, and the commit fails. No archive took those rows: the file is the only
// true copy left. It stays, whatever else the tampering did to the vault, and
// the error says so.
func TestArchiveKeepsItsFileWhenItsRowsLeftTheTableByHand(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, e archiveEnv, first, cut uint64){
		"every row through the cut deleted": func(t *testing.T, e archiveEnv, _, cut uint64) {
			execArchiveSQL(t, e.path, `DELETE FROM audit WHERE seq<=?`, int64(cut))
		},
		"all but the first deleted": func(t *testing.T, e archiveEnv, first, cut uint64) {
			execArchiveSQL(t, e.path, `DELETE FROM audit WHERE seq>? AND seq<=?`, int64(first), int64(cut))
		},
		"deleted, and the head moved so the session cannot adopt": func(t *testing.T, e archiveEnv, first, cut uint64) {
			execArchiveSQL(t, e.path, `DELETE FROM audit WHERE seq>? AND seq<=?`, int64(first), int64(cut))
			execArchiveSQL(t, e.path, `UPDATE vault SET audit_seq=audit_seq+1`)
		},
		"the whole table emptied": func(t *testing.T, e archiveEnv, _, _ uint64) {
			execArchiveSQL(t, e.path, `DELETE FROM audit`)
		},
		"one row changed in place": func(t *testing.T, e archiveEnv, first, _ uint64) {
			execArchiveSQL(t, e.path, `UPDATE audit SET result='denied' WHERE seq=?`, int64(first+1))
		},
		"the table cannot be read": func(t *testing.T, e archiveEnv, _, _ uint64) {
			execArchiveSQL(t, e.path, `ALTER TABLE audit RENAME TO elsewhere`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newArchiveEnv(t, 20)
			before := mustArchive(t, e.session, e.out("first.jsonl"), 20)
			for range 15 {
				if _, err := e.session.List(); err != nil {
					t.Fatal(err)
				}
			}
			cut := e.session.audit[len(e.session.audit)-6].Seq
			e.session.archiveAttempt = func() { tamper(t, e, before.LastSeq+1, cut) }
			e.session.commitFault = func() error { return errors.New("disk") }
			out := e.out("second.jsonl")
			_, err := e.session.ArchiveAudit(out, 5)
			e.session.commitFault = nil
			if !errors.Is(err, ErrArchiveKept) {
				t.Fatalf("archive over rows tampered with under it: %v", err)
			}
			if got, verr := VerifyArchive(e.out("first.jsonl"), out); verr != nil || got.LastSeq != cut {
				t.Fatalf("the only copy of rows through %d: %+v %v", cut, got, verr)
			}
			e.session.Lock()
			if _, err := VerifyAudit(e.path, e.pass); err == nil {
				t.Fatal("the tampered vault verified")
			}
		})
	}
}

// Failed unlocks by someone else keep landing denial rows behind the head.
// Each is a lost race, and the archive says so when it gives up: the write
// that failed calls it an audit failure, which would read like tampering.
func TestArchiveGivesUpUnderConstantUnlockDenials(t *testing.T) {
	e := newArchiveEnv(t, 20)
	rounds := 0
	e.session.archiveAttempt = func() {
		rounds++
		if _, err := Unlock(e.path, []byte("not the passphrase"), nil); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("wrong passphrase: %v", err)
		}
	}
	out := e.out("a.jsonl")
	if _, err := e.session.ArchiveAudit(out, 6); !errors.Is(err, ErrStale) || errors.Is(err, ErrArchiveKept) {
		t.Fatalf("archive under constant unlock denials: %v", err)
	}
	if rounds != archiveRetries+1 {
		t.Fatalf("%d attempts, want %d", rounds, archiveRetries+1)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the archive that gave up left its file")
	}
	e.session.archiveAttempt = nil
	mustArchive(t, e.session, out, 6)
}

// The file must hold the rows that are about to be deleted, not merely rows
// that read back as valid lines. A value that does not survive encoding comes
// back changed, and the vault's copy must not be deleted on that file.
func TestWriteArchiveComparesWhatItReadsBack(t *testing.T) {
	e := newArchiveEnv(t, 3)
	rows := append([]auditEvent{}, e.session.audit...)
	rows[1].Reasons = "\xff"
	out := e.out("a.jsonl")
	if err := writeArchive(out, rows); !errors.Is(err, ErrIO) {
		t.Fatalf("a file that reads back as different rows: %v", err)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the rejected file was left in place")
	}
	if err := writeArchive(out, e.session.audit); err != nil {
		t.Fatal(err)
	}
}

// A copy of the vault from before its first archive has no base. Checking it
// against the archive file made later is a failed verification, not a crash.
func TestVerifyAuditArchiveAgainstACopyFromBeforeTheCut(t *testing.T) {
	e := newArchiveEnv(t, 20)
	e.session.Lock()
	raw, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	old := e.out("old-vault.db")
	if err := os.WriteFile(old, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s := mustUnlock(t, e.path, e.pass)
	out := e.out("a.jsonl")
	mustArchive(t, s, out, 4)
	s.Lock()
	if _, _, err := VerifyAuditArchive(old, e.pass, out); !errors.Is(err, ErrAudit) {
		t.Fatalf("an archive checked against a copy that was never cut: %v", err)
	}
}

// The chain's hashes are not keyed, so anyone can alter a row in an archive
// file and recompute every hash after it. The result is a valid run on its
// own. It is not this vault's history: the vault names the hash it follows.
func TestVerifyAuditArchiveRejectsARecomputedFile(t *testing.T) {
	e := newArchiveEnv(t, 20)
	out := e.out("a.jsonl")
	mustArchive(t, e.session, out, 4)
	e.session.Lock()
	rows, err := readArchive(out)
	if err != nil {
		t.Fatal(err)
	}
	i := len(rows) / 2
	rows[i].Time = rows[i-1].Time
	for ; i < len(rows); i++ {
		prev, err := hex.DecodeString(rows[i-1].Hash)
		if err != nil {
			t.Fatal(err)
		}
		rows[i].Prev = rows[i-1].Hash
		rows[i].Hash = hex.EncodeToString(hashEvent(prev, rows[i]))
	}
	forged := e.out("forged.jsonl")
	writeLines(t, forged, rows)
	if _, err := VerifyArchive(forged); err != nil {
		t.Fatalf("the forged file should be a valid run on its own, or the test proves nothing: %v", err)
	}
	if _, _, err := VerifyAuditArchive(e.path, e.pass, forged); !errors.Is(err, ErrAudit) {
		t.Fatalf("a recomputed archive verified against the vault: %v", err)
	}
	if _, _, err := VerifyAuditArchive(e.path, e.pass, out); err != nil {
		t.Fatal(err)
	}

	// A run that starts at row 1 with anything but the vault's creation is
	// not the start of a vault's history.
	first, err := nextAudit(nil, rows[0].VaultID, auditEvent{Action: actionList, Result: resultAllowed})
	if err != nil {
		t.Fatal(err)
	}
	headless := e.out("headless.jsonl")
	writeLines(t, headless, []auditEvent{first})
	if _, err := VerifyArchive(headless); !errors.Is(err, ErrAudit) {
		t.Fatalf("a run whose row 1 is not vault_create verified: %v", err)
	}
}

func writeLines(t *testing.T, path string, rows []auditEvent) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range rows {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

package vault

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRoundTripLifecycleAndNoPlaintext(t *testing.T) {
	var logs bytes.Buffer
	logger := log.New(&logs, "", 0)
	path, pass, session := mustCreate(t, logger)
	secret := randBytesT(t, 32)
	other := randBytesT(t, 24)
	label := "ci-label-" + hex.EncodeToString(randBytesT(t, 8))
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	review := time.Date(2029, 6, 1, 0, 0, 0, 0, time.UTC)
	rotation := time.Date(2028, 5, 4, 0, 0, 0, 0, time.UTC)
	stored, err := session.Put(label, "api_key", secret, PutOptions{
		ExpiresAt:     &exp,
		ReviewDueAt:   &review,
		RotationDueAt: &rotation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Type != "api_key" || stored.Lifecycle.State != StateActive || len(stored.Secret) != 0 {
		t.Fatalf("put metadata id=%s type=%s state=%s secretLen=%d", stored.ID, stored.Type, stored.Lifecycle.State, len(stored.Secret))
	}
	if !stored.Lifecycle.ExpiresAt.Equal(exp) || !stored.Lifecycle.ReviewDueAt.Equal(review) || !stored.Lifecycle.RotationDueAt.Equal(rotation) {
		t.Fatal("lifecycle fields were not stored")
	}
	second, err := session.Put("other", "password", other, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Put("x", "not-a-type", secret, PutOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := session.Put("x", "generic", nil, PutOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	listed, err := session.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatal(len(listed))
	}
	for _, item := range listed {
		if len(item.Secret) != 0 {
			t.Fatal("list returned a secret")
		}
	}
	session.Lock()
	if _, err := session.Get(stored.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}

	opened, err := Unlock(path, pass, logger)
	if err != nil {
		t.Fatal(err)
	}
	got, err := opened.Get(stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, secret) || got.Type != "api_key" || got.Lifecycle.State != StateActive {
		t.Fatal("retrieved credential metadata or secret mismatch")
	}
	if got.Lifecycle.CreatedAt.IsZero() || got.Lifecycle.UpdatedAt.IsZero() {
		t.Fatal("missing lifecycle timestamps")
	}
	gotOther, err := opened.Get(second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotOther.Secret, other) {
		t.Fatal("second credential mismatch")
	}
	if _, err := opened.Get(string(secret)); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	dek := append([]byte(nil), opened.dek...)
	head, err := VerifyAudit(path, pass)
	if err != nil || head == "" || head != opened.header.AuditHead {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(path, []byte("wrong-passphrase")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	opened.Lock()
	raw := readAll(t, path)
	assertAbsent(t, raw, secret)
	assertAbsent(t, raw, other)
	assertAbsent(t, raw, pass)
	assertAbsent(t, raw, []byte(label))
	assertAbsent(t, logs.Bytes(), secret)
	assertAbsent(t, logs.Bytes(), pass)
	if bytes.Contains(raw, dek) {
		t.Fatal("master key persisted")
	}
	if _, err := os.Stat(path + ".audit"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode %v", path, fi.Mode().Perm())
		}
	}
}

func TestCredentialAndAuditCommitAtomically(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 32)
	stored, err := session.Put("label", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if session.header.AuditSeq == 0 || session.header.AuditHead == "" {
		t.Fatal("missing authenticated head")
	}
	db := mustOpen(t, path)
	var action, head string
	var seq int64
	if err := db.QueryRow(`SELECT action FROM audit WHERE seq=?`, session.header.AuditSeq).Scan(&action); err != nil {
		t.Fatal(err)
	}
	if action != actionPut {
		t.Fatalf("action %s", action)
	}
	if err := db.QueryRow(`SELECT audit_head, audit_seq FROM vault`).Scan(&head, &seq); err != nil {
		t.Fatal(err)
	}
	if head != session.header.AuditHead || uint64(seq) != session.header.AuditSeq {
		t.Fatalf("head %s seq %d", head, seq)
	}
	db.Close()
	session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	got, err := opened.Get(stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, secret) {
		t.Fatal("secret mismatch")
	}
	if err := verifyChain(opened.audit); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionFailureRollsBackCredentialAndAudit(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	beforeLen := len(session.audit)
	beforeHead := session.header.AuditHead
	beforeSeq := session.header.AuditSeq
	secret := randBytesT(t, 32)
	session.commitFault = func() error { return errors.New("induced") }
	_, err := session.Put("label", "generic", secret, PutOptions{})
	if !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(err.Error()), secret) {
		t.Fatal("rollback error contains secret")
	}
	if len(session.creds) != 0 || len(session.audit) != beforeLen || session.header.AuditHead != beforeHead || session.header.AuditSeq != beforeSeq {
		t.Fatal("failed put changed the session")
	}
	db := mustOpen(t, path)
	var seq int64
	var action string
	if err := db.QueryRow(`SELECT audit_seq FROM vault`).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if uint64(seq) != beforeSeq {
		t.Fatalf("durable seq %d", seq)
	}
	err = db.QueryRow(`SELECT action FROM audit WHERE action=?`, actionPut).Scan(&action)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("durable put action %q err %v", action, err)
	}
	db.Close()
	session.commitFault = nil
	stored, err := session.Put("label", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	session.Lock()
	assertAbsent(t, readAll(t, path), secret)
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	got, err := opened.Get(stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, secret) {
		t.Fatal("secret missing after a later commit")
	}
	var puts int
	for _, ev := range opened.audit {
		if ev.Action == actionPut && ev.Result == resultAllowed {
			puts++
		}
	}
	if puts != 1 {
		t.Fatalf("allowed puts %d", puts)
	}
}

func TestGetWithholdsSecretWhenAuditCommitFails(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 32)
	stored, err := session.Put("label", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	session.commitFault = func() error { return errors.New("induced") }
	cred, err := session.Get(stored.ID)
	if !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	if len(cred.Secret) != 0 || bytes.Contains([]byte(err.Error()), secret) {
		t.Fatal("failed get returned secret material")
	}
	for _, ev := range session.audit {
		if ev.Action == actionGet {
			t.Fatal("rolled-back get stayed in the session chain")
		}
	}
	db := mustOpen(t, path)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action=?`, actionGet).Scan(&n); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if n != 0 {
		t.Fatalf("durable get events %d", n)
	}
	session.commitFault = nil
	got, err := session.Get(stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, secret) {
		t.Fatal("secret mismatch")
	}
	session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	again, err := opened.Get(stored.ID)
	if err != nil || !bytes.Equal(again.Secret, secret) {
		t.Fatal(err)
	}
}

func TestWrongPassphrase(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	secret := randBytesT(t, 32)
	if _, err := session.Put("label", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	wrong := []byte(randHex(t, 16))
	_, err := Unlock(path, wrong, log.New(&logs, "", 0))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), string(wrong)) || strings.Contains(err.Error(), string(pass)) || bytes.Contains([]byte(err.Error()), secret) {
		t.Fatal("unlock error contains secret material")
	}
	raw := readAll(t, path)
	assertAbsent(t, raw, secret)
	assertAbsent(t, raw, wrong)
	assertAbsent(t, logs.Bytes(), secret)
	assertAbsent(t, logs.Bytes(), wrong)
	if !bytes.Contains(raw, []byte(resultDenied)) {
		t.Fatal("denied unlock was not audited")
	}
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	got, err := opened.Get(mustOne(t, opened).ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, secret) {
		t.Fatal("secret unreadable after denied unlock")
	}
	var denialSeq uint64
	for _, ev := range opened.audit {
		if ev.Action == actionUnlock && ev.Result == resultDenied {
			denialSeq = ev.Seq
		}
	}
	if denialSeq == 0 || opened.header.AuditSeq <= denialSeq {
		t.Fatalf("denial seq %d head %d", denialSeq, opened.header.AuditSeq)
	}
	if err := verifyChain(opened.audit); err != nil {
		t.Fatal(err)
	}
	if err := suffixAllows(opened.audit, opened.header); err != nil {
		t.Fatal(err)
	}
}

func TestTamperAndSwap(t *testing.T) {
	pathA, passA, sessionA := mustCreate(t, nil)
	secretA := randBytesT(t, 32)
	if _, err := sessionA.Put("a", "generic", secretA, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	sessionA.Lock()
	pathB, passB, sessionB := mustCreate(t, nil)
	secretB := randBytesT(t, 32)
	if _, err := sessionB.Put("b", "generic", secretB, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	sessionB.Lock()

	dataCopy := filepath.Join(t.TempDir(), "data.db")
	wrapCopy := filepath.Join(t.TempDir(), "wrap.db")
	copyFile(t, pathA, dataCopy)
	copyFile(t, pathA, wrapCopy)
	mutateDB(t, dataCopy, func(db *sql.DB) {
		var data []byte
		if err := db.QueryRow(`SELECT encrypted_document FROM vault`).Scan(&data); err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 0xff
		if _, err := db.Exec(`UPDATE vault SET encrypted_document=?`, data); err != nil {
			t.Fatal(err)
		}
	})
	_, err := Unlock(dataCopy, passA, nil)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(err.Error()), secretA) || strings.Contains(err.Error(), string(passA)) {
		t.Fatal("tamper error contains secret material")
	}
	db, header, events, err := loadVault(dataCopy)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	var denials int
	for _, ev := range events {
		if ev.Action == actionUnlock && ev.Result == resultDenied {
			denials++
			if ev.CredID != "" || ev.CredType != "" {
				t.Fatal("corrupt unlock denial carried metadata")
			}
		}
	}
	if denials != 1 || events[len(events)-1].Hash == header.AuditHead {
		t.Fatalf("denials %d head %s", denials, header.AuditHead)
	}
	if err := suffixAllows(events, header); err != nil {
		t.Fatal(err)
	}
	mutateDB(t, wrapCopy, func(db *sql.DB) {
		var wrapped []byte
		if err := db.QueryRow(`SELECT wrapped_dek FROM vault`).Scan(&wrapped); err != nil {
			t.Fatal(err)
		}
		wrapped[len(wrapped)-1] ^= 0xff
		if _, err := db.Exec(`UPDATE vault SET wrapped_dek=?`, wrapped); err != nil {
			t.Fatal(err)
		}
	})
	_, err = Unlock(wrapCopy, passA, nil)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}

	var dataB, nonceB []byte
	mutateDB(t, pathB, func(db *sql.DB) {
		if err := db.QueryRow(`SELECT encrypted_document, data_nonce FROM vault`).Scan(&dataB, &nonceB); err != nil {
			t.Fatal(err)
		}
	})
	mutateDB(t, pathA, func(db *sql.DB) {
		if _, err := db.Exec(`UPDATE vault SET encrypted_document=?, data_nonce=?`, dataB, nonceB); err != nil {
			t.Fatal(err)
		}
	})
	_, err = Unlock(pathA, passA, nil)
	if err == nil {
		t.Fatal("swapped ciphertext decrypted")
	}
	if bytes.Contains([]byte(err.Error()), secretA) || bytes.Contains([]byte(err.Error()), secretB) {
		t.Fatal("swap error contains secret material")
	}
	opened, err := Unlock(pathB, passB, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	got, err := opened.Get(mustOne(t, opened).ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, secretB) {
		t.Fatal("untampered vault secret changed")
	}
}

func TestForgedAuditBlocksUnlock(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 32)
	stored, err := session.Put("label", "bearer_token", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	session.Lock()
	mutateDB(t, path, func(db *sql.DB) {
		events, err := readAuditRows(db)
		if err != nil {
			t.Fatal(err)
		}
		forged, err := nextEvent(events, actionGet, events[0].VaultID, stored.ID, "bearer_token", resultAllowed)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := insertAudit(tx, forged); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	_, err = Unlock(path, pass, nil)
	if !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(err.Error()), secret) {
		t.Fatal("audit error contains secret")
	}
}

func TestTamperedAuditHashFailsVerify(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 24)
	if _, err := session.Put("label", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	mutateDB(t, path, func(db *sql.DB) {
		if _, err := db.Exec(`UPDATE audit SET result=? WHERE seq=1`, resultDenied); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	_, err := Unlock(path, pass, nil)
	if !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(err.Error()), secret) || strings.Contains(err.Error(), string(pass)) {
		t.Fatal("tamper error contains secret material")
	}
}

func TestRewrittenAuditHeadFailsVerify(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 24)
	if _, err := session.Put("label", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	mutateDB(t, path, func(db *sql.DB) {
		events, err := readAuditRows(db)
		if err != nil || len(events) < 2 {
			t.Fatal(err)
		}
		kept := events[len(events)-2]
		if _, err := db.Exec(`DELETE FROM audit WHERE seq=?`, int64(events[len(events)-1].Seq)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE vault SET audit_head=?, audit_seq=?`, kept.Hash, int64(kept.Seq)); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	_, err := Unlock(path, pass, nil)
	if err == nil {
		t.Fatal("rewritten head unlocked")
	}
	if bytes.Contains([]byte(err.Error()), secret) || strings.Contains(err.Error(), string(pass)) {
		t.Fatal("error contains secret material")
	}
}

func TestNoncanonicalDenialSuffixRejected(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 24)
	if _, err := session.Put("label", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	head := session.header.AuditHead
	seq := session.header.AuditSeq
	session.Lock()
	mutateDB(t, path, func(db *sql.DB) {
		events, err := readAuditRows(db)
		if err != nil {
			t.Fatal(err)
		}
		forged, err := nextEvent(events, actionUnlock, events[0].VaultID, strings.Repeat("ab", 16), "api_key", resultDenied)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := insertAudit(tx, forged); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	_, err := Unlock(path, pass, nil)
	if !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(err.Error()), secret) || strings.Contains(err.Error(), string(pass)) {
		t.Fatal("error contains secret material")
	}
	mutateDB(t, path, func(db *sql.DB) {
		h, err := readVaultRow(db)
		if err != nil {
			t.Fatal(err)
		}
		if h.AuditHead != head || h.AuditSeq != seq {
			t.Fatalf("head advanced to %s seq %d", h.AuditHead, h.AuditSeq)
		}
	})
}

func TestNoncanonicalDenialTimeRejected(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 24)
	if _, err := session.Put("label", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	head := session.header.AuditHead
	seq := session.header.AuditSeq
	session.Lock()
	stamps := []string{
		"not-a-time",
		"2000-01-01T00:00:00Z",
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}
	for _, ts := range stamps {
		var forged auditEvent
		mutateDB(t, path, func(db *sql.DB) {
			events, err := readAuditRows(db)
			if err != nil {
				t.Fatal(err)
			}
			forged, err = denialAt(events[len(events)-1], ts)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if err := insertAudit(tx, forged); err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		})
		if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
			t.Fatalf("verify %q: %v", ts, err)
		}
		_, err := Unlock(path, pass, nil)
		if !errors.Is(err, ErrAudit) {
			t.Fatalf("unlock %q: %v", ts, err)
		}
		if bytes.Contains([]byte(err.Error()), secret) || strings.Contains(err.Error(), string(pass)) {
			t.Fatal("error contains secret material")
		}
		mutateDB(t, path, func(db *sql.DB) {
			h, err := readVaultRow(db)
			if err != nil {
				t.Fatal(err)
			}
			if h.AuditHead != head || h.AuditSeq != seq {
				t.Fatalf("head advanced to %s seq %d", h.AuditHead, h.AuditSeq)
			}
			if _, err := db.Exec(`DELETE FROM audit WHERE seq=?`, int64(forged.Seq)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCorruptDatabase(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 24)
	if _, err := session.Put("label", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Unlock(path, pass, nil)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(err.Error()), secret) || strings.Contains(err.Error(), string(pass)) {
		t.Fatal("corrupt error contains secret material")
	}
}

func TestLogOmitsFreeFormLabel(t *testing.T) {
	var logs bytes.Buffer
	_, _, session := mustCreate(t, log.New(&logs, "", 0))
	secret := []byte(randHex(t, 16))
	// A label may carry a secret this session has never stored. Redaction
	// does not know it, so the log line must not include the label at all.
	foreign := randHex(t, 16)
	label := "pre-" + foreign + "-post"
	stored, err := session.Put(label, "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(logs.Bytes(), []byte(foreign)) || bytes.Contains(logs.Bytes(), secret) {
		t.Fatal("put log contains label or secret")
	}
	logs.Reset()
	if _, err := session.Get(stored.ID); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(logs.Bytes(), []byte(foreign)) || bytes.Contains(logs.Bytes(), secret) {
		t.Fatal("get log contains label or secret")
	}
}

func TestDeniedGetOmitsUnknownHexID(t *testing.T) {
	var logs bytes.Buffer
	path, _, session := mustCreate(t, log.New(&logs, "", 0))
	stored, err := session.Put("label", "generic", []byte(randHex(t, 8)), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// A 32-character hex value is the shape of a credential id, but this one
	// is a foreign secret the vault has never stored. It must not be copied
	// into the denial's plaintext credential_id or the process log.
	foreign := randHex(t, 16)
	if len(foreign) != 32 || foreign == stored.ID {
		t.Fatalf("foreign id %q", foreign)
	}
	logs.Reset()
	if _, err := session.Get(foreign); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	var denied int
	for _, ev := range session.audit {
		if ev.Action != actionGet || ev.Result != resultDenied {
			continue
		}
		denied++
		if ev.CredID != "" || ev.CredType != "" {
			t.Fatalf("unknown lookup denial carried metadata id=%q type=%q", ev.CredID, ev.CredType)
		}
	}
	if denied != 1 {
		t.Fatalf("denied gets %d", denied)
	}
	if _, err := session.Get(stored.ID); err != nil {
		t.Fatal(err)
	}
	var allowed bool
	for _, ev := range session.audit {
		if ev.Action == actionGet && ev.Result == resultAllowed && ev.CredID == stored.ID && ev.CredType == "generic" {
			allowed = true
		}
	}
	if !allowed {
		t.Fatal("known credential id missing from allowed lookup")
	}
	session.Lock()
	raw := readAll(t, path)
	assertAbsent(t, raw, []byte(foreign))
	assertAbsent(t, logs.Bytes(), []byte(foreign))
	var sawKnown bool
	for _, ev := range mustAudit(t, path) {
		if strings.Contains(ev.CredID, foreign) || strings.Contains(ev.CredType, foreign) || strings.Contains(ev.Action, foreign) || strings.Contains(ev.Result, foreign) {
			t.Fatal("foreign secret flowed into plaintext audit storage")
		}
		if ev.Action == actionGet && ev.Result == resultAllowed && ev.CredID == stored.ID {
			sawKnown = true
		}
		if ev.Action == actionGet && ev.Result == resultDenied && ev.CredID != "" {
			t.Fatalf("persisted denial id %q", ev.CredID)
		}
	}
	if !sawKnown {
		t.Fatal("known credential id missing from persisted audit")
	}
}

func TestDeniedGetOmitsEmbeddedSecret(t *testing.T) {
	var logs bytes.Buffer
	path := filepath.Join(t.TempDir(), "vault.db")
	pass := []byte(randHex(t, 4))
	secret := []byte(randHex(t, 4))
	session, err := Create(path, pass, log.New(&logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Lock()
	if _, err := session.Put("label", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	embeddedSecret := strings.Repeat("0", 24) + string(secret)
	embeddedPass := strings.Repeat("1", 24) + string(pass)
	clean := strings.Repeat("ab", 16)
	for _, id := range []string{embeddedSecret, embeddedPass, clean} {
		if _, err := hex.DecodeString(id); err != nil || len(id) != 32 {
			t.Fatal(id)
		}
		if _, err := session.Get(id); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	var denied int
	for _, ev := range session.audit {
		if ev.Action != actionGet || ev.Result != resultDenied {
			continue
		}
		denied++
		if ev.CredID != "" || ev.CredType != "" {
			t.Fatalf("unknown lookup denial carried metadata id=%q type=%q", ev.CredID, ev.CredType)
		}
	}
	if denied != 3 {
		t.Fatalf("denied gets %d", denied)
	}
	session.Lock()
	raw := readAll(t, path)
	for _, leaked := range [][]byte{secret, pass, []byte(embeddedSecret), []byte(embeddedPass), []byte(clean)} {
		assertAbsent(t, raw, leaked)
		assertAbsent(t, logs.Bytes(), leaked)
	}
}

func TestSentinelSecretDoesNotFlowIntoPlaintext(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	sentinel := []byte(randHex(t, 16))
	label := "pre-" + string(sentinel) + "-post"
	stored, err := session.Put(label, "generic", sentinel, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// These values already exist as identifiers or fixed literals. Storing
	// them as secrets must succeed; the audit row is not a copy of the secret.
	incidental := []struct {
		label, typ string
		secret     []byte
	}{
		{label: "id-secret", typ: "generic", secret: []byte(stored.ID)},
		{label: "id-prefix", typ: "generic", secret: []byte(stored.ID[:8])},
		{label: "type-name", typ: "generic", secret: []byte("api_key")},
		{label: "type-substring", typ: "generic", secret: []byte("api")},
		{label: "result-substring", typ: "generic", secret: []byte("allow")},
		{label: "vault-id", typ: "generic", secret: []byte(session.id)},
		{label: "root-label", typ: "generic", secret: []byte(rootPassphrase)},
		{label: "kdf-id", typ: "generic", secret: []byte(algoArgon2id)},
		{label: "kdf-substring", typ: "generic", secret: []byte("argon")},
	}
	for _, item := range incidental {
		cred, err := session.Put(item.label, item.typ, item.secret, PutOptions{})
		if err != nil {
			t.Fatalf("label %s: %v", item.label, err)
		}
		if cred.Type != item.typ || len(cred.Secret) != 0 {
			t.Fatalf("label %s echoed secret metadata", item.label)
		}
	}
	if _, err := session.List(); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	raw := readAll(t, path)
	assertAbsent(t, raw, sentinel)
	assertAbsent(t, raw, pass)
	assertAbsent(t, logs.Bytes(), sentinel)
	assertAbsent(t, logs.Bytes(), pass)
	for _, ev := range mustAudit(t, path) {
		fields := strings.Join([]string{ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.Time, ev.Prev, ev.Hash}, "\n")
		if strings.Contains(fields, string(sentinel)) || strings.Contains(fields, string(pass)) {
			t.Fatal("sentinel flowed into an audit field")
		}
		if strings.Contains(fields, "api_key") {
			t.Fatal("type-name secret flowed into an audit field")
		}
	}
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	got, err := opened.Get(stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, sentinel) || got.Label != label {
		t.Fatal("sentinel round-trip mismatch")
	}
	if bytes.Contains(raw, []byte(label)) {
		t.Fatal("label containing the sentinel was stored in plaintext")
	}
}

func TestRejectedPutIsAuditedWithoutMetadata(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	secret := randBytesT(t, 24)
	badLabel := "bad-\n" + hex.EncodeToString(secret)
	badUTF := "bad-\xff-" + hex.EncodeToString(secret)
	badType := "not-a-type-" + hex.EncodeToString(secret[:4])
	zero := time.Time{}
	beyond := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	negative := time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)
	attempts := []struct {
		label, typ string
		secret     []byte
		opt        PutOptions
	}{
		{label: "", typ: "generic", secret: secret},
		{label: badLabel, typ: "generic", secret: secret},
		{label: badUTF, typ: "generic", secret: secret},
		{label: "ok", typ: badType, secret: secret},
		{label: "ok", typ: "generic", secret: nil},
		{label: "ok", typ: "generic", secret: secret, opt: PutOptions{ExpiresAt: &zero}},
		{label: "ok", typ: "generic", secret: secret, opt: PutOptions{ExpiresAt: &beyond}},
		{label: "ok", typ: "generic", secret: secret, opt: PutOptions{RotationDueAt: &negative}},
	}
	for _, attempt := range attempts {
		if _, err := session.Put(attempt.label, attempt.typ, attempt.secret, attempt.opt); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	var denied int
	for _, ev := range session.audit {
		if ev.Action == actionPut && ev.Result == resultDenied {
			denied++
			if ev.CredID != "" || ev.CredType != "" {
				t.Fatalf("denial carried metadata id=%q type=%q", ev.CredID, ev.CredType)
			}
		}
	}
	if denied != len(attempts) {
		t.Fatalf("denied puts %d", denied)
	}
	far := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	stored, err := session.Put("café", "generic", secret, PutOptions{ExpiresAt: &far})
	if err != nil {
		t.Fatal(err)
	}
	session.Lock()
	raw := readAll(t, path)
	assertAbsent(t, raw, secret)
	assertAbsent(t, logs.Bytes(), secret)
	if bytes.Contains(raw, []byte(badLabel)) || bytes.Contains(raw, []byte(badUTF)) || bytes.Contains(raw, []byte(badType)) || bytes.Contains(logs.Bytes(), []byte(badLabel)) || bytes.Contains(logs.Bytes(), []byte(badUTF)) {
		t.Fatal("denial recorded free-form metadata")
	}
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	got, err := opened.Get(stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, secret) || got.Label != "café" || got.Lifecycle.ExpiresAt == nil || !got.Lifecycle.ExpiresAt.Equal(far) {
		t.Fatal("secret mismatch after denied puts")
	}
	sealed := 0
	for _, ev := range opened.audit {
		if ev.Action == actionPut && ev.Result == resultDenied {
			sealed++
		}
	}
	if sealed != len(attempts) {
		t.Fatalf("durable denials %d", sealed)
	}
}

func TestAuthenticatedPlaintextRejectionIsAudited(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	secret := randBytesT(t, 32)
	if _, err := session.Put("label", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	head := session.header.AuditHead
	seq := session.header.AuditSeq
	aad := dataAAD(session.id, head, seq)
	before := len(session.audit)
	badNonce, badJSON, err := seal(session.dek, []byte("{"), aad)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	stored, err := json.Marshal(document{Credentials: []credential{{
		ID:        strings.Repeat("cd", 16),
		Label:     "label",
		Type:      "generic",
		Secret:    []byte{},
		Lifecycle: lifecycle{State: StateActive, CreatedAt: now, UpdatedAt: now},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	storedNonce, badStored, err := seal(session.dek, stored, aad)
	if err != nil {
		t.Fatal(err)
	}
	session.Lock()

	// Both payloads authenticate under the current audit head. One is not JSON;
	// the other unmarshals and fails validateStored. Each unlock must still
	// append a secret-free denial without moving the authenticated head.
	cases := []struct {
		name  string
		nonce []byte
		data  []byte
	}{
		{name: "invalid json", nonce: badNonce, data: badJSON},
		{name: "invalid stored", nonce: storedNonce, data: badStored},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			copyPath := filepath.Join(t.TempDir(), "vault.db")
			copyFile(t, path, copyPath)
			mutateDB(t, copyPath, func(db *sql.DB) {
				if _, err := db.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=?`, tc.nonce, tc.data); err != nil {
					t.Fatal(err)
				}
			})
			_, err := Unlock(copyPath, pass, log.New(&logs, "", 0))
			if !errors.Is(err, ErrCorrupt) {
				t.Fatal(err)
			}
			if bytes.Contains([]byte(err.Error()), secret) || strings.Contains(err.Error(), string(pass)) {
				t.Fatal("rejection error contains secret material")
			}
			db, header, events, err := loadVault(copyPath)
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			if header.AuditHead != head || header.AuditSeq != seq {
				t.Fatalf("head advanced to %s seq %d", header.AuditHead, header.AuditSeq)
			}
			if len(events) != before+1 {
				t.Fatalf("events %d", len(events))
			}
			last := events[len(events)-1]
			if last.Action != actionUnlock || last.Result != resultDenied || last.CredID != "" || last.CredType != "" {
				t.Fatalf("denial %+v", last)
			}
			if err := suffixAllows(events, header); err != nil {
				t.Fatal(err)
			}
			raw := readAll(t, copyPath)
			assertAbsent(t, raw, secret)
			assertAbsent(t, raw, pass)
		})
	}
	assertAbsent(t, logs.Bytes(), secret)
	assertAbsent(t, logs.Bytes(), pass)
}

func TestCredentialTypesCopyDoesNotChangeAllowlist(t *testing.T) {
	got := CredentialTypes()
	if len(got) == 0 {
		t.Fatal("empty allowlist")
	}
	got[0] = "not-a-type"
	again := CredentialTypes()
	if again[0] == "not-a-type" {
		t.Fatal("CredentialTypes returned the live allowlist")
	}
	if err := validateType("not-a-type"); err == nil {
		t.Fatal("mutated copy accepted by validateType")
	}
	if err := validateType(again[0]); err != nil {
		t.Fatal(err)
	}
}

func TestOutOfRangePassphraseUnlockIsAudited(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, nil)
	session.Lock()
	logger := log.New(&logs, "", 0)
	short := []byte("s3cret!")
	long := bytes.Repeat([]byte("Z"), maxPassphrase+1)
	for _, phrase := range [][]byte{short, long} {
		_, err := Unlock(path, phrase, logger)
		if !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
		if strings.Contains(err.Error(), string(phrase)) {
			t.Fatal("unlock error contains passphrase")
		}
	}
	raw := readAll(t, path)
	assertAbsent(t, raw, short)
	assertAbsent(t, raw, long)
	assertAbsent(t, logs.Bytes(), short)
	assertAbsent(t, logs.Bytes(), long)
	events := mustAudit(t, path)
	var denied int
	for _, ev := range events {
		if ev.Action == actionUnlock && ev.Result == resultDenied {
			denied++
			if ev.CredID != "" || ev.CredType != "" {
				t.Fatal("unlock denial carried credential metadata")
			}
		}
	}
	if denied != 2 {
		t.Fatalf("denied unlocks %d", denied)
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
	opened, err := Unlock(path, pass, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	sealed := 0
	for _, ev := range opened.audit {
		if ev.Action == actionUnlock && ev.Result == resultDenied {
			sealed++
		}
	}
	if sealed != 2 {
		t.Fatalf("incorporated denials %d", sealed)
	}
	if opened.header.AuditSeq <= uint64(sealed) {
		t.Fatal("authenticated head did not advance past denials")
	}
}

func mustCreate(t *testing.T, logger *log.Logger) (string, []byte, *Session) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	pass := []byte(randHex(t, 16))
	session, err := Create(path, pass, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Lock() })
	return path, pass, session
}

func mustOpen(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustAudit(t *testing.T, path string) []auditEvent {
	t.Helper()
	db := mustOpen(t, path)
	events, err := readAuditRows(db)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func mustOne(t *testing.T, s *Session) Credential {
	t.Helper()
	listed, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("count %d", len(listed))
	}
	return listed[0]
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	return hex.EncodeToString(randBytesT(t, n))
}

func randBytesT(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func assertAbsent(t *testing.T, blob, secret []byte) {
	t.Helper()
	if len(secret) == 0 {
		t.Fatal("empty secret")
	}
	if bytes.Contains(blob, secret) {
		t.Fatalf("found %d secret bytes in persisted output", len(secret))
	}
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b := readAll(t, src)
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mutateDB(t *testing.T, path string, fn func(*sql.DB)) {
	t.Helper()
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fn(db)
}

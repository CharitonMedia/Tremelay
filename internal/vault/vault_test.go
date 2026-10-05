package vault

import (
	"bytes"
	"crypto/rand"
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
	defer opened.Lock()
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

	raw := readAll(t, path)
	audit := readAll(t, auditPath(path))
	assertAbsent(t, raw, secret)
	assertAbsent(t, raw, other)
	assertAbsent(t, raw, pass)
	assertAbsent(t, raw, []byte(label))
	assertAbsent(t, audit, secret)
	assertAbsent(t, audit, other)
	assertAbsent(t, audit, pass)
	assertAbsent(t, logs.Bytes(), secret)
	assertAbsent(t, logs.Bytes(), pass)
	if bytes.Contains(raw, opened.dek) {
		t.Fatal("master key persisted")
	}
	head, err := VerifyAudit(path)
	if err != nil || head == "" {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{path, auditPath(path)} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm()&0o077 != 0 {
				t.Fatalf("%s mode %v", p, fi.Mode().Perm())
			}
		}
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
	audit := readAll(t, auditPath(path))
	assertAbsent(t, audit, secret)
	assertAbsent(t, audit, wrong)
	assertAbsent(t, logs.Bytes(), secret)
	assertAbsent(t, logs.Bytes(), wrong)
	if !bytes.Contains(audit, []byte(resultDenied)) {
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
	var sawDenial bool
	for _, ev := range opened.audit {
		if ev.Action == actionUnlock && ev.Result == resultDenied {
			sawDenial = true
		}
	}
	if !sawDenial {
		t.Fatal("denial was not sealed")
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

	dataCopy := filepath.Join(t.TempDir(), "data.json")
	wrapCopy := filepath.Join(t.TempDir(), "wrap.json")
	copyFile(t, pathA, dataCopy)
	copyFile(t, pathA, wrapCopy)
	mutateHeader(t, dataCopy, func(h *fileHeader) {
		h.Data[len(h.Data)-1] ^= 0xff
	})
	_, err := Unlock(dataCopy, passA, nil)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(err.Error()), secretA) || strings.Contains(err.Error(), string(passA)) {
		t.Fatal("tamper error contains secret material")
	}
	mutateHeader(t, wrapCopy, func(h *fileHeader) {
		h.WrappedDEK[len(h.WrappedDEK)-1] ^= 0xff
	})
	_, err = Unlock(wrapCopy, passA, nil)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}

	mutateHeader(t, pathA, func(h *fileHeader) {
		other, readErr := readHeader(pathB)
		if readErr != nil {
			t.Fatal(readErr)
		}
		h.Data = other.Data
		h.DataNonce = other.DataNonce
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
	side, _, err := readAudit(auditPath(path))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := nextEvent(side, actionGet, side[0].VaultID, stored.ID, "bearer_token", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	if err := appendAudit(auditPath(path), forged); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(path); !errors.Is(err, ErrAudit) {
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

func TestMissingSidecarRestored(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	session.Lock()
	if err := os.Remove(auditPath(path)); err != nil {
		t.Fatal(err)
	}
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	opened.Lock()
	if _, err := VerifyAudit(path); err != nil {
		t.Fatal(err)
	}
}

func TestLogRedactsLabelContainingSecret(t *testing.T) {
	var logs bytes.Buffer
	_, _, session := mustCreate(t, log.New(&logs, "", 0))
	secret := []byte(randHex(t, 16))
	label := "pre-" + string(secret) + "-post"
	if _, err := session.Put(label, "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(logs.Bytes(), secret) {
		t.Fatal("log contains secret")
	}
	if !bytes.Contains(logs.Bytes(), []byte(redacted)) {
		t.Fatalf("expected redaction marker in logs")
	}
}

func TestUnlockRoomSurvivesAuditGrowth(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 32)
	stored, err := session.Put("a", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if _, err := session.List(); err != nil {
			t.Fatalf("list %d: %v", i, err)
		}
	}
	before := readAll(t, path)
	floor, err := encodedSize(session.header, session.creds, twoUnlocks(session.audit, session.id))
	if err != nil {
		t.Fatal(err)
	}
	limit := floor
	if len(before) > limit {
		limit = len(before)
	}
	old := maxVaultFile
	t.Cleanup(func() { maxVaultFile = old })
	maxVaultFile = int64(limit)

	big := randBytesT(t, 4096)
	if _, err := session.Put("b", "generic", big, PutOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("put err %v", err)
	}
	if !bytes.Equal(readAll(t, path), before) {
		t.Fatal("rejected put replaced the vault file")
	}
	assertAbsent(t, before, big)

	sideBefore, _, err := readAudit(auditPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.List(); err != nil {
		t.Fatal(err)
	}
	if int64(len(readAll(t, path))) > maxVaultFile {
		t.Fatalf("list wrote %d bytes over %d", len(readAll(t, path)), maxVaultFile)
	}
	session.Lock()

	var opened *Session
	for i := 0; i < 3; i++ {
		opened, err = Unlock(path, pass, nil)
		if err != nil {
			t.Fatalf("unlock %d: %v", i, err)
		}
		if len(opened.creds) != 1 || !bytes.Equal(opened.creds[0].Secret, secret) || opened.creds[0].ID != stored.ID {
			opened.Lock()
			t.Fatal("credential missing after unlock")
		}
		if int64(len(readAll(t, path))) > maxVaultFile {
			opened.Lock()
			t.Fatal("unlock wrote past the read limit")
		}
		opened.Lock()
	}
	if _, err := VerifyAudit(path); err != nil {
		t.Fatal(err)
	}
	sideAfter, _, err := readAudit(auditPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(sideAfter) <= len(sideBefore) {
		t.Fatalf("sidecar shrank: %d -> %d", len(sideBefore), len(sideAfter))
	}
	var unlocks int
	for _, ev := range sideAfter {
		if ev.Action == actionUnlock && ev.Result == resultAllowed {
			unlocks++
		}
	}
	if unlocks < 3 {
		t.Fatalf("allowed unlocks %d", unlocks)
	}
}

func TestPutRejectsGrowthPastReadLimit(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	before := readAll(t, path)
	old := maxVaultFile
	defer func() { maxVaultFile = old }()
	maxVaultFile = int64(len(before))

	secret := randBytesT(t, 64)
	if _, err := session.Put("label", "generic", secret, PutOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if !bytes.Equal(readAll(t, path), before) {
		t.Fatal("rejected put replaced the vault file")
	}
	assertAbsent(t, before, secret)

	maxVaultFile = old
	session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	listed, err := opened.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 0 {
		t.Fatalf("count %d", len(listed))
	}
}

func TestSidecarGapRepairedBeforeNextAppend(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	if _, err := session.Put("a", "generic", randBytesT(t, 16), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	side, exists, err := readAudit(auditPath(path))
	if err != nil || !exists || len(side) < 2 {
		t.Fatalf("sidecar exists=%v len=%d err=%v", exists, len(side), err)
	}
	if err := writeAuditFile(auditPath(path), side[:1]); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Put("b", "password", randBytesT(t, 16), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(path); err != nil {
		t.Fatal(err)
	}
	repaired, _, err := readAudit(auditPath(path))
	if err != nil {
		t.Fatal(err)
	}
	for i, ev := range repaired {
		if ev.Seq != uint64(i+1) {
			t.Fatalf("seq %d at %d", ev.Seq, i)
		}
	}
	if len(repaired) != len(session.audit) {
		t.Fatalf("sidecar %d session %d", len(repaired), len(session.audit))
	}
	session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	listed, err := opened.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("count %d", len(listed))
	}
}

func TestRejectedPutIsAuditedWithoutMetadata(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	secret := randBytesT(t, 24)
	badLabel := "bad-\n" + hex.EncodeToString(secret)
	badType := "not-a-type-" + hex.EncodeToString(secret[:4])
	zero := time.Time{}
	attempts := []struct {
		label, typ string
		secret     []byte
		opt        PutOptions
	}{
		{label: "", typ: "generic", secret: secret},
		{label: badLabel, typ: "generic", secret: secret},
		{label: "ok", typ: badType, secret: secret},
		{label: "ok", typ: "generic", secret: nil},
		{label: "ok", typ: "generic", secret: secret, opt: PutOptions{ExpiresAt: &zero}},
	}
	for _, attempt := range attempts {
		if _, err := session.Put(attempt.label, attempt.typ, attempt.secret, attempt.opt); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	audit := readAll(t, auditPath(path))
	assertAbsent(t, audit, secret)
	assertAbsent(t, logs.Bytes(), secret)
	if bytes.Contains(audit, []byte(badLabel)) || bytes.Contains(audit, []byte(badType)) || bytes.Contains(logs.Bytes(), []byte(badLabel)) {
		t.Fatal("denial recorded free-form metadata")
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
	stored, err := session.Put("ok", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
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
		t.Fatal("secret mismatch after denied puts")
	}
	sealed := 0
	for _, ev := range opened.audit {
		if ev.Action == actionPut && ev.Result == resultDenied {
			sealed++
		}
	}
	if sealed != len(attempts) {
		t.Fatalf("sealed denials %d", sealed)
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
	audit := readAll(t, auditPath(path))
	assertAbsent(t, audit, short)
	assertAbsent(t, audit, long)
	assertAbsent(t, logs.Bytes(), short)
	assertAbsent(t, logs.Bytes(), long)
	side, _, err := readAudit(auditPath(path))
	if err != nil {
		t.Fatal(err)
	}
	var denied int
	for _, ev := range side {
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
		t.Fatalf("sealed denials %d", sealed)
	}
}

func mustCreate(t *testing.T, logger *log.Logger) (string, []byte, *Session) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.json")
	pass := []byte(randHex(t, 16))
	session, err := Create(path, pass, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Lock() })
	return path, pass, session
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

func mutateHeader(t *testing.T, path string, fn func(*fileHeader)) {
	t.Helper()
	b := readAll(t, path)
	var header fileHeader
	if err := unmarshalStrict(b, &header); err != nil {
		t.Fatal(err)
	}
	fn(&header)
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

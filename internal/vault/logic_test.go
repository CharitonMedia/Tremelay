package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAuditHashVector(t *testing.T) {
	prev := make([]byte, 32)
	sum := eventHash(prev, 1, "2026-01-01T00:00:00Z", actionCreate, "abc", "", "", resultAllowed)
	got := hex.EncodeToString(sum)
	const want = "5e042f2a7cc66219aed0043ef67661d5d872a357d6c1106054b455bba75ffed5"
	if got != want {
		t.Fatalf("hash vector changed: %s", got)
	}
}

func TestVerifyChainRejectsTamper(t *testing.T) {
	ev, err := nextEvent(nil, actionCreate, "abc", "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChain([]auditEvent{ev}); err != nil {
		t.Fatal(err)
	}
	ev.Result = resultDenied
	if err := verifyChain([]auditEvent{ev}); !errors.Is(err, ErrAudit) {
		t.Fatalf("tampered event: %v", err)
	}
}

func TestSuffixAllowsDenialOnly(t *testing.T) {
	id := strings.Repeat("ab", 16)
	create, err := nextEvent(nil, actionCreate, id, "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	denial, err := nextEvent([]auditEvent{create}, actionUnlock, id, "", "", resultDenied)
	if err != nil {
		t.Fatal(err)
	}
	header := fileHeader{ID: id, AuditHead: create.Hash, AuditSeq: create.Seq}
	if err := suffixAllows([]auditEvent{create, denial}, header); err != nil {
		t.Fatal(err)
	}
	forged, err := nextEvent([]auditEvent{create}, actionGet, id, "id", "api_key", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChain([]auditEvent{create, forged}); err != nil {
		t.Fatal(err)
	}
	if err := suffixAllows([]auditEvent{create, forged}, header); !errors.Is(err, ErrAudit) {
		t.Fatalf("forged allow: %v", err)
	}
	tagged, err := nextEvent([]auditEvent{create}, actionUnlock, id, strings.Repeat("cd", 16), "bearer_token", resultDenied)
	if err != nil {
		t.Fatal(err)
	}
	if err := suffixAllows([]auditEvent{create, tagged}, header); !errors.Is(err, ErrAudit) {
		t.Fatalf("tagged denial: %v", err)
	}
	idOnly, err := nextEvent([]auditEvent{create}, actionUnlock, id, strings.Repeat("ef", 16), "", resultDenied)
	if err != nil {
		t.Fatal(err)
	}
	if err := suffixAllows([]auditEvent{create, idOnly}, header); !errors.Is(err, ErrAudit) {
		t.Fatalf("id-only denial: %v", err)
	}
}

func TestRedactorHidesSecretAndPassphrase(t *testing.T) {
	secret := randBytesT(t, 24)
	pass := randBytesT(t, 24)
	var r Redactor
	r.Add(secret)
	r.Add(pass)
	msg := r.Redact("failed " + string(secret) + " using " + string(pass))
	if strings.Contains(msg, string(secret)) || strings.Contains(msg, string(pass)) {
		t.Fatal("redactor left secret material in place")
	}
	if !strings.Contains(msg, redacted) {
		t.Fatalf("redactor output = %q", msg)
	}
	var buf bytes.Buffer
	if _, err := (RedactingWriter{Dst: &buf, Redactor: &r}).Write([]byte("log " + string(secret))); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), secret) {
		t.Fatal("writer left secret material in place")
	}
}

func TestRedactorMatchesLongerSecretFirst(t *testing.T) {
	short := []byte("x")
	long := []byte("xSUPERSECRET")
	for _, order := range [][][]byte{{short, long}, {long, short}} {
		var r Redactor
		for _, secret := range order {
			r.Add(secret)
		}
		got := r.Redact("label " + string(long) + " tail")
		if strings.Contains(got, "SUPERSECRET") || strings.Contains(got, string(long)) {
			t.Fatalf("order %q leaked: %q", order, got)
		}
		if got != "label "+redacted+" tail" {
			t.Fatalf("order %q got %q", order, got)
		}
	}
}

func TestProductionKDFParams(t *testing.T) {
	if prodMemory != 64*1024 || prodTime != 3 || prodThreads != 4 || keyLen != 32 || saltLen != 16 {
		t.Fatalf("production KDF drifted from RFC 9106 second recommendation")
	}
	if algoArgon2id != "argon2id" {
		t.Fatal(algoArgon2id)
	}
}

func TestNoGetSecretMethod(t *testing.T) {
	typ := reflect.TypeOf(&Session{})
	for i := 0; i < typ.NumMethod(); i++ {
		name := strings.ToLower(typ.Method(i).Name)
		if strings.Contains(name, "getsecret") {
			t.Fatal(typ.Method(i).Name)
		}
	}
}

func TestShortPassphraseRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	if _, err := Create(path, []byte("short"), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestCreateRejectsPassphraseInAuditPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	for _, pass := range []string{"vault_create", "vault_unlock", "password", "credential"} {
		_, err := Create(path, []byte(pass), nil)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", pass, err)
		}
		if strings.Contains(err.Error(), pass) {
			t.Fatalf("%s echoed passphrase", pass)
		}
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s left a vault file", pass)
		}
	}
}

func TestAuditPlaintextContainment(t *testing.T) {
	ev := auditEvent{
		Action:  actionCreate,
		Result:  resultAllowed,
		VaultID: "0123456789abcdef0123456789abcdef",
		Time:    "2026-10-05T18:22:10Z",
		Hash:    strings.Repeat("ab", 32),
	}
	for _, secret := range []string{"allow", "api", "01234567", "2026-10-", "vault_create"} {
		if !secretDisclosedByAudit([]byte(secret), nil, ev) {
			t.Fatalf("accepted %q", secret)
		}
	}
	prior := auditEvent{CredID: "abcdef0123456789abcdef0123456789", CredType: "generic", Action: actionPut, Result: resultAllowed}
	if !secretDisclosedByAudit([]byte("abcdef01"), []auditEvent{prior}, ev) {
		t.Fatal("accepted prior id prefix")
	}
	if secretDisclosedByAudit(nil, nil, ev) {
		t.Fatal("empty secret")
	}
	if secretDisclosedByAudit([]byte("qqqqqqqq"), nil, ev) {
		t.Fatal("rejected unrelated secret")
	}
}

func TestTruncatedVaultRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	pass := randBytesT(t, 16)
	_, err := Unlock(path, pass, nil)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(err.Error()), pass) {
		t.Fatal("error contains passphrase")
	}
}

func TestHostileKDFRejectedWithoutDerivation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	db, err := createDB(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO vault (
		id, format_version, root, kdf_algorithm, kdf_salt, kdf_time, kdf_memory, kdf_threads, kdf_key_len,
		wrap_nonce, wrapped_dek, data_nonce, encrypted_document, audit_head, audit_seq
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.Repeat("ab", 16), formatVersion, rootPassphrase, algoArgon2id, bytes.Repeat([]byte{7}, 16),
		3, int64(1)<<31, 4, keyLen,
		bytes.Repeat([]byte{1}, nonceLen), bytes.Repeat([]byte{2}, keyLen+16),
		bytes.Repeat([]byte{3}, nonceLen), bytes.Repeat([]byte{4}, 32),
		strings.Repeat("cd", 32), 1,
	)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	pass := randBytesT(t, 16)
	_, err = Unlock(path, pass, nil)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(err.Error()), pass) {
		t.Fatal("error contains passphrase")
	}
}

func TestDatabasePragmasAndExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	db, err := createDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	dsn, err := sqliteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dsn, "mode=rw") || strings.Contains(dsn, "mode=rwc") {
		t.Fatal(dsn)
	}
	opened, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertDurable(opened); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	opened.Close()
	if _, err := createDB(path); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.db")
	if _, err := Unlock(missing, randBytesT(t, 16), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unlock created a database")
	}
}

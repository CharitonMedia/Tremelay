package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestReconcileDenialAndForgery(t *testing.T) {
	create, err := nextEvent(nil, actionCreate, "vault", "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	sealed := []auditEvent{create}
	denial, err := nextEvent(sealed, actionUnlock, "vault", "", "", resultDenied)
	if err != nil {
		t.Fatal(err)
	}
	withDenial := []auditEvent{create, denial}
	merged, err := reconcile(sealed, withDenial, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 2 || merged[1].Result != resultDenied {
		t.Fatalf("denial suffix not kept")
	}
	forged, err := nextEvent(sealed, actionGet, "vault", "id", "api_key", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconcile(sealed, []auditEvent{create, forged}, true); !errors.Is(err, ErrAudit) {
		t.Fatalf("forged allow: %v", err)
	}
	restored, err := reconcile(sealed, nil, false)
	if err != nil || len(restored) != 1 {
		t.Fatalf("missing sidecar: %v len %d", err, len(restored))
	}
}

func TestReconcileSealedSuffix(t *testing.T) {
	create, err := nextEvent(nil, actionCreate, "vault", "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := nextEvent([]auditEvent{create}, actionList, "vault", "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	third, err := nextEvent([]auditEvent{create, second}, actionUnlock, "vault", "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	full := []auditEvent{create, second, third}
	suffix := full[1:]
	merged, err := reconcile(suffix, full, true)
	if err != nil || len(merged) != len(full) || merged[2].Hash != third.Hash {
		t.Fatalf("suffix merge: %v len %d", err, len(merged))
	}
	partial, err := reconcile(suffix, full[:2], true)
	if err != nil || len(partial) != len(full) || partial[2].Hash != third.Hash {
		t.Fatalf("overlap restore: %v", err)
	}
	if _, err := reconcile(suffix, nil, false); !errors.Is(err, ErrAudit) {
		t.Fatalf("missing sidecar after drop: %v", err)
	}
	if _, err := reconcile(full[2:], full[:1], true); !errors.Is(err, ErrAudit) {
		t.Fatal("sealed gap was accepted")
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

func TestUnlockProbeCoversRealEvent(t *testing.T) {
	id := strings.Repeat("ab", 16)
	create, err := nextEvent(nil, actionCreate, id, "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := nextEvent([]auditEvent{create}, actionUnlock, id, "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	probe := unlockProbe([]auditEvent{create}, id)
	got, err := json.Marshal(unlock)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > len(want) {
		t.Fatalf("probe %d bytes is smaller than a real unlock %d: %s", len(want), len(got), got)
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
	path := t.TempDir() + "/vault.json"
	if _, err := Create(path, []byte("short"), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestTruncatedVaultRejected(t *testing.T) {
	path := t.TempDir() + "/vault.json"
	if err := writeAtomic(path, []byte("{")); err != nil {
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
	path := t.TempDir() + "/vault.json"
	header := fileHeader{
		Version:    formatVersion,
		ID:         strings.Repeat("ab", 16),
		Root:       rootPassphrase,
		KDF:        kdfParams{Algorithm: algoArgon2id, Salt: bytes.Repeat([]byte{7}, 16), Time: 3, Memory: 1 << 31, Threads: 4, KeyLen: keyLen},
		WrapNonce:  bytes.Repeat([]byte{1}, nonceLen),
		WrappedDEK: bytes.Repeat([]byte{2}, keyLen+16),
		DataNonce:  bytes.Repeat([]byte{3}, nonceLen),
		Data:       bytes.Repeat([]byte{4}, 32),
		AuditHead:  strings.Repeat("cd", 32),
		AuditSeq:   1,
	}
	raw, err := jsonMarshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, raw); err != nil {
		t.Fatal(err)
	}
	_, err = Unlock(path, randBytesT(t, 16), nil)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
}

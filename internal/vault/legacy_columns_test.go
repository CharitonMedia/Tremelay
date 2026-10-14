package vault

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// TestPre3eVaultUnlocksAndBacksUp: a vault written before the DEK handoff
// columns existed is an intact vault. Verify and backup read it without
// writing, unlock migrates it, and a backup taken before the migration restores.
func TestPre3eVaultUnlocksAndBacksUp(t *testing.T) {
	// Backup and Restore refuse symlinked ancestors (macOS /var).
	path := filepath.Join(canonicalTemp(t), "vault.db")
	pass := []byte(randHex(t, 16))
	s, err := Create(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("pre3e-" + randHex(t, 12))
	cred, err := s.Put("api", "api_key", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s.Lock()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"dek_reload_pubkey", "dek_handoff_nonce", "dek_handoff"} {
		if _, err := raw.Exec(`ALTER TABLE vault DROP COLUMN ` + col); err != nil {
			t.Fatal(err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatalf("verify pre-3e vault: %v", err)
	}
	artifact := filepath.Join(canonicalTemp(t), "pre3e.backup")
	cp, err := Backup(path, artifact, pass, nil)
	if err != nil {
		t.Fatalf("backup pre-3e vault: %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("read-only paths wrote the pre-3e vault")
	}
	u, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatalf("unlock pre-3e vault: %v", err)
	}
	got, err := u.Get(cred.ID)
	if err != nil || !bytes.Equal(got.Secret, secret) {
		t.Fatalf("credential after migration: %v", err)
	}
	u.Lock()
	restored := filepath.Join(canonicalTemp(t), "restored.db")
	if err := Restore(artifact, restored, pass, cp, nil); err != nil {
		t.Fatalf("restore pre-3e artifact: %v", err)
	}
	r, err := Unlock(restored, pass, nil)
	if err != nil {
		t.Fatalf("unlock restored pre-3e artifact: %v", err)
	}
	r.Lock()
}

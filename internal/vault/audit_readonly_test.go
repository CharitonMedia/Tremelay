package vault

import (
	"bytes"
	"errors"
	"testing"
)

func TestVerifyAuditReadOnlyCompatibility(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	if _, err := session.CreateAgent("legacy"); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	rewriteAudit(t, path, true)
	before := readAll(t, path)
	db, _, events, err := loadVaultForVerify(path)
	if err != nil {
		t.Fatal(err)
	}
	var queryOnly int
	if err := db.QueryRow(`PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly != 1 {
		t.Fatalf("query_only=%d: %v", queryOnly, err)
	}
	if _, err := db.Exec(`UPDATE audit SET result='denied' WHERE seq=1`); err == nil {
		t.Fatal("verification connection accepted a write")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if events[0].V != auditVersion || events[len(events)-1].V != auditCapabilityVersion {
		t.Fatal("legacy versions were not inferred from their actions")
	}
	if strict, _, _, err := loadVaultRead(path); !errors.Is(err, ErrCorrupt) {
		if strict != nil {
			strict.Close()
		}
		t.Fatalf("backup artifact reader accepted legacy schema: %v", err)
	}
	if tip, err := VerifyAudit(path, pass); err != nil || tip != events[len(events)-1].Hash {
		t.Fatalf("legacy verify: %v", err)
	}
	if !bytes.Equal(before, readAll(t, path)) {
		t.Fatal("read-only verification changed legacy bytes")
	}
	// The writable unlock retains migration and its failed-auth audit event.
	if _, err := Unlock(path, []byte(randHex(t, 16)), nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unlock denial: %v", err)
	}
	if bytes.Equal(before, readAll(t, path)) {
		t.Fatal("ordinary failed unlock did not record its denial")
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatalf("verify locked-denial suffix: %v", err)
	}
}

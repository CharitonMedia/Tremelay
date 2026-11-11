package vault

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestOpenBusyIsNotCorruption is the regression test for a human CLI command
// that reported "vault data is corrupt or tampered" because a daemon held the
// file's lock for longer than one busy_timeout while the command opened it.
func TestOpenBusyIsNotCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	holder, err := createDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	ctx := context.Background()
	conn, err := holder.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	// Longer than one busy_timeout (5s), so a single attempt cannot succeed.
	release := time.AfterFunc(6*time.Second, func() { _, _ = conn.ExecContext(ctx, `ROLLBACK`) })
	defer release.Stop()
	db, err := openDB(path)
	if err != nil {
		t.Fatalf("open of a vault another process had locked: %v", err)
	}
	db.Close()
}

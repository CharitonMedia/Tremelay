package vault

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

// A session whose file was swapped out from under it can never serve again.
// It must say so and retire, so a daemon locks and exits. It used to answer
// every call with a plain IO error, forever, and stay unlocked.
func TestReplacedVaultFileRetiresTheSession(t *testing.T) {
	t.Run("another file renamed over the path", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("an open file cannot be renamed over on Windows")
		}
		path, pass, s := mustCreate(t, nil)
		defer s.Lock()
		older, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.List(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".old", older, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".old", path); err != nil {
			t.Fatal(err)
		}
		if _, err := s.List(); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("first call after the rename: %v, want ErrCorrupt", err)
		}
		if _, err := s.List(); !errors.Is(err, ErrStale) {
			t.Fatalf("retired session: %v, want ErrStale", err)
		}
		// The file that is there now is a valid vault for a fresh unlock.
		fresh, err := Unlock(path, pass, nil)
		if err != nil {
			t.Fatal(err)
		}
		fresh.Lock()
	})
	t.Run("another vault's bytes written in place", func(t *testing.T) {
		path, _, s := mustCreate(t, nil)
		defer s.Lock()
		other, _, s2 := mustCreate(t, nil)
		// Give the other vault a different length of history, so SQLite's
		// change counter differs and it re-reads the file.
		for i := 0; i < 3; i++ {
			if _, err := s2.List(); err != nil {
				t.Fatal(err)
			}
		}
		s2.Lock()
		foreign, err := os.ReadFile(other)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, foreign, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.List(); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("first call after the overwrite: %v, want ErrCorrupt", err)
		}
		if _, err := s.List(); !errors.Is(err, ErrStale) {
			t.Fatalf("retired session: %v, want ErrStale", err)
		}
	})
	t.Run("a removed file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("an open file cannot be removed on Windows")
		}
		path, _, s := mustCreate(t, nil)
		defer s.Lock()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		// SQLite can keep serving reads from the unlinked file. Whenever it
		// does fail, the failure must be terminal, not an IO error.
		for i := 0; i < 3; i++ {
			if _, err := s.List(); err != nil && !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrStale) {
				t.Fatalf("call %d on a removed vault: %v", i, err)
			}
		}
	})
}

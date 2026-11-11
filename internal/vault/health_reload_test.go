package vault

import (
	"bytes"
	"errors"
	"testing"
)

type reentrantChecker struct {
	t    *testing.T
	s    *Session
	path string
	done bool
}

func (c *reentrantChecker) Lookup(CompromiseQuery) ([]string, error) {
	if !c.done {
		c.done = true
		// Another process: a mistyped `tremelay` unlock appends a locked denial.
		db, err := openDB(c.path)
		if err != nil {
			c.t.Fatal(err)
		}
		if err := appendDenial(db, c.s.id); err != nil {
			c.t.Fatal(err)
		}
		db.Close()
		// Another caller of the same resident session enters while the
		// lock is released for the lookup (e.g. any agent request).
		if err := c.s.SetNotifier(nil); err != nil {
			c.t.Fatalf("concurrent entrant: %v", err)
		}
	}
	return nil, nil
}

// A reload while the lock is released for the breach lookup zeroes the secrets
// the refresh plan shares. The plan must be dropped, not committed: committing
// it stored every credential as zeroes, for good.
func TestReloadDuringCompromiseLookupKeepsSecrets(t *testing.T) {
	path, pass, s := mustCreate(t, nil)
	secret := []byte("correct-horse-battery-staple-" + randHex(t, 8))
	c, err := s.Put("pw", "password", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pol := HealthPolicy{MinPasswordLength: 12, PatternRun: 4, Freshness: 24 * 3600e9, ReminderLead: 0, CompromiseOptIn: true}
	if err := s.SetHealthPolicy(pol); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCompromiseChecker(&reentrantChecker{t: t, s: s, path: path}); err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshHealth(c.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("refresh across a reload: %v, want ErrConflict", err)
	}
	s.Lock()
	u, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Lock()
	got, err := u.Get(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, secret) {
		t.Fatalf("stored secret changed: len=%d allzero=%v", len(got.Secret), bytes.Count(got.Secret, []byte{0}) == len(got.Secret))
	}
}

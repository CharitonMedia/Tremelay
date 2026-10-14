package vault

import (
	"bytes"
	"errors"
	"log"
	"path/filepath"
	"reflect"
	"testing"
)

func TestChangePassphraseRewrapAndSnapshot(t *testing.T) {
	var logs bytes.Buffer
	path, oldPass, s := mustCreate(t, log.New(&logs, "", 0))
	defer s.Lock()
	path = canonicalExisting(t, path)
	secret := randBytesT(t, 32)
	cred, err := s.Put("synthetic", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The snapshot is deliberately made before the change. Its wrap must stay old.
	artifact := filepath.Join(filepath.Dir(path), "before-change.db")
	cp, err := Backup(path, artifact, oldPass, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := readAll(t, artifact)
	header, dek := s.header, append([]byte(nil), s.dek...)
	defer wipe(dek)
	newPass := []byte(randHex(t, 24))
	if err := s.ChangePassphrase(oldPass, newPass); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s.dek, dek) {
		t.Fatal("passphrase change did not rotate DEK")
	}
	if bytes.Equal(s.header.KDF.Salt, header.KDF.Salt) || bytes.Equal(s.header.WrapNonce, header.WrapNonce) || bytes.Equal(s.header.WrappedDEK, header.WrappedDEK) {
		t.Fatal("wrap was not refreshed")
	}
	if s.header.KDF.Time != prodTime || s.header.KDF.Memory != prodMemory || s.header.KDF.Threads != prodThreads {
		t.Fatal("unexpected KDF parameters")
	}
	row := s.audit[len(s.audit)-1]
	if row.Action != actionPassphrase || row.Result != resultAllowed || row.Seq != header.AuditSeq+1 || row.CredID != "" || row.CredType != "" {
		t.Fatal("missing fixed passphrase change audit event")
	}
	if _, err := VerifyAudit(path, oldPass); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old pass accepted: %v", err)
	}
	if _, err := VerifyAudit(path, newPass); err != nil {
		t.Fatal(err)
	}
	// A later ordinary state commit must keep the new wrap.
	if _, err := s.CreateAgent("synthetic agent"); err != nil {
		t.Fatal(err)
	}
	s.Lock()
	opened, err := Unlock(path, newPass, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := opened.Get(cred.ID)
	if err != nil || !bytes.Equal(got.Secret, secret) {
		t.Fatalf("credential lost: %v", err)
	}
	wipe(got.Secret)
	opened.Lock()
	if _, err := VerifyAudit(path, oldPass); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("ordinary write restored old authority")
	}
	restored := filepath.Join(filepath.Dir(path), "restored-before-change.db")
	if err := Restore(artifact, restored, oldPass, cp, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(restored, newPass); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("new pass opened old snapshot")
	}
	if !bytes.Equal(before, readAll(t, artifact)) {
		t.Fatal("passphrase change rewrote existing snapshot")
	}
	for _, b := range [][]byte{readAll(t, path), readAll(t, restored), logs.Bytes()} {
		for _, forbidden := range [][]byte{oldPass, newPass, secret, dek} {
			assertAbsent(t, b, forbidden)
		}
	}
}

func TestChangePassphraseFailurePreservesAuthority(t *testing.T) {
	path, oldPass, s := mustCreate(t, nil)
	defer s.Lock()
	newPass := []byte(randHex(t, 24))
	for _, tc := range []struct {
		name      string
		old, next []byte
		want      error
	}{
		{"wrong old", []byte(randHex(t, 24)), newPass, ErrUnauthenticated},
		{"invalid old", nil, newPass, ErrInvalid},
		{"short new", oldPass, []byte("short"), ErrInvalid},
		{"long new", oldPass, randBytesT(t, maxPassphrase+1), ErrInvalid},
		{"unchanged", oldPass, oldPass, ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := s.header
			if err := s.ChangePassphrase(tc.old, tc.next); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s.header.KDF, before.KDF) || !bytes.Equal(s.header.WrapNonce, before.WrapNonce) || !bytes.Equal(s.header.WrappedDEK, before.WrappedDEK) {
				t.Fatal("denial changed wrap")
			}
			row := s.audit[len(s.audit)-1]
			if row.Action != actionPassphrase || row.Result != resultDenied {
				t.Fatal("missing denial")
			}
			if _, err := VerifyAudit(path, oldPass); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyAudit(path, newPass); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("failure granted new authority")
			}
		})
	}
	t.Run("transaction rollback", func(t *testing.T) {
		before, header, seq := readAll(t, path), s.header, len(s.audit)
		s.commitFault = func() error { return errors.New("synthetic transaction failure") }
		if err := s.ChangePassphrase(oldPass, newPass); !errors.Is(err, ErrAudit) {
			t.Fatal(err)
		}
		s.commitFault = nil
		if !bytes.Equal(before, readAll(t, path)) || !reflect.DeepEqual(header, s.header) || len(s.audit) != seq {
			t.Fatal("failed commit changed durable or cached state")
		}
		if _, err := VerifyAudit(path, oldPass); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyAudit(path, newPass); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("failed transaction granted authority")
		}
		if err := s.ChangePassphrase(oldPass, newPass); err != nil {
			t.Fatalf("retry: %v", err)
		}
	})
	s.Lock()
	if err := s.ChangePassphrase(newPass, oldPass); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
}

func TestChangePassphraseStaleSession(t *testing.T) {
	for _, rewrap := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary write", true: "rewrap"}[rewrap], func(t *testing.T) {
			path, oldPass, stale := mustCreate(t, nil)
			defer stale.Lock()
			current, err := Unlock(path, oldPass, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer current.Lock()
			newPass := []byte(randHex(t, 24))
			if err := current.ChangePassphrase(oldPass, newPass); err != nil {
				t.Fatal(err)
			}
			// Since V1.md item 3d the session that lost this race adopts the
			// newer wrap at its next entry point instead of refusing every
			// later call. The property that matters is unchanged and is what
			// the checks below assert: the old passphrase is never revived,
			// and no write puts the old wrap back on the file.
			if rewrap {
				// The adopted wrap is the new one, so the old passphrase no
				// longer authenticates a further change.
				if err := stale.ChangePassphrase(oldPass, []byte(randHex(t, 24))); !errors.Is(err, ErrUnauthenticated) {
					t.Fatalf("stale rewrap: %v", err)
				}
			} else if _, err := stale.CreateAgent("stale"); err != nil {
				t.Fatalf("adopted write: %v", err)
			}
			if _, err := VerifyAudit(path, newPass); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyAudit(path, oldPass); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("old pass revived")
			}
		})
	}
}

package vault

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestChangePassphraseOldWrappedDEKCannotDecryptPostChange(t *testing.T) {
	path, oldPass, s := mustCreate(t, nil)
	defer s.Lock()
	secret := randBytesT(t, 32)
	if _, err := s.Put("rotate-target", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	beforeWrap := passphraseWrap{
		kdf:        s.header.KDF,
		nonce:      append([]byte(nil), s.header.WrapNonce...),
		ciphertext: append([]byte(nil), s.header.WrappedDEK...),
	}
	beforeDEK := append([]byte(nil), s.dek...)
	defer wipe(beforeDEK)
	newPass := []byte(randHex(t, 24))
	if err := s.ChangePassphrase(oldPass, newPass); err != nil {
		t.Fatal(err)
	}
	after, err := readHeaderFile(path)
	if err != nil {
		t.Fatal(err)
	}
	kek := deriveKEK(oldPass, beforeWrap.kdf)
	defer wipe(kek)
	staleDEK, err := openAEAD(kek, beforeWrap.nonce, beforeWrap.ciphertext, dekAAD(s.id))
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(staleDEK)
	if !bytes.Equal(staleDEK, beforeDEK) {
		t.Fatal("pre-change wrap did not open the old DEK")
	}
	if _, err := openAEAD(staleDEK, after.DataNonce, after.Data, dataAAD(after.ID, after.AuditHead, after.AuditSeq)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("old DEK decrypted post-change ciphertext: %v", err)
	}
	if len(after.DEKHandoff) != 0 {
		t.Fatal("passphrase change wrote a DEK handoff")
	}
	opened, err := Unlock(path, newPass, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := opened.Get(mustOne(t, opened).ID)
	if err != nil || !bytes.Equal(got.Secret, secret) {
		t.Fatalf("new authority lost credential: %v", err)
	}
	wipe(got.Secret)
	opened.Lock()
}

func TestChangePassphraseCrashRecovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inject  func(*Session)
		wantOld bool
	}{
		{
			name: "before commit",
			inject: func(s *Session) {
				s.commitFault = func() error { return errors.New("synthetic transaction failure") }
			},
			wantOld: true,
		},
		{
			name: "mid reseal",
			inject: func(s *Session) {
				s.rotateFault = func(step string) error {
					if step == "reseal" {
						return errors.New("synthetic reseal failure")
					}
					return nil
				}
			},
			wantOld: true,
		},
		{
			name: "after commit",
			inject: func(s *Session) {
				s.postCommitFault = func() error { return errors.New("synthetic post-commit failure") }
			},
			wantOld: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, oldPass, s := mustCreate(t, nil)
			secret := randBytesT(t, 32)
			cred, err := s.Put("crash", "generic", secret, PutOptions{})
			if err != nil {
				t.Fatal(err)
			}
			before := readAll(t, path)
			header := s.header
			dek := append([]byte(nil), s.dek...)
			defer wipe(dek)
			newPass := []byte(randHex(t, 24))
			tc.inject(s)
			err = s.ChangePassphrase(oldPass, newPass)
			s.commitFault = nil
			s.rotateFault = nil
			s.postCommitFault = nil
			if err == nil {
				t.Fatal("expected injected failure")
			}
			after := readAll(t, path)
			if tc.wantOld {
				if !bytes.Equal(before, after) {
					t.Fatal("failed change altered durable state")
				}
				if !reflect.DeepEqual(header, s.header) || !bytes.Equal(dek, s.dek) {
					t.Fatal("failed change altered cached wrap or DEK")
				}
				if _, err := VerifyAudit(path, oldPass); err != nil {
					t.Fatal(err)
				}
				if _, err := VerifyAudit(path, newPass); !errors.Is(err, ErrUnauthenticated) {
					t.Fatal("failure granted new authority")
				}
				got, err := s.Get(cred.ID)
				if err != nil || !bytes.Equal(got.Secret, secret) {
					t.Fatalf("old session lost credential: %v", err)
				}
				wipe(got.Secret)
				return
			}
			if bytes.Equal(before, after) {
				t.Fatal("successful commit left durable state unchanged")
			}
			if _, err := VerifyAudit(path, oldPass); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("post-change vault still accepts old passphrase")
			}
			if _, err := VerifyAudit(path, newPass); err != nil {
				t.Fatal(err)
			}
			s.Lock()
			opened, err := Unlock(path, newPass, nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := opened.Get(cred.ID)
			if err != nil || !bytes.Equal(got.Secret, secret) {
				t.Fatalf("new authority lost credential: %v", err)
			}
			wipe(got.Secret)
			opened.Lock()
			if _, err := VerifyAudit(path, oldPass); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("old passphrase revived")
			}
		})
	}
}

// TestSessionLocksOnPassphraseRotation is V1 item 3g: a resident session
// never adopts a rotated DEK. It zeroises, records the refusal as a
// vault_unlock denial, signals Rekeyed, and the new passphrase opens the
// vault with everything in it.
func TestSessionLocksOnPassphraseRotation(t *testing.T) {
	for _, planted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "planted handoff"}[planted], func(t *testing.T) {
			path, oldPass, resident := mustCreate(t, nil)
			defer resident.Lock()
			secret := randBytesT(t, 32)
			cred, err := resident.Put("relock", "generic", secret, PutOptions{})
			if err != nil {
				t.Fatal(err)
			}
			control, err := Unlock(path, oldPass, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Lock()
			newPass := []byte(randHex(t, 24))
			if err := control.ChangePassphrase(oldPass, newPass); err != nil {
				t.Fatal(err)
			}
			if planted {
				// A 3e-style handoff left in the file is never opened.
				db, err := openDB(path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`UPDATE vault SET dek_handoff = randomblob(?)`, minDEKHandoffLen()); err != nil {
					t.Fatal(err)
				}
				db.Close()
			}
			if _, err := resident.Get(cred.ID); !errors.Is(err, ErrStale) {
				t.Fatalf("resident after rotation: %v", err)
			}
			select {
			case <-resident.Rekeyed():
			default:
				t.Fatal("Rekeyed not signalled")
			}
			if resident.dek != nil || resident.creds != nil {
				t.Fatal("resident kept key material after rotation")
			}
			if _, err := resident.Get(cred.ID); !errors.Is(err, ErrStale) {
				t.Fatalf("second call: %v", err)
			}
			if planted {
				return // the planted column is not a valid vault; the lock is the point
			}
			rows := mustAudit(t, path)
			last := rows[len(rows)-1]
			if last.Action != actionUnlock || last.Result != resultDenied || rows[len(rows)-2].Action != actionPassphrase {
				t.Fatalf("refused resident key not audited: %+v", last)
			}
			if _, err := VerifyAudit(path, newPass); err != nil {
				t.Fatal(err)
			}
			opened, err := Unlock(path, newPass, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Lock()
			got, err := opened.Get(cred.ID)
			if err != nil || !bytes.Equal(got.Secret, secret) {
				t.Fatalf("new passphrase lost credential: %v", err)
			}
			wipe(got.Secret)
		})
	}
}

// TestChangePassphraseIgnoresLegacyReloadKey: a 3e document may still carry a
// daemon reload public key. Nothing is sealed to it any more.
func TestChangePassphraseIgnoresLegacyReloadKey(t *testing.T) {
	path, oldPass, s := mustCreate(t, nil)
	defer s.Lock()
	s.dekReloadPubKey = randBytesT(t, 32)
	if err := s.ChangePassphrase(oldPass, []byte(randHex(t, 24))); err != nil {
		t.Fatal(err)
	}
	after, err := readHeaderFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.DEKHandoff) != 0 {
		t.Fatal("passphrase change sealed a handoff to a legacy reload key")
	}
}

func readHeaderFile(path string) (fileHeader, error) {
	db, err := openDBRead(path)
	if err != nil {
		return fileHeader{}, err
	}
	defer db.Close()
	if err := vaultHandoffReady(db); err != nil {
		return fileHeader{}, err
	}
	return readVaultRow(db)
}

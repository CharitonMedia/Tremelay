package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestChangePassphraseOldWrappedDEKCannotDecryptPostChange(t *testing.T) {
	path, oldPass, s := mustCreate(t, nil)
	defer s.Lock()
	secret := randBytesT(t, 32)
	if _, err := s.Put("rotate-target", "generic", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishDaemonReloadPubKey(); err != nil {
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
		attackerPub, attackerPriv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var pub [32]byte
		copy(pub[:], after.DEKReloadPubKey)
		if plain, ok := box.OpenAnonymous(nil, after.DEKHandoff, &pub, attackerPriv); ok {
			wipe(plain)
			t.Fatal("foreign private key opened DEK handoff")
		}
		if _, err := openDEKHandoffReload(attackerPriv, after); err == nil {
			t.Fatal("wrong reload key recovered DEK handoff")
		}
		_ = attackerPub
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

func TestSessionReloadAdoptsPassphraseRotation(t *testing.T) {
	path, oldPass, resident := mustCreate(t, nil)
	defer resident.Lock()
	secret := randBytesT(t, 32)
	cred, err := resident.Put("reload", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := resident.PublishDaemonReloadPubKey(); err != nil {
		t.Fatal(err)
	}
	oldDEK := append([]byte(nil), resident.dek...)
	defer wipe(oldDEK)
	control, err := Unlock(path, oldPass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Lock()
	newPass := []byte(randHex(t, 24))
	if err := control.ChangePassphrase(oldPass, newPass); err != nil {
		t.Fatal(err)
	}
	got, err := resident.Get(cred.ID)
	if err != nil || !bytes.Equal(got.Secret, secret) {
		t.Fatalf("resident session did not reload after passphrase rotation: %v", err)
	}
	wipe(got.Secret)
	if bytes.Equal(resident.dek, oldDEK) || !bytes.Equal(resident.dek, control.dek) {
		t.Fatal("resident session did not adopt the rotated DEK")
	}
	if _, err := VerifyAudit(path, newPass); err != nil {
		t.Fatal(err)
	}
}

func TestChangePassphraseNoReloadKeyWritesNoHandoff(t *testing.T) {
	path, oldPass, s := mustCreate(t, nil)
	defer s.Lock()
	if _, err := s.Put("nohandoff", "generic", randBytesT(t, 16), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	newPass := []byte(randHex(t, 24))
	if err := s.ChangePassphrase(oldPass, newPass); err != nil {
		t.Fatal(err)
	}
	after, err := readHeaderFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.DEKHandoff) != 0 || len(after.DEKReloadPubKey) != 0 {
		t.Fatal("passphrase change without reload key wrote handoff or pubkey")
	}
}

func TestSessionReloadRejectsForeignReloadPubKey(t *testing.T) {
	path, oldPass, resident := mustCreate(t, nil)
	defer resident.Lock()
	secret := randBytesT(t, 32)
	cred, err := resident.Put("foreign-pub", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := resident.PublishDaemonReloadPubKey(); err != nil {
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
	foreign, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := vaultHandoffReady(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE vault SET dek_reload_pubkey = ?`, foreign[:]); err != nil {
		t.Fatal(err)
	}
	_, err = resident.Get(cred.ID)
	if !errors.Is(err, ErrStale) && !errors.Is(err, ErrCorrupt) {
		t.Fatalf("foreign reload pubkey: %v", err)
	}
	if !resident.defunct {
		t.Fatal("foreign reload pubkey did not retire session")
	}
}

func TestSessionReloadRejectsBadDEKHandoff(t *testing.T) {
	path, oldPass, resident := mustCreate(t, nil)
	defer resident.Lock()
	secret := randBytesT(t, 32)
	cred, err := resident.Put("tamper", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := resident.PublishDaemonReloadPubKey(); err != nil {
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
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := vaultHandoffReady(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE vault SET dek_handoff = randomblob(length(dek_handoff))`); err != nil {
		t.Fatal(err)
	}
	_, err = resident.Get(cred.ID)
	if !errors.Is(err, ErrStale) && !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered handoff: %v", err)
	}
	if !resident.defunct {
		t.Fatal("tampered handoff did not retire session")
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

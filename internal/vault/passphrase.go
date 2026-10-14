package vault

import (
	"bytes"
	"crypto/subtle"
)

type passphraseWrap struct {
	kdf        kdfParams
	nonce      []byte
	ciphertext []byte
}

// ChangePassphrase reauthenticates the current passphrase, generates a fresh
// DEK, re-encrypts every credential under it, and commits the new wrap, the
// resealed document, and the vault_passphrase_change audit row atomically. A
// resident session (the daemon) does not adopt the new DEK; it locks and the
// human unlocks again (item 3g). A stale session cannot replace a newer wrap. This is
// host custody, not an agent operation. Snapshots keep their original
// passphrase and DEK. This does not revoke a DEK that another process already
// holds or defend against a compromised host.
func (s *Session) ChangePassphrase(oldPassphrase, newPassphrase []byte) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	s.redactor.Add(oldPassphrase)
	s.redactor.Add(newPassphrase)
	if err := validatePassphrase(oldPassphrase); err != nil {
		return s.denyAction(actionPassphrase, err)
	}
	if err := validatePassphrase(newPassphrase); err != nil {
		return s.denyAction(actionPassphrase, err)
	}
	if bytes.Equal(oldPassphrase, newPassphrase) {
		return s.denyAction(actionPassphrase, ErrInvalid)
	}
	oldKEK := deriveKEK(oldPassphrase, s.header.KDF)
	defer wipe(oldKEK)
	dek, err := openAEAD(oldKEK, s.header.WrapNonce, s.header.WrappedDEK, dekAAD(s.id))
	if err != nil {
		return s.denyAction(actionPassphrase, ErrUnauthenticated)
	}
	defer wipe(dek)
	if subtle.ConstantTimeCompare(dek, s.dek) != 1 {
		return s.denyAction(actionPassphrase, ErrUnauthenticated)
	}
	newDEK, err := randBytes(keyLen)
	if err != nil {
		return err
	}
	defer wipe(newDEK)
	kdf, err := newKDF()
	if err != nil {
		return err
	}
	kek := deriveKEK(newPassphrase, kdf)
	defer wipe(kek)
	wrapNonce, wrapped, err := seal(kek, newDEK, dekAAD(s.id))
	if err != nil {
		return err
	}
	ev, err := nextEvent(s.audit, actionPassphrase, s.id, "", "", resultAllowed)
	if err != nil {
		return err
	}
	if s.rotateFault != nil {
		if err := s.rotateFault("reseal"); err != nil {
			return err
		}
	}
	rot := &dekRotation{newDEK: newDEK}
	// newDEK is adopted by commitBatchWrap on success; do not wipe it here.
	newDEK = nil
	if err := s.commitBatchWrap([]auditEvent{ev}, s.creds, s.agents, s.grants, true, nil,
		&passphraseWrap{kdf: kdf, nonce: wrapNonce, ciphertext: wrapped}, rot); err != nil {
		return err
	}
	s.logf("vault_passphrase_change result=allowed")
	return nil
}

// RejectPassphraseChange records a fixed denial after a human authenticated
// but did not supply a confirmed replacement. Caller text is never recorded.
func (s *Session) RejectPassphraseChange() error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.denyAction(actionPassphrase, ErrInvalid)
}

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

// ChangePassphrase reauthenticates the current passphrase and rewraps the
// existing DEK with a fresh salt and nonce. The wrap, encrypted state, and
// vault_passphrase_change audit row commit atomically. A stale session cannot
// replace a newer wrap. This is host custody, not an agent operation.
// Snapshots keep their original passphrase. This does not revoke a DEK that
// another process already holds or defend against a compromised host.
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
	kdf, err := newKDF()
	if err != nil {
		return err
	}
	kek := deriveKEK(newPassphrase, kdf)
	defer wipe(kek)
	nonce, ciphertext, err := seal(kek, s.dek, dekAAD(s.id))
	if err != nil {
		return err
	}
	ev, err := nextEvent(s.audit, actionPassphrase, s.id, "", "", resultAllowed)
	if err != nil {
		return err
	}
	if err := s.commitBatchWrap([]auditEvent{ev}, s.creds, s.agents, s.grants, true, nil,
		&passphraseWrap{kdf: kdf, nonce: nonce, ciphertext: ciphertext}); err != nil {
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

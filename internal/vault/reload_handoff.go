package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/nacl/box"
)

// PublishDaemonReloadPubKey records an ephemeral X25519 public key for this
// resident session and retains the private key only in memory. A later
// passphrase rotation can leave a one-time DEK handoff sealed to that key.
// The private key is wiped on Lock. Host custody only; not an agent operation.
func (s *Session) PublishDaemonReloadPubKey() error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return ErrIO
	}
	s.reloadPriv = priv
	s.pendingReloadPub = pub[:]
	ev, err := nextEvent(s.audit, actionDaemonReloadPubkey, s.id, "", "", resultAllowed)
	if err != nil {
		s.pendingReloadPub = nil
		s.reloadPriv = nil
		return err
	}
	err = s.commitBatchWrap([]auditEvent{ev}, s.creds, s.agents, s.grants, true, nil, nil, nil)
	s.pendingReloadPub = nil
	if err != nil {
		s.reloadPriv = nil
		return err
	}
	s.logf("daemon_reload_pubkey result=allowed")
	return nil
}

func sealDEKHandoff(pub []byte, newDEK []byte, vaultID, auditHead string, auditSeq uint64) ([]byte, error) {
	if len(pub) != 32 || len(newDEK) != keyLen {
		return nil, ErrCorrupt
	}
	var key [32]byte
	copy(key[:], pub)
	binding := dekHandoffBinding(vaultID, auditHead, auditSeq)
	plain := make([]byte, keyLen+len(binding))
	copy(plain, newDEK)
	copy(plain[keyLen:], binding)
	out, err := box.SealAnonymous(nil, plain, &key, rand.Reader)
	wipe(plain)
	if err != nil {
		return nil, ErrIO
	}
	return out, nil
}

func openDEKHandoffReload(priv *[32]byte, header fileHeader) ([]byte, error) {
	if priv == nil || len(header.DEKHandoff) == 0 || len(header.DEKReloadPubKey) != 32 {
		return nil, ErrCorrupt
	}
	if len(header.DEKHandoffNonce) != 0 {
		return nil, ErrCorrupt
	}
	var pub [32]byte
	copy(pub[:], header.DEKReloadPubKey)
	plain, ok := box.OpenAnonymous(nil, header.DEKHandoff, &pub, priv)
	if !ok {
		return nil, ErrCorrupt
	}
	binding := dekHandoffBinding(header.ID, header.AuditHead, header.AuditSeq)
	if len(plain) != keyLen+len(binding) || !bytes.Equal(plain[keyLen:], binding) {
		wipe(plain)
		return nil, ErrCorrupt
	}
	dek := append([]byte(nil), plain[:keyLen]...)
	wipe(plain)
	return dek, nil
}

func dekHandoffBinding(vaultID, auditHead string, auditSeq uint64) []byte {
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], auditSeq)
	return append([]byte("tremelay/v1/dek-handoff\x00"+vaultID+"\x00"+auditHead+"\x00"), seq[:]...)
}

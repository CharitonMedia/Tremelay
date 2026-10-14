package vault

import (
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/nacl/box"
)

// dekHandoffInnerLen is nonce || AES-GCM ciphertext of the new DEK.
const dekHandoffInnerLen = nonceLen + keyLen + 16

func minDEKHandoffLen() int {
	return box.AnonymousOverhead + dekHandoffInnerLen
}

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
	s.reloadPub = pub
	s.pendingReloadPub = pub[:]
	ev, err := nextEvent(s.audit, actionDaemonReloadPubkey, s.id, "", "", resultAllowed)
	if err != nil {
		s.pendingReloadPub = nil
		s.reloadPriv = nil
		s.reloadPub = nil
		return err
	}
	err = s.commitBatchWrap([]auditEvent{ev}, s.creds, s.agents, s.grants, true, nil, nil, nil)
	s.pendingReloadPub = nil
	if err != nil {
		s.reloadPriv = nil
		s.reloadPub = nil
		return err
	}
	s.logf("daemon_reload_pubkey result=allowed")
	return nil
}

// sealDEKHandoff wraps the new DEK for resident reload: inner AES-GCM under the
// old DEK with binding AAD, outer anonymous box to the reload public key.
func sealDEKHandoff(pub, oldDEK, newDEK []byte, vaultID, auditHead string, auditSeq uint64) ([]byte, error) {
	if len(pub) != 32 || len(oldDEK) != keyLen || len(newDEK) != keyLen {
		return nil, ErrCorrupt
	}
	var key [32]byte
	copy(key[:], pub)
	binding := dekHandoffBinding(vaultID, auditHead, auditSeq)
	innerNonce, innerCT, err := seal(oldDEK, newDEK, binding)
	if err != nil {
		return nil, err
	}
	inner := append(innerNonce, innerCT...)
	defer wipe(inner)
	out, err := box.SealAnonymous(nil, inner, &key, rand.Reader)
	if err != nil {
		return nil, ErrIO
	}
	return out, nil
}

func openDEKHandoffReload(priv, pub *[32]byte, oldDEK []byte, header fileHeader) ([]byte, error) {
	if priv == nil || pub == nil || len(oldDEK) != keyLen || len(header.DEKHandoff) == 0 {
		return nil, ErrCorrupt
	}
	if len(header.DEKHandoffNonce) != 0 {
		return nil, ErrCorrupt
	}
	if len(header.DEKHandoff) < minDEKHandoffLen() {
		return nil, ErrCorrupt
	}
	outer, ok := box.OpenAnonymous(nil, header.DEKHandoff, pub, priv)
	if !ok {
		return nil, ErrCorrupt
	}
	defer wipe(outer)
	if len(outer) < dekHandoffInnerLen {
		return nil, ErrCorrupt
	}
	innerNonce := outer[:nonceLen]
	innerCT := outer[nonceLen:]
	binding := dekHandoffBinding(header.ID, header.AuditHead, header.AuditSeq)
	newDEK, err := openAEAD(oldDEK, innerNonce, innerCT, binding)
	if err != nil {
		return nil, ErrCorrupt
	}
	if len(newDEK) != keyLen {
		wipe(newDEK)
		return nil, ErrCorrupt
	}
	return newDEK, nil
}

func dekHandoffBinding(vaultID, auditHead string, auditSeq uint64) []byte {
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], auditSeq)
	return append([]byte("tremelay/v1/dek-handoff\x00"+vaultID+"\x00"+auditHead+"\x00"), seq[:]...)
}

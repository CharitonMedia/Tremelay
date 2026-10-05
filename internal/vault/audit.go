package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

const (
	auditVersion = 1

	actionCreate = "vault_create"
	actionUnlock = "vault_unlock"
	actionPut    = "credential_put"
	actionGet    = "credential_get"
	actionList   = "credential_list"

	resultAllowed = "allowed"
	resultDenied  = "denied"
)

type auditEvent struct {
	V        int    `json:"v"`
	Seq      uint64 `json:"seq"`
	Time     string `json:"time"`
	Action   string `json:"action"`
	VaultID  string `json:"vault_id"`
	CredID   string `json:"credential_id,omitempty"`
	CredType string `json:"credential_type,omitempty"`
	Result   string `json:"result"`
	Prev     string `json:"prev"`
	Hash     string `json:"hash"`
}

// VerifyAudit checks the hash chain, then authenticates the encrypted
// document under the plaintext audit head. That head is associated data
// on the credential ciphertext, so rewriting it to match a truncated chain
// fails here. The passphrase unwraps the DEK for that check and is not
// retained. Rows after the head are accepted only when they are canonical
// locked-state unlock denials. The returned hash is the chain tip, for a
// later external checkpoint. This read does not append an audit event.
func VerifyAudit(vaultPath string, passphrase []byte) (string, error) {
	db, header, events, err := loadVault(vaultPath)
	if err != nil {
		return "", err
	}
	defer db.Close()
	if err := validatePassphrase(passphrase); err != nil {
		return "", err
	}
	kek := deriveKEK(passphrase, header.KDF)
	defer wipe(kek)
	dek, err := openAEAD(kek, header.WrapNonce, header.WrappedDEK, dekAAD(header.ID))
	if err != nil {
		return "", ErrUnauthenticated
	}
	defer wipe(dek)
	plain, err := openAEAD(dek, header.DataNonce, header.Data, dataAAD(header.ID, header.AuditHead, header.AuditSeq))
	if err != nil {
		return "", ErrAudit
	}
	wipe(plain)
	return events[len(events)-1].Hash, nil
}

func eventHash(prev []byte, seq uint64, timeStr, action, vaultID, credID, credType, result string) []byte {
	h := sha256.New()
	h.Write(prev)
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	h.Write(seqb[:])
	for _, part := range []string{timeStr, action, vaultID, credID, credType, result} {
		b := []byte(part)
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	return h.Sum(nil)
}

func nextEvent(chain []auditEvent, action, vaultID, credID, credType, result string) (auditEvent, error) {
	prev := make([]byte, 32)
	seq := uint64(1)
	if len(chain) > 0 {
		last := chain[len(chain)-1]
		decoded, err := hex.DecodeString(last.Hash)
		if err != nil || len(decoded) != 32 {
			return auditEvent{}, ErrAudit
		}
		prev = decoded
		seq = last.Seq + 1
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	sum := eventHash(prev, seq, ts, action, vaultID, credID, credType, result)
	return auditEvent{
		V:        auditVersion,
		Seq:      seq,
		Time:     ts,
		Action:   action,
		VaultID:  vaultID,
		CredID:   credID,
		CredType: credType,
		Result:   result,
		Prev:     hex.EncodeToString(prev),
		Hash:     hex.EncodeToString(sum),
	}, nil
}

func verifyChain(events []auditEvent) error {
	if len(events) == 0 {
		return nil
	}
	if events[0].Seq != 1 {
		return ErrAudit
	}
	if err := verifyLinked(events); err != nil {
		return err
	}
	if events[0].Action != actionCreate || events[0].Result != resultAllowed {
		return ErrAudit
	}
	return nil
}

func verifyLinked(events []auditEvent) error {
	if len(events) == 0 {
		return nil
	}
	first := events[0]
	prev, err := hex.DecodeString(first.Prev)
	if err != nil || len(prev) != 32 || first.Seq == 0 || first.VaultID == "" {
		return ErrAudit
	}
	if first.Seq == 1 && !bytes.Equal(prev, make([]byte, 32)) {
		return ErrAudit
	}
	for i, ev := range events {
		if ev.V != auditVersion || ev.Seq != first.Seq+uint64(i) {
			return ErrAudit
		}
		if ev.VaultID != first.VaultID || !knownAction(ev.Action) {
			return ErrAudit
		}
		if ev.Result != resultAllowed && ev.Result != resultDenied {
			return ErrAudit
		}
		gotPrev, err := hex.DecodeString(ev.Prev)
		if err != nil || !bytes.Equal(gotPrev, prev) {
			return ErrAudit
		}
		sum := eventHash(prev, ev.Seq, ev.Time, ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result)
		if hex.EncodeToString(sum) != ev.Hash {
			return ErrAudit
		}
		prev = sum
	}
	return nil
}

func knownAction(action string) bool {
	switch action {
	case actionCreate, actionUnlock, actionPut, actionGet, actionList:
		return true
	default:
		return false
	}
}

func suffixAllows(events []auditEvent, header fileHeader) error {
	idx := -1
	for i, ev := range events {
		if ev.Hash == header.AuditHead && ev.Seq == header.AuditSeq && ev.VaultID == header.ID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrAudit
	}
	for _, ev := range events[idx+1:] {
		// appendDenial leaves credential fields empty. A hash-linked row
		// with any other metadata is a forged suffix and must not be incorporated.
		if ev.Action != actionUnlock || ev.Result != resultDenied || ev.VaultID != header.ID || ev.CredID != "" || ev.CredType != "" {
			return ErrAudit
		}
	}
	return nil
}

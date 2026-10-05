package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
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

// errNoSidecar means a locked denial cannot be linked because the mirror is gone.
// The caller still reports authentication failure.
var errNoSidecar = errors.New("audit sidecar missing")

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

// VerifyAudit checks the sidecar against the head stored in the vault header
// and returns the sidecar tip as hex. Authenticity of that header head is
// enforced on unlock, where the head is AES-GCM associated data.
func VerifyAudit(vaultPath string) (string, error) {
	header, err := readHeader(vaultPath)
	if err != nil {
		return "", err
	}
	side, exists, err := readAudit(auditPath(vaultPath))
	if err != nil {
		return "", err
	}
	if !exists || len(side) == 0 {
		return "", ErrAudit
	}
	if err := verifyChain(side); err != nil {
		return "", err
	}
	if err := suffixAllows(side, header); err != nil {
		return "", err
	}
	return side[len(side)-1].Hash, nil
}

func auditPath(vaultPath string) string {
	return vaultPath + ".audit"
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
	prev := make([]byte, 32)
	for i, ev := range events {
		if ev.V != auditVersion || ev.Seq != uint64(i+1) {
			return ErrAudit
		}
		if ev.VaultID == "" || ev.VaultID != events[0].VaultID {
			return ErrAudit
		}
		if !knownAction(ev.Action) || (ev.Result != resultAllowed && ev.Result != resultDenied) {
			return ErrAudit
		}
		if i == 0 && (ev.Action != actionCreate || ev.Result != resultAllowed) {
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

func hashesEqual(a, b []auditEvent) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Hash != b[i].Hash || a[i].Seq != b[i].Seq {
			return false
		}
	}
	return true
}

// reconcile merges a sidecar with the sealed chain.
// A missing sidecar or a strict prefix is restored from the sealed chain.
// A suffix of unlock denials is kept. Anything else is ErrAudit.
func reconcile(sealed, side []auditEvent, sideExists bool) ([]auditEvent, error) {
	if len(sealed) == 0 {
		return nil, ErrAudit
	}
	if err := verifyChain(sealed); err != nil {
		return nil, err
	}
	if !sideExists {
		return copyEvents(sealed), nil
	}
	if err := verifyChain(side); err != nil {
		return nil, err
	}
	if len(side) < len(sealed) {
		if !hashesEqual(side, sealed[:len(side)]) {
			return nil, ErrAudit
		}
		return copyEvents(sealed), nil
	}
	if !hashesEqual(sealed, side[:len(sealed)]) {
		return nil, ErrAudit
	}
	for _, ev := range side[len(sealed):] {
		if ev.Action != actionUnlock || ev.Result != resultDenied || ev.VaultID != sealed[0].VaultID {
			return nil, ErrAudit
		}
	}
	return copyEvents(side), nil
}

func copyEvents(in []auditEvent) []auditEvent {
	out := make([]auditEvent, len(in))
	copy(out, in)
	return out
}

func suffixAllows(side []auditEvent, header fileHeader) error {
	idx := -1
	for i, ev := range side {
		if ev.Hash == header.AuditHead && ev.Seq == header.AuditSeq && ev.VaultID == header.ID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrAudit
	}
	for _, ev := range side[idx+1:] {
		if ev.Action != actionUnlock || ev.Result != resultDenied || ev.VaultID != header.ID {
			return ErrAudit
		}
	}
	return nil
}

func readAudit(path string) ([]auditEvent, bool, error) {
	b, err := readLimited(path, maxVaultFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var events []auditEvent
	for {
		var ev auditEvent
		if err := dec.Decode(&ev); err != nil {
			if err == io.EOF {
				break
			}
			return nil, true, ErrAudit
		}
		events = append(events, ev)
	}
	return events, true, nil
}

func appendAudit(path string, ev auditEvent) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(ev); err != nil {
		return ErrAudit
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrIO
	}
	defer f.Close()
	if _, err := f.Write(buf.Bytes()); err != nil {
		return ErrIO
	}
	if err := f.Sync(); err != nil {
		return ErrIO
	}
	return nil
}

func writeAuditFile(path string, events []auditEvent) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return ErrAudit
		}
	}
	return writeAtomic(path, buf.Bytes())
}

// syncSidecar appends any sealed events the mirror is missing.
// It does not rewrite a divergent file.
func syncSidecar(path string, chain []auditEvent) error {
	have, exists, err := readAudit(path)
	if err != nil {
		return err
	}
	if !exists {
		return writeAuditFile(path, chain)
	}
	if len(have) > len(chain) || !hashesEqual(have, chain[:len(have)]) {
		return ErrAudit
	}
	for _, ev := range chain[len(have):] {
		if err := appendAudit(path, ev); err != nil {
			return err
		}
	}
	return nil
}

func appendUnlockDenial(vaultPath, vaultID, sealedHead string, sealedSeq uint64) error {
	side, exists, err := readAudit(auditPath(vaultPath))
	if err != nil {
		return err
	}
	if !exists {
		return errNoSidecar
	}
	if err := verifyChain(side); err != nil {
		return err
	}
	header := fileHeader{ID: vaultID, AuditHead: sealedHead, AuditSeq: sealedSeq}
	if err := suffixAllows(side, header); err != nil {
		return err
	}
	ev, err := nextEvent(side, actionUnlock, vaultID, "", "", resultDenied)
	if err != nil {
		return err
	}
	return appendAudit(auditPath(vaultPath), ev)
}

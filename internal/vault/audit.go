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

// verifyLinked checks a hash-linked run. A sealed suffix may start after seq 1.
// The sidecar still has to pass verifyChain so dropped history stays visible.
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
// The sealed copy may be a hash-linked suffix once a prefix is already durable
// in the sidecar. A missing sidecar restores a genesis chain only. A strict
// overlapping prefix is restored from the sealed copy. A suffix of unlock
// denials is kept. Anything else is ErrAudit.
func reconcile(sealed, side []auditEvent, sideExists bool) ([]auditEvent, error) {
	if len(sealed) == 0 {
		return nil, ErrAudit
	}
	if err := verifyLinked(sealed); err != nil {
		return nil, err
	}
	if !sideExists {
		if sealed[0].Seq != 1 {
			return nil, ErrAudit
		}
		return copyEvents(sealed), nil
	}
	if err := verifyChain(side); err != nil {
		return nil, err
	}
	idx := -1
	for i := range side {
		if side[i].Hash == sealed[0].Hash && side[i].Seq == sealed[0].Seq {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, ErrAudit
	}
	overlap := len(side) - idx
	if overlap >= len(sealed) {
		if !hashesEqual(sealed, side[idx:idx+len(sealed)]) {
			return nil, ErrAudit
		}
		for _, ev := range side[idx+len(sealed):] {
			if ev.Action != actionUnlock || ev.Result != resultDenied || ev.VaultID != sealed[0].VaultID {
				return nil, ErrAudit
			}
		}
		return copyEvents(side), nil
	}
	if !hashesEqual(side[idx:], sealed[:overlap]) {
		return nil, ErrAudit
	}
	out := append(copyEvents(side), sealed[overlap:]...)
	if err := verifyChain(out); err != nil {
		return nil, err
	}
	return out, nil
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
	events, _, exists, err := inspectSidecar(path)
	return events, exists, err
}

// inspectSidecar returns the complete events and how many prefix bytes they
// occupy. A trailing partial line is not an event: it is the remnant of a
// crashed append, and the next append drops it. A complete line that does not
// decode stays an error so tampering is not trimmed away.
func inspectSidecar(path string) (events []auditEvent, keep int, exists bool, err error) {
	b, err := readAuditBytes(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	events, keep, torn, err := splitAudit(b)
	if err != nil {
		return nil, 0, true, err
	}
	if torn && len(events) == 0 {
		return nil, 0, false, nil
	}
	return events, keep, true, nil
}

func readAuditBytes(path string) ([]byte, error) {
	b, err := readLimited(path, maxVaultFile)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	bak, bakErr := readLimited(path+".bak", maxVaultFile)
	if errors.Is(bakErr, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if bakErr != nil {
		return nil, bakErr
	}
	return bak, nil
}

// splitAudit parses newline-delimited events. keep is the length of the
// complete prefix. torn is set when the file ends mid-line.
func splitAudit(b []byte) (events []auditEvent, keep int, torn bool, err error) {
	i := 0
	for i < len(b) {
		rel := bytes.IndexByte(b[i:], '\n')
		if rel < 0 {
			line := b[i:]
			if len(bytes.TrimSpace(line)) == 0 {
				return events, i, false, nil
			}
			if !json.Valid(line) {
				return events, i, true, nil
			}
			ev, derr := decodeAuditLine(line)
			if derr != nil {
				return nil, 0, false, ErrAudit
			}
			events = append(events, ev)
			return events, len(b), false, nil
		}
		line := b[i : i+rel]
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, 0, false, ErrAudit
		}
		ev, derr := decodeAuditLine(line)
		if derr != nil {
			return nil, 0, false, ErrAudit
		}
		events = append(events, ev)
		i += rel + 1
	}
	return events, i, false, nil
}

func decodeAuditLine(line []byte) (auditEvent, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var ev auditEvent
	if err := dec.Decode(&ev); err != nil {
		return auditEvent{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return auditEvent{}, ErrAudit
	}
	return ev, nil
}

func auditLine(ev auditEvent) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(ev); err != nil {
		return nil, ErrAudit
	}
	return buf.Bytes(), nil
}

func auditLinesLen(events []auditEvent) (int64, error) {
	var n int64
	for _, ev := range events {
		line, err := auditLine(ev)
		if err != nil {
			return 0, err
		}
		n += int64(len(line))
	}
	return n, nil
}

// sidecarFits reports whether chain can be mirrored and, when reserve is set,
// still leave room for one maximum-width vault_unlock line.
func sidecarFits(path string, chain []auditEvent, reserve bool) error {
	have, keep, exists, err := inspectSidecar(path)
	if err != nil {
		return err
	}
	base := 0
	if exists {
		if len(have) > len(chain) || !hashesEqual(have, chain[:len(have)]) {
			return ErrAudit
		}
		base = keep
	}
	extra, err := auditLinesLen(chain[len(have):])
	if err != nil {
		return err
	}
	need := int64(base) + extra
	if reserve {
		if len(chain) == 0 {
			return ErrAudit
		}
		probe, err := auditLine(unlockProbe(chain, chain[len(chain)-1].VaultID))
		if err != nil {
			return err
		}
		need += int64(len(probe))
	}
	if need > maxVaultFile {
		return ErrInvalid
	}
	return nil
}

// appendAudit adds one JSON line without exceeding maxVaultFile.
// The line replaces the file, so a crash cannot leave a new partial record.
// A torn tail already present is omitted from the replacement.
// ponytail: the sidecar is not rotated. Ceiling: once a vault_unlock line
// would not fit, later unlocks fail closed and the previous file stays
// readable. Upgrade path: store the chain outside this file (ADR 0003).
func appendAudit(path string, ev auditEvent) error {
	line, err := auditLine(ev)
	if err != nil {
		return err
	}
	b, err := readAuditBytes(path)
	if errors.Is(err, os.ErrNotExist) {
		b = nil
		err = nil
	}
	if err != nil {
		return err
	}
	_, keep, _, err := splitAudit(b)
	if err != nil {
		return err
	}
	next := make([]byte, 0, keep+len(line))
	if keep > 0 {
		next = append(next, b[:keep]...)
	}
	next = append(next, line...)
	if int64(len(next)) > maxVaultFile {
		return ErrInvalid
	}
	return writeAtomic(path, next)
}

func writeAuditFile(path string, events []auditEvent) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return ErrAudit
		}
	}
	if int64(buf.Len()) > maxVaultFile {
		return ErrInvalid
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
	// A denial must not consume the line reserved for the next successful unlock.
	if err := sidecarFits(auditPath(vaultPath), append(copyEvents(side), ev), true); err != nil {
		return err
	}
	return appendAudit(auditPath(vaultPath), ev)
}

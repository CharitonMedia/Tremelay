package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

const (
	auditVersion           = 1
	auditCapabilityVersion = 2
	auditNoticeVersion     = 3

	actionCreate      = "vault_create"
	actionUnlock      = "vault_unlock"
	actionPut         = "credential_put"
	actionGet         = "credential_get"
	actionList        = "credential_list"
	actionAgentCreate = "agent_create"
	actionGrantCreate = "grant_create"
	actionGrantRevoke = "grant_revoke"
	actionAuthorize   = "capability_authorize"
	actionCapList     = "capability_list"
	actionBroker      = "broker_http"
	actionNotify      = "notify"
	actionContain     = "contain"

	resultAllowed           = "allowed"
	resultDenied            = "denied"
	resultDeniedAgent       = "denied_agent"
	resultDeniedCredential  = "denied_credential"
	resultDeniedOperation   = "denied_operation"
	resultDeniedScope       = "denied_scope"
	resultDeniedExpired     = "denied_expired"
	resultDeniedRevoked     = "denied_revoked"
	resultDeniedMissing     = "denied_missing"
	resultDeniedDestination = "denied_destination"
	resultDeniedOrigin      = "denied_origin"
	resultDeniedSSRF        = "denied_ssrf"
	resultDeniedRedirect    = "denied_redirect"
	resultDeniedMethod      = "denied_method"
	resultDeniedPath        = "denied_path"
	resultDeniedAction      = "denied_action"
	resultDeniedMalformed   = "denied_malformed"
	resultDeniedAbuse       = "denied_abuse"
	resultDeniedSecret      = "denied_secret"
	resultDeniedDestructive = "denied_destructive"
	resultUpstreamError     = "upstream_error"
	resultCompleted         = "completed"
	resultDelivered         = "delivered"
	resultFailed            = "failed"
	resultAttempted         = "attempted"
	resultFlagged           = "flagged"
	resultSuspended         = "suspended"
	resultUnchanged         = "unchanged"
)

type auditEvent struct {
	V         int    `json:"v"`
	Seq       uint64 `json:"seq"`
	Time      string `json:"time"`
	Action    string `json:"action"`
	VaultID   string `json:"vault_id"`
	CredID    string `json:"credential_id,omitempty"`
	CredType  string `json:"credential_type,omitempty"`
	Result    string `json:"result"`
	AgentID   string `json:"agent_id,omitempty"`
	GrantID   string `json:"grant_id,omitempty"`
	Operation string `json:"operation,omitempty"`
	Class     string `json:"class,omitempty"`
	RefSeq    uint64 `json:"ref_seq,omitempty"`
	Prev      string `json:"prev"`
	Hash      string `json:"hash"`
}

// VerifyAudit checks the hash chain, then authenticates the encrypted
// document under the plaintext audit head. That head is associated data
// on the credential ciphertext, so rewriting it to match a truncated chain
// fails here. The passphrase unwraps the DEK for that check and is not
// retained. Rows after the head are accepted only when they are canonical
// locked-state unlock denials with a chronological timestamp. The returned
// hash is the chain tip, for a later external checkpoint. This read does not
// append an audit event.
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
	defer wipe(plain)
	var doc document
	if err := unmarshalStrict(plain, &doc); err != nil {
		return "", ErrAudit
	}
	defer wipeCredentials(doc.Credentials)
	// The detection mirror is inside the authenticated document. A pre-M5
	// document has no member; the chain supplies it. A stored member that
	// does not match the chain is a failed verification, not a clean tip.
	doc.Detection, err = sealedDetection(plain, events, doc.Detection)
	if err != nil || checkDetection(events, doc.Detection) != nil {
		return "", ErrAudit
	}
	return events[len(events)-1].Hash, nil
}

func eventHash(prev []byte, seq uint64, timeStr, action, vaultID, credID, credType, result string) []byte {
	return hashParts(prev, seq, timeStr, action, vaultID, credID, credType, result)
}

// eventHashV2 extends the version-1 preimage with the capability fields.
// Resource strings are not part of the preimage; they stay in the encrypted document.
func eventHashV2(prev []byte, seq uint64, timeStr, action, vaultID, credID, credType, result, agentID, grantID, operation string) []byte {
	return hashParts(prev, seq, timeStr, action, vaultID, credID, credType, result, agentID, grantID, operation)
}

func eventHashV3(prev []byte, seq uint64, timeStr, action, vaultID, credID, credType, result, agentID, grantID, operation, class string, refSeq uint64) []byte {
	var ref [8]byte
	binary.BigEndian.PutUint64(ref[:], refSeq)
	return hashPartsTail(prev, seq, []string{timeStr, action, vaultID, credID, credType, result, agentID, grantID, operation, class}, ref[:])
}

func hashParts(prev []byte, seq uint64, parts ...string) []byte {
	return hashPartsTail(prev, seq, parts, nil)
}

func hashPartsTail(prev []byte, seq uint64, parts []string, tail []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	h.Write(seqb[:])
	for _, part := range parts {
		b := []byte(part)
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	h.Write(tail)
	return h.Sum(nil)
}

func nextEvent(chain []auditEvent, action, vaultID, credID, credType, result string) (auditEvent, error) {
	return nextAudit(chain, vaultID, auditEvent{
		Action:   action,
		CredID:   credID,
		CredType: credType,
		Result:   result,
	})
}

func nextAudit(chain []auditEvent, vaultID string, partial auditEvent) (auditEvent, error) {
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
	ev := partial
	ev.V = auditVersionFor(ev.Action)
	ev.Seq = seq
	ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
	ev.VaultID = vaultID
	ev.Prev = hex.EncodeToString(prev)
	var sum []byte
	switch ev.V {
	case auditNoticeVersion:
		if ev.Class == "" || ev.RefSeq == 0 || ev.RefSeq >= ev.Seq {
			return auditEvent{}, ErrAudit
		}
		sum = eventHashV3(prev, ev.Seq, ev.Time, ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation, ev.Class, ev.RefSeq)
	case auditCapabilityVersion:
		if ev.Class != "" || ev.RefSeq != 0 {
			return auditEvent{}, ErrAudit
		}
		sum = eventHashV2(prev, ev.Seq, ev.Time, ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation)
	default:
		if ev.AgentID != "" || ev.GrantID != "" || ev.Operation != "" || ev.Class != "" || ev.RefSeq != 0 {
			return auditEvent{}, ErrAudit
		}
		sum = eventHash(prev, ev.Seq, ev.Time, ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result)
	}
	ev.Hash = hex.EncodeToString(sum)
	return ev, nil
}

func auditVersionFor(action string) int {
	switch {
	case noticeAction(action):
		return auditNoticeVersion
	case capabilityAction(action):
		return auditCapabilityVersion
	default:
		return auditVersion
	}
}

func hashEvent(prev []byte, ev auditEvent) []byte {
	switch ev.V {
	case auditNoticeVersion:
		return eventHashV3(prev, ev.Seq, ev.Time, ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation, ev.Class, ev.RefSeq)
	case auditCapabilityVersion:
		return eventHashV2(prev, ev.Seq, ev.Time, ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation)
	default:
		return eventHash(prev, ev.Seq, ev.Time, ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result)
	}
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
		if ev.V != 1 && ev.V != 2 && ev.V != 3 {
			return ErrAudit
		}
		if ev.V != auditVersionFor(ev.Action) || ev.Seq != first.Seq+uint64(i) {
			return ErrAudit
		}
		if noticeAction(ev.Action) {
			found := false
			for _, prevEv := range events[:i] {
				if prevEv.Seq == ev.RefSeq {
					found = true
					break
				}
			}
			if !found {
				return ErrAudit
			}
		}
		if ev.VaultID != first.VaultID || !knownAction(ev.Action) {
			return ErrAudit
		}
		if err := validAuditShape(ev); err != nil {
			return err
		}
		gotPrev, err := hex.DecodeString(ev.Prev)
		if err != nil || !bytes.Equal(gotPrev, prev) {
			return ErrAudit
		}
		sum := hashEvent(prev, ev)
		if hex.EncodeToString(sum) != ev.Hash {
			return ErrAudit
		}
		prev = sum
	}
	return nil
}

func knownAction(action string) bool {
	switch action {
	case actionCreate, actionUnlock, actionPut, actionGet, actionList,
		actionAgentCreate, actionGrantCreate, actionGrantRevoke, actionAuthorize, actionCapList,
		actionBroker, actionNotify, actionContain:
		return true
	default:
		return false
	}
}

func noticeAction(action string) bool {
	return action == actionNotify || action == actionContain
}

func capabilityAction(action string) bool {
	switch action {
	case actionAgentCreate, actionGrantCreate, actionGrantRevoke, actionAuthorize, actionCapList, actionBroker:
		return true
	default:
		return false
	}
}

func validAuditShape(ev auditEvent) error {
	if noticeAction(ev.Action) {
		return validNoticeAudit(ev)
	}
	if ev.Class != "" || ev.RefSeq != 0 {
		return ErrAudit
	}
	if ev.Result == resultDeniedSecret && ev.Operation != "" {
		return ErrAudit
	}
	if !capabilityAction(ev.Action) {
		if ev.Result != resultAllowed && ev.Result != resultDenied {
			return ErrAudit
		}
		if ev.AgentID != "" || ev.GrantID != "" || ev.Operation != "" {
			return ErrAudit
		}
		return nil
	}
	if ev.AgentID != "" && safeID(ev.AgentID) == "" {
		return ErrAudit
	}
	if ev.GrantID != "" && safeID(ev.GrantID) == "" {
		return ErrAudit
	}
	if ev.CredID != "" && safeID(ev.CredID) == "" {
		return ErrAudit
	}
	if ev.CredType != "" && validateType(ev.CredType) != nil {
		return ErrAudit
	}
	if !validAuditOperation(ev.Operation) {
		return ErrAudit
	}
	switch ev.Result {
	case resultAllowed, resultDenied, resultDeniedAgent, resultDeniedCredential, resultDeniedOperation,
		resultDeniedScope, resultDeniedExpired, resultDeniedRevoked, resultDeniedMissing, resultDeniedSecret:
	default:
		if ev.Action != actionBroker || !brokerOnlyResult(ev.Result) {
			return ErrAudit
		}
	}
	switch ev.Action {
	case actionAgentCreate:
		if ev.GrantID != "" || ev.Operation != "" || ev.CredID != "" || ev.CredType != "" {
			return ErrAudit
		}
		if ev.Result == resultAllowed && ev.AgentID == "" {
			return ErrAudit
		}
		if ev.Result != resultAllowed && ev.Result != resultDenied {
			return ErrAudit
		}
	case actionGrantCreate:
		if ev.Result == resultAllowed && (ev.AgentID == "" || ev.GrantID == "" || ev.CredType == "" || ev.Operation == "") {
			return ErrAudit
		}
	case actionGrantRevoke:
		if ev.Result == resultAllowed && (ev.AgentID == "" || ev.GrantID == "" || ev.Operation == "") {
			return ErrAudit
		}
	case actionAuthorize:
		if stringsContainComma(ev.Operation) {
			return ErrAudit
		}
		if ev.Result == resultAllowed && (ev.AgentID == "" || ev.GrantID == "" || ev.CredID == "" || ev.CredType == "" || ev.Operation == "") {
			return ErrAudit
		}
	case actionCapList:
		if ev.GrantID != "" || ev.Operation != "" || ev.CredID != "" || ev.CredType != "" {
			return ErrAudit
		}
		if ev.Result == resultAllowed && ev.AgentID == "" {
			return ErrAudit
		}
		if ev.Result != resultAllowed && ev.Result != resultDenied && ev.Result != resultDeniedAgent {
			return ErrAudit
		}
	case actionBroker:
		if err := validBrokerAudit(ev); err != nil {
			return err
		}
	default:
		return ErrAudit
	}
	return nil
}

func validNoticeAudit(ev auditEvent) error {
	if ev.V != auditNoticeVersion || !knownClass(ev.Class) || ev.RefSeq == 0 || ev.RefSeq >= ev.Seq || ev.Operation != "" {
		return ErrAudit
	}
	if ev.AgentID != "" && safeID(ev.AgentID) == "" {
		return ErrAudit
	}
	if ev.GrantID != "" && safeID(ev.GrantID) == "" {
		return ErrAudit
	}
	if ev.CredID != "" && safeID(ev.CredID) == "" {
		return ErrAudit
	}
	if ev.CredType != "" && validateType(ev.CredType) != nil {
		return ErrAudit
	}
	switch ev.Action {
	case actionNotify:
		if ev.Result != resultDelivered && ev.Result != resultFailed && ev.Result != resultAttempted {
			return ErrAudit
		}
	case actionContain:
		switch ev.Result {
		case resultFlagged, resultSuspended, resultUnchanged:
		default:
			return ErrAudit
		}
	default:
		return ErrAudit
	}
	return nil
}

func brokerOnlyResult(result string) bool {
	switch result {
	case resultDeniedDestination, resultDeniedOrigin, resultDeniedSSRF, resultDeniedRedirect,
		resultDeniedMethod, resultDeniedPath, resultDeniedAction, resultDeniedMalformed,
		resultDeniedAbuse, resultDeniedDestructive, resultUpstreamError, resultCompleted:
		return true
	default:
		return false
	}
}

// validBrokerAudit keeps broker rows on the closed result set. Free-form
// caller text is not a legal result or operation.
func validBrokerAudit(ev auditEvent) error {
	if stringsContainComma(ev.Operation) || (ev.Operation != "" && ev.Operation != OpHTTPRequest) {
		return ErrAudit
	}
	switch ev.Result {
	case resultAllowed, resultCompleted, resultUpstreamError, resultDeniedAbuse, resultDeniedDestructive:
		if ev.AgentID == "" || ev.GrantID == "" || ev.CredID == "" || ev.CredType == "" || ev.Operation != OpHTTPRequest {
			return ErrAudit
		}
	case resultDenied:
		if ev.AgentID != "" || ev.GrantID != "" || ev.Operation != "" || ev.CredID != "" || ev.CredType != "" {
			return ErrAudit
		}
	case resultDeniedDestination, resultDeniedOrigin, resultDeniedSSRF, resultDeniedRedirect,
		resultDeniedMethod, resultDeniedPath, resultDeniedAction, resultDeniedMalformed,
		resultDeniedAgent, resultDeniedCredential, resultDeniedOperation,
		resultDeniedScope, resultDeniedExpired, resultDeniedRevoked, resultDeniedMissing:
	default:
		return ErrAudit
	}
	return nil
}

func stringsContainComma(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return true
		}
	}
	return false
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
	if idx == len(events)-1 {
		return nil
	}
	// ponytail: wall-clock order only. A step backward can make a real denial
	// look forged and block unlock until that row is removed. Upgrade path: a trusted time source.
	prevTime, ok := canonicalAuditTime(events[idx].Time)
	if !ok {
		return ErrAudit
	}
	now := time.Now()
	for _, ev := range events[idx+1:] {
		// appendDenial leaves credential fields empty and stamps Time with
		// time.Now().UTC().Format(time.RFC3339Nano). Any other metadata, a
		// noncanonical timestamp, or a time outside [previous, now] is a
		// forged suffix and must not be incorporated.
		if ev.Action != actionUnlock || ev.Result != resultDenied || ev.VaultID != header.ID || ev.CredID != "" || ev.CredType != "" || ev.AgentID != "" || ev.GrantID != "" || ev.Operation != "" || ev.Class != "" || ev.RefSeq != 0 {
			return ErrAudit
		}
		ts, ok := canonicalAuditTime(ev.Time)
		if !ok || ts.Before(prevTime) || ts.After(now) {
			return ErrAudit
		}
		prevTime = ts
	}
	return nil
}

// canonicalAuditTime accepts only the UTC RFC3339Nano text nextEvent writes.
func canonicalAuditTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Location() != time.UTC || t.Format(time.RFC3339Nano) != s {
		return time.Time{}, false
	}
	return t, true
}

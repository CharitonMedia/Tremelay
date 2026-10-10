package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// AgentCapVersion is the only agent-capability message version this slice accepts.
	AgentCapVersion = 1
	// MaxAgentCapMessage is the largest accepted request or response.
	// It covers one MaxAttestPayload plus framing. Larger input is rejected
	// and is not truncated.
	MaxAgentCapMessage = MaxAttestPayload + 512

	// ponytail: one response lists at most 64 attestation grants. A larger
	// catalog is denied in full. Upgrade path: a paged list.
	maxAgentCapEntries = 64

	capMethodError    = 0
	capMethodList     = 1
	capMethodDescribe = 2
	capMethodInvoke   = 3
	capMethodRequest  = 4

	capFieldHandle    = 1
	capFieldPayload   = 2
	capFieldOperation = 3
	capFieldResource  = 4
	capFieldKeyID     = 5
	capFieldStatus    = 6
	capFieldExpiry    = 7
	capFieldCatalog   = 8
	capFieldSignature = 9
	capFieldPublicKey = 10
	capFieldDomain    = 11
	capFieldPurpose   = 12
	capFieldCode      = 13
	capFieldMessage   = 14

	capTypeBytes  = 1
	capTypeString = 2
	maxCapFields  = 8

	capMalformed          = "malformed"
	capUnsupportedVersion = "unsupported_version"
	capUnknownMethod      = "unknown_method"
	capUnsupported        = "unsupported"
	capUnknownHandle      = "unknown_handle"
	capDenied             = "denied"
	capDeniedAgent        = "denied_agent"
	capDeniedRevoked      = "denied_revoked"
	capDeniedExpired      = "denied_expired"
	capDeniedKey          = "denied_key"
	capFailed             = "failed"
)

// errCapStale means a handle this adapter issued no longer matches the grant
// it was bound to. The client sees the same fixed unknown-handle response as
// a foreign or never-issued handle.
var errCapStale = errors.New("capability handle is not current")

// agentCapGrant is the exact authority a handle locates. It stays inside the
// adapter. The caller message cannot supply these fields.
type agentCapGrant struct {
	grantID  string
	credID   string
	keyID    string
	resource string
}

type agentCapSnapshot struct {
	agentCapGrant
	status  string
	expires time.Time
}

type agentCapView struct {
	status  string
	expires time.Time
}

// agentCapBroker is the session surface for one bound adapter.
// It is not *Session. The adapter cannot replace the principal, clock, or vault.
type agentCapBroker interface {
	agentCapList(agentID string) ([]agentCapSnapshot, error)
	agentCapDescribe(agentID string, bound agentCapGrant) (agentCapView, error)
	agentCapInvoke(agentID, grantID string, payload []byte) (LocalAttestation, error)
	agentCapDeny(agentID string, invoke bool) error
}

// AgentCapability is one in-process caller boundary for an already-bound agent.
// Exchange is the only caller operation. Messages cannot choose a principal,
// grant, credential, resource, key, clock, or signing domain. A handle is a
// locator in this adapter, not an authentication credential.
//
// The unlocked Session is not safe for concurrent callers. Exchange must not
// run on another goroutine while the host uses that session.
type AgentCapability struct {
	broker  agentCapBroker
	agentID string

	mu       sync.Mutex
	byGrant  map[string][32]byte
	byHandle map[[32]byte]agentCapGrant
}

// BindAgentCapability binds an adapter to one host-selected principal.
// The principal cannot be replaced by a later message. A nil principal,
// or a view that is not the session binder, is refused.
func BindAgentCapability(p *AgentPrincipal) (*AgentCapability, error) {
	if p == nil || p.view == nil || safeID(p.id) == "" {
		return nil, ErrUnauthenticated
	}
	broker, ok := p.view.(agentCapBroker)
	if !ok {
		return nil, ErrUnauthenticated
	}
	return &AgentCapability{
		broker:   broker,
		agentID:  p.id,
		byGrant:  map[string][32]byte{},
		byHandle: map[[32]byte]agentCapGrant{},
	}, nil
}

// Exchange answers one complete capability message. Protocol failures are
// fixed response bytes. A locked session, a stale session, or a failed
// required audit returns an error and no response bytes, and does not mean
// an event was recorded.
func (a *AgentCapability) Exchange(message []byte) ([]byte, error) {
	if a == nil || a.broker == nil || safeID(a.agentID) == "" {
		return nil, ErrUnauthenticated
	}
	req, code := parseCapRequest(message)
	defer wipe(req.payload)
	if code != "" {
		return a.protocolDeny(req.method == capMethodInvoke && code == capMalformed, code)
	}
	switch req.method {
	case capMethodList:
		return a.list()
	case capMethodDescribe:
		return a.describe(req.handle)
	case capMethodInvoke:
		return a.invoke(req.handle, req.payload)
	default:
		return a.protocolDeny(false, capUnknownMethod)
	}
}

func (a *AgentCapability) protocolDeny(invoke bool, code string) ([]byte, error) {
	if err := a.broker.agentCapDeny(a.agentID, invoke); err != nil {
		return nil, err
	}
	return encodeCapError(code)
}

func (a *AgentCapability) list() ([]byte, error) {
	snaps, err := a.broker.agentCapList(a.agentID)
	if err != nil {
		if capHost(err) {
			return nil, err
		}
		return encodeCapError(capFromErr(err))
	}
	entries, err := a.bindAll(snaps)
	if err != nil {
		return nil, err
	}
	cat, err := encodeCatalog(entries)
	if err != nil {
		return nil, ErrInvalid
	}
	return encodeCap(capMethodList, []capWire{{id: capFieldCatalog, typ: capTypeBytes, val: cat}})
}

func (a *AgentCapability) describe(handle [32]byte) ([]byte, error) {
	bound, ok := a.lookup(handle)
	if !ok {
		return a.protocolDeny(false, capUnknownHandle)
	}
	view, err := a.broker.agentCapDescribe(a.agentID, bound)
	if err != nil {
		if capHost(err) {
			return nil, err
		}
		if errors.Is(err, errCapStale) {
			return encodeCapError(capUnknownHandle)
		}
		return encodeCapError(capFromErr(err))
	}
	exp, err := requireTime(view.expires)
	if err != nil {
		return nil, ErrInvalid
	}
	return encodeCap(capMethodDescribe, []capWire{
		{id: capFieldHandle, typ: capTypeBytes, val: handle[:]},
		{id: capFieldOperation, typ: capTypeString, val: []byte(OpLocalArtifactAttest)},
		{id: capFieldResource, typ: capTypeString, val: []byte(bound.resource)},
		{id: capFieldKeyID, typ: capTypeString, val: []byte(bound.keyID)},
		{id: capFieldStatus, typ: capTypeString, val: []byte(view.status)},
		{id: capFieldExpiry, typ: capTypeString, val: []byte(exp.Format(time.RFC3339Nano))},
	})
}

func (a *AgentCapability) invoke(handle [32]byte, payload []byte) ([]byte, error) {
	bound, ok := a.lookup(handle)
	if !ok {
		return a.protocolDeny(true, capUnknownHandle)
	}
	att, err := a.broker.agentCapInvoke(a.agentID, bound.grantID, payload)
	if err != nil {
		if capHost(err) {
			return nil, err
		}
		return encodeCapError(capFromErr(err))
	}
	if att.Domain != AttestDomain || att.Purpose != AttestPurpose || att.Resource != bound.resource || hex.EncodeToString(att.PublicKey[:]) != bound.keyID {
		return nil, ErrSignFailed
	}
	return encodeCap(capMethodInvoke, []capWire{
		{id: capFieldResource, typ: capTypeString, val: []byte(att.Resource)},
		{id: capFieldSignature, typ: capTypeBytes, val: att.Signature[:]},
		{id: capFieldPublicKey, typ: capTypeBytes, val: att.PublicKey[:]},
		{id: capFieldDomain, typ: capTypeString, val: []byte(att.Domain)},
		{id: capFieldPurpose, typ: capTypeString, val: []byte(att.Purpose)},
	})
}

func (a *AgentCapability) lookup(handle [32]byte) (agentCapGrant, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	bound, ok := a.byHandle[handle]
	return bound, ok
}

func (a *AgentCapability) bindAll(snaps []agentCapSnapshot) ([]capEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]capEntry, 0, len(snaps))
	for _, sn := range snaps {
		handle, ok := a.byGrant[sn.grantID]
		if !ok {
			raw, err := randBytes(32)
			if err != nil {
				return nil, err
			}
			copy(handle[:], raw)
			if _, exists := a.byHandle[handle]; exists {
				return nil, ErrIO
			}
			a.byGrant[sn.grantID] = handle
			a.byHandle[handle] = sn.agentCapGrant
		}
		// An existing handle keeps its original grant, credential, key, and
		// resource. A later list does not point it at another grant.
		stored := a.byHandle[handle]
		exp, err := requireTime(sn.expires)
		if err != nil {
			return nil, ErrInvalid
		}
		out = append(out, capEntry{
			handle:    handle,
			operation: OpLocalArtifactAttest,
			resource:  stored.resource,
			keyID:     stored.keyID,
			status:    sn.status,
			expires:   exp,
		})
	}
	return out, nil
}

func (b agentBinder) agentCapList(agentID string) ([]agentCapSnapshot, error) {
	if b.s == nil {
		return nil, ErrUnauthenticated
	}
	return b.s.agentCapList(agentID)
}

func (b agentBinder) agentCapDescribe(agentID string, bound agentCapGrant) (agentCapView, error) {
	if b.s == nil {
		return agentCapView{}, ErrUnauthenticated
	}
	return b.s.agentCapDescribe(agentID, bound)
}

func (b agentBinder) agentCapInvoke(agentID, grantID string, payload []byte) (LocalAttestation, error) {
	if b.s == nil {
		return LocalAttestation{}, ErrUnauthenticated
	}
	return b.s.localAttestExact(agentID, grantID, payload)
}

func (b agentBinder) agentCapDeny(agentID string, invoke bool) error {
	if b.s == nil {
		return ErrUnauthenticated
	}
	return b.s.agentCapDeny(agentID, invoke)
}

func (s *Session) agentCapList(agentID string) ([]agentCapSnapshot, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	defer s.end()
	if err := s.requireCurrent(); err != nil {
		return nil, err
	}
	now, err := s.evaluationTime()
	if err != nil {
		return nil, s.denyAction(actionCapList, err)
	}
	if safeID(agentID) == "" {
		return nil, s.denyAction(actionCapList, ErrInvalid)
	}
	if !s.agentExists(agentID) {
		if err := s.finish(auditEvent{Action: actionCapList, Result: resultDeniedAgent}, ErrAgentNotFound); err != nil {
			return nil, err
		}
		return nil, ErrAgentNotFound
	}
	var snaps []agentCapSnapshot
	for _, g := range s.grants {
		if g.AgentID != agentID || !soleLocalAttest(g.Operations) || g.CredentialClass != "" || safeID(g.CredentialID) == "" || !canonicalKeyID(g.KeyID) {
			continue
		}
		snaps = append(snaps, agentCapSnapshot{
			agentCapGrant: agentCapGrant{
				grantID: g.ID, credID: g.CredentialID, keyID: g.KeyID, resource: g.Resource,
			},
			status:  s.attestCapStatus(g, now),
			expires: g.ExpiresAt.UTC(),
		})
	}
	slices.SortFunc(snaps, func(a, b agentCapSnapshot) int {
		return strings.Compare(a.grantID, b.grantID)
	})
	if len(snaps) > maxAgentCapEntries {
		if err := s.finish(auditEvent{Action: actionCapList, Result: resultDenied, AgentID: agentID}, nil); err != nil {
			return nil, err
		}
		return nil, ErrInvalid
	}
	if err := s.finish(auditEvent{Action: actionCapList, Result: resultAllowed, AgentID: agentID}, nil); err != nil {
		return nil, err
	}
	return snaps, nil
}

func (s *Session) attestCapStatus(g grantRecord, now time.Time) string {
	if g.RevokedAt != nil || (s.shared() && !s.provenanceLive(g.Provenance)) {
		return GrantRevoked
	}
	if !now.Before(g.ExpiresAt) {
		return GrantExpired
	}
	return GrantActive
}

func (s *Session) agentCapDescribe(agentID string, bound agentCapGrant) (agentCapView, error) {
	if err := s.begin(); err != nil {
		return agentCapView{}, err
	}
	defer s.end()
	if err := s.requireCurrent(); err != nil {
		return agentCapView{}, err
	}
	deny := s.boundAgentDenial(agentID)
	deny.Action = actionAgentCap
	g, ok := s.grantByID(bound.grantID)
	if !ok || g.AgentID != agentID || g.CredentialID != bound.credID || g.Resource != bound.resource || g.KeyID != bound.keyID || !soleLocalAttest(g.Operations) {
		if err := s.finish(deny, nil); err != nil {
			return agentCapView{}, err
		}
		return agentCapView{}, errCapStale
	}
	now, err := s.evaluationTime()
	if err != nil {
		if werr := s.finish(deny, nil); werr != nil {
			return agentCapView{}, werr
		}
		return agentCapView{}, err
	}
	ev := auditEvent{
		Action: actionAgentCap, Result: resultAllowed, AgentID: agentID, GrantID: g.ID,
		CredID: g.CredentialID, CredType: CredTypeEd25519, Operation: OpLocalArtifactAttest,
	}
	if err := s.finish(ev, nil); err != nil {
		return agentCapView{}, err
	}
	exp, err := requireTime(g.ExpiresAt)
	if err != nil {
		return agentCapView{}, ErrInvalid
	}
	return agentCapView{status: s.attestCapStatus(g, now), expires: exp}, nil
}

func (s *Session) agentCapDeny(agentID string, invoke bool) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	if err := s.requireCurrent(); err != nil {
		return err
	}
	ev := s.boundAgentDenial(agentID)
	ev.Action = actionAgentCap
	if invoke {
		ev.Action = actionLocalAttest
	}
	return s.finish(ev, nil)
}

func (s *Session) boundAgentDenial(agentID string) auditEvent {
	ev := auditEvent{Result: resultDenied}
	if safeID(agentID) != "" && s.agentExists(agentID) {
		ev.AgentID = agentID
	}
	return ev
}

// localAttestExact signs with grantID and no other grant. It does not retarget
// when the credential key changes or when another grant matches the payload.
func (s *Session) localAttestExact(agentID, grantID string, payload []byte) (LocalAttestation, error) {
	if err := s.begin(); err != nil {
		return LocalAttestation{}, err
	}
	defer s.end()
	if err := s.requireCurrent(); err != nil {
		return LocalAttestation{}, err
	}
	if s.agentExists(agentID) && !s.agentActive(agentID) {
		return s.attestDeny(s.destinationEvent(agentID, "", resultDeniedAgent, OpLocalArtifactAttest), ErrDeniedAgent)
	}
	if len(payload) == 0 || len(payload) > MaxAttestPayload {
		return s.attestDeny(s.boundAgentDenial(agentID), ErrInvalid)
	}
	priv, partial, cause := s.prepareExactAttest(agentID, grantID)
	if cause != nil {
		wipe(priv)
		if capHost(cause) {
			return LocalAttestation{}, cause
		}
		return s.attestDeny(partial, cause)
	}
	g, ok := s.grantByID(partial.GrantID)
	if !ok || g.Resource == "" {
		wipe(priv)
		partial.Result = resultFailed
		return s.attestDeny(partial, ErrSignFailed)
	}
	return s.releaseAttestation(partial, priv, g.Resource, payload)
}

// prepareExactAttest checks the named grant and its current key.
// A different matching grant is not selected.
func (s *Session) prepareExactAttest(agentID, grantID string) (ed25519.PrivateKey, auditEvent, error) {
	bare := s.boundAgentDenial(agentID)
	if safeID(agentID) == "" || !s.agentExists(agentID) || safeID(grantID) == "" {
		return nil, bare, ErrInvalid
	}
	g, ok := s.grantByID(grantID)
	if !ok || g.AgentID != agentID || !soleLocalAttest(g.Operations) || g.CredentialClass != "" || safeID(g.CredentialID) == "" || !canonicalKeyID(g.KeyID) {
		return nil, bare, ErrInvalid
	}
	partial := auditEvent{
		AgentID: agentID, GrantID: g.ID, CredID: g.CredentialID,
		CredType: CredTypeEd25519, Operation: OpLocalArtifactAttest,
	}
	if err := s.sharedGrantLive(grantID); err != nil {
		if capHost(err) {
			return nil, partial, err
		}
		partial.Result = resultDeniedRevoked
		if errors.Is(err, ErrDeniedExpired) {
			partial.Result = resultDeniedExpired
		}
		return nil, partial, err
	}
	if g.RevokedAt != nil {
		partial.Result = resultDeniedRevoked
		return nil, partial, ErrDeniedRevoked
	}
	now, err := s.evaluationTime()
	if err != nil {
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	if !now.Before(g.ExpiresAt) {
		partial.Result = resultDeniedExpired
		return nil, partial, ErrDeniedExpired
	}
	c, ok := s.credByID(g.CredentialID)
	if !ok || c.Type != CredTypeEd25519 || c.Lifecycle.State != StateActive {
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	secret, ok := s.copySecret(g.CredentialID)
	if !ok {
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	defer wipe(secret)
	priv, err := parseEd25519Private(secret)
	if err != nil {
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !keyBound(g.KeyID, pub) {
		wipe(priv)
		partial.Result = resultDeniedKey
		return nil, partial, ErrDeniedKey
	}
	return priv, partial, nil
}

func capHost(err error) bool {
	return errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrStale) || errors.Is(err, ErrAudit) || errors.Is(err, ErrIO) || errors.Is(err, ErrCorrupt) || errors.Is(err, ErrConflict)
}

func capFromErr(err error) string {
	switch {
	case errors.Is(err, ErrDeniedAgent), errors.Is(err, ErrAgentNotFound):
		return capDeniedAgent
	case errors.Is(err, ErrDeniedRevoked):
		return capDeniedRevoked
	case errors.Is(err, ErrDeniedExpired):
		return capDeniedExpired
	case errors.Is(err, ErrDeniedKey):
		return capDeniedKey
	case errors.Is(err, ErrSignFailed):
		return capFailed
	default:
		return capDenied
	}
}

func capText(code string) (string, bool) {
	switch code {
	case capMalformed:
		return "malformed message", true
	case capUnsupportedVersion:
		return "unsupported version", true
	case capUnknownMethod:
		return "unknown method", true
	case capUnsupported:
		return "method is not supported", true
	case capUnknownHandle:
		return "unknown handle", true
	case capDenied:
		return "request denied", true
	case capDeniedAgent:
		return "agent is not active", true
	case capDeniedRevoked:
		return "grant is revoked", true
	case capDeniedExpired:
		return "grant is expired", true
	case capDeniedKey:
		return "key identity does not match", true
	case capFailed:
		return "attestation failed", true
	default:
		return "", false
	}
}

type capWire struct {
	id  byte
	typ byte
	val []byte
}

type capRequest struct {
	method  byte
	handle  [32]byte
	payload []byte
}

type capEntry struct {
	handle    [32]byte
	operation string
	resource  string
	keyID     string
	status    string
	expires   time.Time
}

type capResponse struct {
	method  byte
	code    string
	message string
	entries []capEntry
	entry   capEntry
	att     LocalAttestation
}

func parseCapRequest(msg []byte) (capRequest, string) {
	if len(msg) == 0 {
		return capRequest{}, capMalformed
	}
	// Keep a version-1 method byte when the body is not parsed. A malformed
	// invoke is audited as local_attest; other methods stay agent_capability.
	if len(msg) > MaxAgentCapMessage {
		if msg[0] == AgentCapVersion && len(msg) >= 2 {
			return capRequest{method: msg[1]}, capMalformed
		}
		return capRequest{}, capMalformed
	}
	if msg[0] != AgentCapVersion {
		return capRequest{}, capUnsupportedVersion
	}
	if len(msg) < 4 {
		var req capRequest
		if len(msg) >= 2 {
			req.method = msg[1]
		}
		return req, capMalformed
	}
	method := msg[1]
	n := binary.BigEndian.Uint16(msg[2:4])
	fields, rest, code := parseCapFields(msg[4:], n)
	if code != "" {
		return capRequest{method: method}, code
	}
	if len(rest) != 0 {
		return capRequest{method: method}, capMalformed
	}
	switch method {
	case capMethodList:
		if len(fields) != 0 {
			return capRequest{method: method}, capMalformed
		}
		return capRequest{method: method}, ""
	case capMethodDescribe:
		handle, ok := capExactBytes(fields, capFieldHandle, 32)
		if !ok || len(fields) != 1 {
			return capRequest{method: method}, capMalformed
		}
		var req capRequest
		req.method = method
		copy(req.handle[:], handle)
		return req, ""
	case capMethodInvoke:
		handle, hok := capExactBytes(fields, capFieldHandle, 32)
		payload, pok := fields[capFieldPayload]
		if !hok || !pok || payload.typ != capTypeBytes || len(fields) != 2 || len(payload.val) == 0 || len(payload.val) > MaxAttestPayload {
			return capRequest{method: method}, capMalformed
		}
		var req capRequest
		req.method = method
		copy(req.handle[:], handle)
		req.payload = append([]byte(nil), payload.val...)
		return req, ""
	case capMethodRequest:
		if len(fields) != 0 {
			return capRequest{method: method}, capMalformed
		}
		return capRequest{method: method}, capUnsupported
	default:
		return capRequest{method: method}, capUnknownMethod
	}
}

func parseCapFields(buf []byte, n uint16) (map[byte]capWire, []byte, string) {
	if n > maxCapFields {
		return nil, nil, capMalformed
	}
	fields := make(map[byte]capWire, n)
	for i := 0; i < int(n); i++ {
		if len(buf) < 6 {
			return nil, nil, capMalformed
		}
		id, typ := buf[0], buf[1]
		ln := binary.BigEndian.Uint32(buf[2:6])
		if uint64(ln) > uint64(len(buf)-6) {
			return nil, nil, capMalformed
		}
		if _, dup := fields[id]; dup || id == 0 || (typ != capTypeBytes && typ != capTypeString) {
			return nil, nil, capMalformed
		}
		val := buf[6 : 6+ln]
		if typ == capTypeString && (!utf8.Valid(val) || bytes.Contains(val, []byte{0})) {
			return nil, nil, capMalformed
		}
		fields[id] = capWire{id: id, typ: typ, val: append([]byte(nil), val...)}
		buf = buf[6+ln:]
	}
	return fields, buf, ""
}

func capExactBytes(fields map[byte]capWire, id byte, n int) ([]byte, bool) {
	f, ok := fields[id]
	if !ok || f.typ != capTypeBytes || len(f.val) != n {
		return nil, false
	}
	return f.val, true
}

func encodeCapError(code string) ([]byte, error) {
	text, ok := capText(code)
	if !ok {
		code, text = capDenied, "request denied"
	}
	return encodeCap(capMethodError, []capWire{
		{id: capFieldCode, typ: capTypeString, val: []byte(code)},
		{id: capFieldMessage, typ: capTypeString, val: []byte(text)},
	})
}

func encodeCap(method byte, fields []capWire) ([]byte, error) {
	slices.SortFunc(fields, func(a, b capWire) int { return int(a.id) - int(b.id) })
	seen := map[byte]struct{}{}
	body := make([]byte, 0, 64)
	for _, f := range fields {
		if _, dup := seen[f.id]; dup || (f.typ != capTypeBytes && f.typ != capTypeString) {
			return nil, ErrInvalid
		}
		if f.typ == capTypeString && (!utf8.Valid(f.val) || bytes.Contains(f.val, []byte{0})) {
			return nil, ErrInvalid
		}
		seen[f.id] = struct{}{}
		body = appendCapField(body, f)
	}
	if len(fields) > maxCapFields || 4+len(body) > MaxAgentCapMessage {
		return nil, ErrInvalid
	}
	out := make([]byte, 4, 4+len(body))
	out[0] = AgentCapVersion
	out[1] = method
	binary.BigEndian.PutUint16(out[2:4], uint16(len(fields)))
	out = append(out, body...)
	return out, nil
}

func appendCapField(dst []byte, f capWire) []byte {
	dst = append(dst, f.id, f.typ)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(f.val)))
	dst = append(dst, n[:]...)
	return append(dst, f.val...)
}

func encodeCatalog(entries []capEntry) ([]byte, error) {
	if len(entries) > maxAgentCapEntries {
		return nil, ErrInvalid
	}
	body := make([]byte, 2, 2+len(entries)*64)
	binary.BigEndian.PutUint16(body[:2], uint16(len(entries)))
	for _, e := range entries {
		raw, err := encodeEntry(e)
		if err != nil {
			return nil, err
		}
		body = append(body, raw...)
	}
	return body, nil
}

func encodeEntry(e capEntry) ([]byte, error) {
	if e.operation != OpLocalArtifactAttest || !capStatusOK(e.status) || !canonicalKeyID(e.keyID) || validateResource(e.resource) != nil {
		return nil, ErrInvalid
	}
	exp, err := requireTime(e.expires)
	if err != nil {
		return nil, err
	}
	fields := []capWire{
		{id: capFieldHandle, typ: capTypeBytes, val: e.handle[:]},
		{id: capFieldOperation, typ: capTypeString, val: []byte(e.operation)},
		{id: capFieldResource, typ: capTypeString, val: []byte(e.resource)},
		{id: capFieldKeyID, typ: capTypeString, val: []byte(e.keyID)},
		{id: capFieldStatus, typ: capTypeString, val: []byte(e.status)},
		{id: capFieldExpiry, typ: capTypeString, val: []byte(exp.Format(time.RFC3339Nano))},
	}
	slices.SortFunc(fields, func(a, b capWire) int { return int(a.id) - int(b.id) })
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body[:2], uint16(len(fields)))
	for _, f := range fields {
		body = appendCapField(body, f)
	}
	return body, nil
}

func decodeCapResponse(msg []byte) (capResponse, error) {
	if len(msg) == 0 || len(msg) > MaxAgentCapMessage || msg[0] != AgentCapVersion || len(msg) < 4 {
		return capResponse{}, ErrInvalid
	}
	method := msg[1]
	n := binary.BigEndian.Uint16(msg[2:4])
	fields, rest, code := parseCapFields(msg[4:], n)
	if code != "" || len(rest) != 0 {
		return capResponse{}, ErrInvalid
	}
	switch method {
	case capMethodError:
		return decodeCapError(fields)
	case capMethodList:
		return decodeCapList(fields)
	case capMethodDescribe:
		entry, err := decodeCapEntryFields(fields)
		if err != nil {
			return capResponse{}, err
		}
		return capResponse{method: method, entry: entry}, nil
	case capMethodInvoke:
		return decodeCapInvoke(fields)
	default:
		return capResponse{}, ErrInvalid
	}
}

func decodeCapError(fields map[byte]capWire) (capResponse, error) {
	code, cok := fields[capFieldCode]
	text, tok := fields[capFieldMessage]
	if !cok || !tok || len(fields) != 2 || code.typ != capTypeString || text.typ != capTypeString {
		return capResponse{}, ErrInvalid
	}
	want, ok := capText(string(code.val))
	if !ok || string(text.val) != want {
		return capResponse{}, ErrInvalid
	}
	return capResponse{method: capMethodError, code: string(code.val), message: want}, nil
}

func decodeCapList(fields map[byte]capWire) (capResponse, error) {
	cat, ok := fields[capFieldCatalog]
	if !ok || len(fields) != 1 || cat.typ != capTypeBytes || len(cat.val) < 2 {
		return capResponse{}, ErrInvalid
	}
	n := binary.BigEndian.Uint16(cat.val[:2])
	if int(n) > maxAgentCapEntries {
		return capResponse{}, ErrInvalid
	}
	buf := cat.val[2:]
	entries := make([]capEntry, 0, n)
	for i := 0; i < int(n); i++ {
		if len(buf) < 2 {
			return capResponse{}, ErrInvalid
		}
		fn := binary.BigEndian.Uint16(buf[:2])
		parsed, rest, code := parseCapFields(buf[2:], fn)
		if code != "" {
			return capResponse{}, ErrInvalid
		}
		entry, err := decodeCapEntryFields(parsed)
		if err != nil {
			return capResponse{}, err
		}
		entries = append(entries, entry)
		buf = rest
	}
	if len(buf) != 0 {
		return capResponse{}, ErrInvalid
	}
	return capResponse{method: capMethodList, entries: entries}, nil
}

func decodeCapEntryFields(fields map[byte]capWire) (capEntry, error) {
	handle, hok := capExactBytes(fields, capFieldHandle, 32)
	op, ook := capString(fields, capFieldOperation)
	resource, rok := capString(fields, capFieldResource)
	keyID, kok := capString(fields, capFieldKeyID)
	status, sok := capString(fields, capFieldStatus)
	expiry, eok := capString(fields, capFieldExpiry)
	if !hok || !ook || !rok || !kok || !sok || !eok || len(fields) != 6 {
		return capEntry{}, ErrInvalid
	}
	if op != OpLocalArtifactAttest || !capStatusOK(status) || !canonicalKeyID(keyID) || validateResource(resource) != nil {
		return capEntry{}, ErrInvalid
	}
	exp, ok := canonicalAuditTime(expiry)
	if !ok {
		return capEntry{}, ErrInvalid
	}
	var entry capEntry
	copy(entry.handle[:], handle)
	entry.operation = op
	entry.resource = resource
	entry.keyID = keyID
	entry.status = status
	entry.expires = exp
	return entry, nil
}

func decodeCapInvoke(fields map[byte]capWire) (capResponse, error) {
	sig, sok := capExactBytes(fields, capFieldSignature, ed25519.SignatureSize)
	pub, pok := capExactBytes(fields, capFieldPublicKey, ed25519.PublicKeySize)
	domain, dok := capString(fields, capFieldDomain)
	purpose, uok := capString(fields, capFieldPurpose)
	resource, rok := capString(fields, capFieldResource)
	if !sok || !pok || !dok || !uok || !rok || len(fields) != 5 || domain != AttestDomain || purpose != AttestPurpose || validateResource(resource) != nil {
		return capResponse{}, ErrInvalid
	}
	var att LocalAttestation
	copy(att.Signature[:], sig)
	copy(att.PublicKey[:], pub)
	att.Domain = domain
	att.Purpose = purpose
	att.Resource = resource
	return capResponse{method: capMethodInvoke, att: att}, nil
}

func capString(fields map[byte]capWire, id byte) (string, bool) {
	f, ok := fields[id]
	if !ok || f.typ != capTypeString {
		return "", false
	}
	return string(f.val), true
}

func capStatusOK(status string) bool {
	return status == GrantActive || status == GrantRevoked || status == GrantExpired
}

func encodeCapList() ([]byte, error) {
	return encodeCap(capMethodList, nil)
}

func encodeCapDescribe(handle [32]byte) ([]byte, error) {
	return encodeCap(capMethodDescribe, []capWire{{id: capFieldHandle, typ: capTypeBytes, val: handle[:]}})
}

func encodeCapInvoke(handle [32]byte, payload []byte) ([]byte, error) {
	return encodeCap(capMethodInvoke, []capWire{
		{id: capFieldHandle, typ: capTypeBytes, val: handle[:]},
		{id: capFieldPayload, typ: capTypeBytes, val: payload},
	})
}

func encodeCapRequest() ([]byte, error) {
	return encodeCap(capMethodRequest, nil)
}

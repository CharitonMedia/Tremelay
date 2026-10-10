package vault

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	// OpSSHUserAuth authorizes one host-bound SSH user authentication signature.
	// It is not an alias of sign, local_artifact_attest, http_request, or github_issue_state.
	OpSSHUserAuth = "ssh_userauth"

	// SSH userauth limits. The frame cap is the SSH agent length field, not
	// including the 4-byte prefix. Inner caps are tighter than the frame so a
	// length that fits in the frame can still be rejected before a copy.
	MaxSSHFrame     = 4 << 10
	MaxSSHPreimage  = 1 << 10
	MinSSHSessionID = 1
	MaxSSHSessionID = 64
	MaxSSHUsername  = 256

	sshAlgoEd25519        = "ssh-ed25519"
	sshServiceConnection  = "ssh-connection"
	sshUserAuthMethod     = "publickey-hostbound-v00@openssh.com"
	sshExtSessionBind     = "session-bind@openssh.com"
	sshMsgUserAuthRequest = 50

	sshAgentFailure           = 5
	sshAgentSuccess           = 6
	sshAgentRequestIdentities = 11
	sshAgentIdentitiesAnswer  = 12
	sshAgentSignRequest       = 13
	sshAgentSignResponse      = 14
	sshAgentExtension         = 27
	sshAgentExtensionFailure  = 28

	// Canonical ssh-ed25519 public key and signature blobs (RFC 8709).
	sshEd25519BlobLen = 51
	sshEd25519SigLen  = 83
	maxSSHExtName     = 64
)

// SSHUserAuth is one protocol stream bound to one existing principal and one
// selected ssh_userauth grant. Wire messages cannot choose the principal,
// grant, credential, resource, clock, or host key. The unlocked Session is not
// safe for concurrent callers. Serve and roundTrip serialize this stream's
// state transitions and signing on mu; the host must not call other Session
// methods on another goroutine while one of those calls is running.
//
// A binding is one verified host-key signature over one session identifier
// with is_forwarding false. It is not proof of a live local SSH transport.
// The same proof can be replayed on a new stream. Close, EOF, and a hard
// stream error drop the binding and wipe the buffers owned by this stream.
type SSHUserAuth struct {
	broker  sshBroker
	agentID string
	grantID string

	mu        sync.Mutex
	closed    bool
	bound     bool
	hostKey   []byte
	sessionID []byte
	hostSig   []byte
}

// sshBroker is the in-process session surface used by one stream.
// It is not *Session, and it has no boolean that marks a host or a session as trusted.
type sshBroker interface {
	sshConstruct(agentID, grantID string) error
	sshJudge(agentID, grantID string) (auditEvent, []byte, error)
	sshRecord(ev auditEvent) error
	sshShowKey(agentID, grantID string, hostKey, sessionID, hostSig []byte) ([]byte, error)
	sshRelease(agentID, grantID string, hostKey, sessionID, hostSig, signBody []byte) ([]byte, error)
}

// SSHUserAuth binds a new stream to grantID. grantID must already name an
// ssh_userauth grant for this principal. Construction does not sign, does not
// write an allow row, and does not make an expired, revoked, or otherwise
// unusable grant usable. A different grant needs a different stream.
func (a *AgentPrincipal) SSHUserAuth(grantID string) (*SSHUserAuth, error) {
	if a == nil || a.view == nil {
		return nil, ErrUnauthenticated
	}
	broker, ok := a.view.(sshBroker)
	if !ok {
		return nil, ErrUnauthenticated
	}
	if err := broker.sshConstruct(a.id, grantID); err != nil {
		return nil, err
	}
	return &SSHUserAuth{broker: broker, agentID: a.id, grantID: grantID}, nil
}

// Serve reads SSH agent frames from rw until EOF. A clean EOF before the next
// frame returns nil. A partial frame, an oversize length, an audit failure, or
// a locked session returns a fixed error and writes no signature. Close runs
// on every return and wipes the binding.
func (a *SSHUserAuth) Serve(rw io.ReadWriter) error {
	if a == nil || a.broker == nil {
		return ErrUnauthenticated
	}
	defer a.Close()
	for {
		body, err := readSSHFrame(rw)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return a.noteFrameErr(err)
		}
		resp, herr := a.roundTrip(body)
		wipe(body)
		if herr != nil {
			return herr
		}
		if _, werr := rw.Write(frameSSH(resp)); werr != nil {
			wipe(resp)
			return werr
		}
		wipe(resp)
	}
}

// Close drops the binding and wipes stream-owned buffers. It waits until an
// in-flight roundTrip on this stream finishes, then rejects later requests.
func (a *SSHUserAuth) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.bound = false
	wipe(a.hostKey)
	wipe(a.sessionID)
	wipe(a.hostSig)
	a.hostKey, a.sessionID, a.hostSig = nil, nil, nil
}

// roundTrip handles one unframed agent message with the same gate Serve uses.
func (a *SSHUserAuth) roundTrip(body []byte) ([]byte, error) {
	if a == nil || a.broker == nil {
		return nil, ErrUnauthenticated
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrInvalid
	}
	return a.handle(body)
}

func (a *SSHUserAuth) noteFrameErr(err error) error {
	ev, _, jerr := a.broker.sshJudge(a.agentID, a.grantID)
	if errors.Is(jerr, ErrUnauthenticated) {
		return jerr
	}
	if jerr != nil {
		if rec := a.broker.sshRecord(ev); rec != nil {
			return rec
		}
		return err
	}
	ev.Result = resultDenied
	if rec := a.broker.sshRecord(ev); rec != nil {
		return rec
	}
	return err
}

func (a *SSHUserAuth) handle(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return a.deny(resultDenied)
	}
	ev, pinned, jerr := a.broker.sshJudge(a.agentID, a.grantID)
	if errors.Is(jerr, ErrUnauthenticated) {
		return nil, jerr
	}
	if jerr != nil {
		if rec := a.broker.sshRecord(ev); rec != nil {
			return nil, rec
		}
		if body[0] == sshAgentRequestIdentities && len(body) == 1 {
			return sshEmptyIdentities(), nil
		}
		return []byte{sshAgentFailure}, nil
	}
	switch body[0] {
	case sshAgentRequestIdentities:
		return a.identities(body, ev)
	case sshAgentSignRequest:
		return a.sign(body, ev)
	case sshAgentExtension:
		return a.extension(body, ev, pinned)
	default:
		// Opcode only. The rest of the frame is not a key, password, or provider.
		ev.Result = resultDenied
		if rec := a.broker.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return []byte{sshAgentFailure}, nil
	}
}

func (a *SSHUserAuth) identities(body []byte, ev auditEvent) ([]byte, error) {
	if len(body) != 1 {
		return a.record(ev, resultDenied, []byte{sshAgentFailure})
	}
	if !a.bound {
		return a.record(ev, resultDenied, sshEmptyIdentities())
	}
	blob, err := a.broker.sshShowKey(a.agentID, a.grantID, a.hostKey, a.sessionID, a.hostSig)
	if err != nil {
		if stopSSH(err) {
			return nil, err
		}
		return sshEmptyIdentities(), nil
	}
	return sshIdentities(blob), nil
}

func (a *SSHUserAuth) sign(body []byte, ev auditEvent) ([]byte, error) {
	if !a.bound {
		return a.record(ev, resultDenied, []byte{sshAgentFailure})
	}
	sig, err := a.broker.sshRelease(a.agentID, a.grantID, a.hostKey, a.sessionID, a.hostSig, body)
	if err != nil {
		if stopSSH(err) {
			return nil, err
		}
		return []byte{sshAgentFailure}, nil
	}
	return sshSignResponse(sig), nil
}

func (a *SSHUserAuth) extension(body []byte, ev auditEvent, pinned []byte) ([]byte, error) {
	name, rest, kind := takeExtName(body)
	if kind != extNameOK {
		code := byte(sshAgentFailure)
		if kind == extNameUnknown {
			code = sshAgentExtensionFailure
		}
		return a.record(ev, resultDenied, []byte{code})
	}
	if name != sshExtSessionBind {
		return a.record(ev, resultDenied, []byte{sshAgentExtensionFailure})
	}
	if a.bound {
		return a.record(ev, resultDenied, []byte{sshAgentFailure})
	}
	host, sid, sig, ok := parseSessionBind(rest)
	if !ok || !sshBytesEq(host, pinned) || !verifyHostBind(pinned, sid, sig) {
		return a.record(ev, resultDenied, []byte{sshAgentFailure})
	}
	a.hostKey = dup(host)
	a.sessionID = dup(sid)
	a.hostSig = dup(sig)
	a.bound = true
	// A successful bind is not a signature release and writes no allow row.
	return []byte{sshAgentSuccess}, nil
}

func (a *SSHUserAuth) deny(result string) ([]byte, error) {
	ev, _, jerr := a.broker.sshJudge(a.agentID, a.grantID)
	if errors.Is(jerr, ErrUnauthenticated) {
		return nil, jerr
	}
	if jerr != nil {
		if rec := a.broker.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return []byte{sshAgentFailure}, nil
	}
	return a.record(ev, result, []byte{sshAgentFailure})
}

func (a *SSHUserAuth) record(ev auditEvent, result string, resp []byte) ([]byte, error) {
	ev.Result = result
	if rec := a.broker.sshRecord(ev); rec != nil {
		return nil, rec
	}
	return resp, nil
}

func stopSSH(err error) bool {
	return errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrAudit) || errors.Is(err, ErrIO)
}

func (b agentBinder) sshConstruct(agentID, grantID string) error {
	if b.s == nil {
		return ErrUnauthenticated
	}
	return b.s.sshConstruct(agentID, grantID)
}

func (b agentBinder) sshJudge(agentID, grantID string) (auditEvent, []byte, error) {
	if b.s == nil {
		return auditEvent{}, nil, ErrUnauthenticated
	}
	return b.s.sshJudge(agentID, grantID)
}

func (b agentBinder) sshRecord(ev auditEvent) error {
	if b.s == nil {
		return ErrUnauthenticated
	}
	return b.s.sshRecord(ev)
}

func (b agentBinder) sshShowKey(agentID, grantID string, hostKey, sessionID, hostSig []byte) ([]byte, error) {
	if b.s == nil {
		return nil, ErrUnauthenticated
	}
	return b.s.sshShowKey(agentID, grantID, hostKey, sessionID, hostSig)
}

func (b agentBinder) sshRelease(agentID, grantID string, hostKey, sessionID, hostSig, signBody []byte) ([]byte, error) {
	if b.s == nil {
		return nil, ErrUnauthenticated
	}
	return b.s.sshRelease(agentID, grantID, hostKey, sessionID, hostSig, signBody)
}

func (s *Session) sshConstruct(agentID, grantID string) error {
	if err := s.live(); err != nil {
		return err
	}
	if safeID(agentID) == "" || safeID(grantID) == "" {
		return ErrInvalid
	}
	if !s.agentExists(agentID) {
		return ErrDeniedAgent
	}
	g, ok := s.grantByID(grantID)
	if !ok {
		return ErrGrantNotFound
	}
	if g.AgentID != agentID {
		return ErrDeniedAgent
	}
	if !sshGrantShape(g) {
		return ErrDeniedOperation
	}
	c, ok := s.credByID(g.CredentialID)
	if !ok || c.Type != CredTypeEd25519 {
		return ErrInvalid
	}
	return nil
}

// sshJudge re-reads the selected grant. It does not look for another grant,
// and it does not write an audit row.
func (s *Session) sshJudge(agentID, grantID string) (auditEvent, []byte, error) {
	if err := s.live(); err != nil {
		return auditEvent{}, nil, err
	}
	ev := auditEvent{Action: actionSSHUserAuth, AgentID: agentID, GrantID: grantID, Operation: OpSSHUserAuth}
	if safeID(agentID) == "" || !s.agentExists(agentID) {
		ev.AgentID = ""
		ev.GrantID = ""
		ev.Operation = ""
		ev.Result = resultDeniedAgent
		return ev, nil, ErrDeniedAgent
	}
	g, ok := s.grantByID(grantID)
	if ok && g.AgentID == agentID && g.CredentialID != "" {
		ev.CredID = g.CredentialID
		ev.CredType = CredTypeEd25519
	}
	if !s.agentActive(agentID) {
		ev.Result = resultDeniedAgent
		return ev, nil, ErrDeniedAgent
	}
	if !ok || g.AgentID != agentID || !sshGrantShape(g) {
		ev.Result = resultFailed
		return ev, nil, ErrSignFailed
	}
	if g.RevokedAt != nil {
		ev.Result = resultDeniedRevoked
		return ev, nil, ErrDeniedRevoked
	}
	now, err := s.evaluationTime()
	if err != nil || !now.Before(g.ExpiresAt) {
		ev.Result = resultDeniedExpired
		return ev, nil, ErrDeniedExpired
	}
	priv, err := s.sshPrivate(g)
	wipe(priv)
	if err != nil {
		ev.Result = resultFrom(err)
		return ev, nil, err
	}
	return ev, dup(g.SSHHostKey), nil
}

func (s *Session) sshRecord(ev auditEvent) error {
	if err := s.live(); err != nil {
		return err
	}
	ev.Action = actionSSHUserAuth
	return s.finish(ev, nil)
}

func (s *Session) sshShowKey(agentID, grantID string, hostKey, sessionID, hostSig []byte) ([]byte, error) {
	ev, pinned, err := s.sshJudge(agentID, grantID)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			return nil, err
		}
		if rec := s.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return nil, err
	}
	if !sshProof(pinned, hostKey, sessionID, hostSig) {
		ev.Result = resultDenied
		if rec := s.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return nil, ErrInvalid
	}
	blob, err := s.sshUserBlob(grantID)
	if err != nil {
		ev.Result = resultFrom(err)
		if rec := s.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return nil, err
	}
	ev.Result = resultAllowed
	if rec := s.sshRecord(ev); rec != nil {
		return nil, rec
	}
	return blob, nil
}

func (s *Session) sshRelease(agentID, grantID string, hostKey, sessionID, hostSig, signBody []byte) ([]byte, error) {
	ev, pinned, err := s.sshJudge(agentID, grantID)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			return nil, err
		}
		if rec := s.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return nil, err
	}
	userBlob, uerr := s.sshUserBlob(grantID)
	if uerr != nil {
		ev.Result = resultFrom(uerr)
		if rec := s.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return nil, uerr
	}
	if !sshProof(pinned, hostKey, sessionID, hostSig) || !sshSignBody(pinned, sessionID, signBody, s.grantUser(grantID), userBlob) {
		ev.Result = resultDenied
		if rec := s.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return nil, ErrInvalid
	}
	// Allowed is durable before the private key is used.
	ev.Result = resultAllowed
	if rec := s.sshRecord(ev); rec != nil {
		return nil, rec
	}
	g, _ := s.grantByID(grantID)
	priv, err := s.sshPrivate(g)
	if err != nil {
		wipe(priv)
		ev.Result = resultFrom(err)
		if rec := s.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return nil, err
	}
	if s.sshFault != nil {
		if faultErr := s.sshFault(); faultErr != nil {
			wipe(priv)
			ev.Result = resultFailed
			if rec := s.sshRecord(ev); rec != nil {
				return nil, rec
			}
			return nil, ErrSignFailed
		}
	}
	preimage := sshSignData(signBody)
	if len(preimage) == 0 {
		wipe(priv)
		ev.Result = resultFailed
		if rec := s.sshRecord(ev); rec != nil {
			return nil, rec
		}
		return nil, ErrSignFailed
	}
	raw := ed25519.Sign(priv, preimage)
	wipe(priv)
	wipe(preimage)
	blob := marshalEd25519Sig(raw)
	wipe(raw)
	ev.Result = resultCompleted
	if rec := s.sshRecord(ev); rec != nil {
		wipe(blob)
		return nil, rec
	}
	return blob, nil
}

func (s *Session) sshPrivate(g grantRecord) (ed25519.PrivateKey, error) {
	c, ok := s.credByID(g.CredentialID)
	if !ok || c.Type != CredTypeEd25519 || c.Lifecycle.State != StateActive {
		return nil, ErrSignFailed
	}
	secret, ok := s.copySecret(g.CredentialID)
	if !ok {
		return nil, ErrSignFailed
	}
	defer wipe(secret)
	priv, err := parseEd25519Private(secret)
	if err != nil {
		return nil, ErrSignFailed
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !keyBound(g.KeyID, pub) {
		wipe(priv)
		if ok && len(pub) == ed25519.PublicKeySize {
			return nil, ErrDeniedKey
		}
		return nil, ErrSignFailed
	}
	return priv, nil
}

func (s *Session) sshUserBlob(grantID string) ([]byte, error) {
	g, ok := s.grantByID(grantID)
	if !ok {
		return nil, ErrSignFailed
	}
	priv, err := s.sshPrivate(g)
	if err != nil {
		wipe(priv)
		return nil, err
	}
	defer wipe(priv)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return marshalEd25519Pub(pub), nil
}

func (s *Session) grantUser(grantID string) string {
	g, ok := s.grantByID(grantID)
	if !ok {
		return ""
	}
	return g.SSHUsername
}

func resultFrom(err error) string {
	switch {
	case errors.Is(err, ErrDeniedKey):
		return resultDeniedKey
	default:
		return resultFailed
	}
}

// screenSSHKey checks the grant Authorize already selected. It does not move
// the decision onto a different grant when the credential key has changed.
func (s *Session) screenSSHKey(partial auditEvent) (auditEvent, error) {
	g, ok := s.grantByID(partial.GrantID)
	if !ok || g.AgentID != partial.AgentID || !sshGrantShape(g) || g.CredentialID != partial.CredID {
		partial.Result = resultFailed
		return partial, ErrSignFailed
	}
	priv, err := s.sshPrivate(g)
	wipe(priv)
	if err != nil {
		partial.Result = resultFrom(err)
		return partial, err
	}
	return partial, nil
}

func sshGrantOK(ops []string, spec GrantSpec, credType string) error {
	has := false
	for _, op := range ops {
		if op == OpSSHUserAuth {
			has = true
		}
	}
	if !has {
		if spec.SSHUsername != "" || len(spec.SSHHostKey) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if !soleSSH(ops) || spec.CredentialClass != "" || spec.CredentialID == "" || credType != CredTypeEd25519 {
		return ErrInvalid
	}
	if !validSSHUsername(spec.SSHUsername) || !canonicalSSHEd25519Blob(spec.SSHHostKey) {
		return ErrInvalid
	}
	return nil
}

func soleSSH(ops []string) bool {
	return len(ops) == 1 && ops[0] == OpSSHUserAuth
}

func sshGrantShape(g grantRecord) bool {
	return g.CredentialClass == "" && g.CredentialID != "" && soleSSH(g.Operations) &&
		canonicalKeyID(g.KeyID) && validSSHUsername(g.SSHUsername) && canonicalSSHEd25519Blob(g.SSHHostKey)
}

func sshCredScope(g grantRecord, op string) bool {
	if op != OpSSHUserAuth {
		return true
	}
	return sshGrantShape(g)
}

func validateSSHGrant(g grantRecord, types map[string]string) error {
	has := false
	for _, op := range g.Operations {
		if op == OpSSHUserAuth {
			has = true
		}
	}
	if !has {
		if g.SSHUsername != "" || len(g.SSHHostKey) != 0 {
			return ErrCorrupt
		}
		return nil
	}
	if !sshGrantShape(g) || types[g.CredentialID] != CredTypeEd25519 {
		return ErrCorrupt
	}
	return nil
}

func validSSHUsername(s string) bool {
	if s == "" || len(s) > MaxSSHUsername || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func canonicalSSHEd25519Blob(blob []byte) bool {
	_, ok := parseEd25519Blob(blob)
	return ok
}

func parseEd25519Blob(blob []byte) (ed25519.PublicKey, bool) {
	if len(blob) != sshEd25519BlobLen {
		return nil, false
	}
	algo, rest, ok := takeSSHBytes(blob, len(sshAlgoEd25519))
	if !ok || string(algo) != sshAlgoEd25519 {
		return nil, false
	}
	key, rest, ok := takeSSHBytes(rest, ed25519.PublicKeySize)
	if !ok || len(key) != ed25519.PublicKeySize || len(rest) != 0 {
		return nil, false
	}
	again := marshalEd25519Pub(key)
	if !sshBytesEq(again, blob) {
		return nil, false
	}
	out := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(out, key)
	return out, true
}

func parseEd25519Sig(blob []byte) ([]byte, bool) {
	if len(blob) != sshEd25519SigLen {
		return nil, false
	}
	algo, rest, ok := takeSSHBytes(blob, len(sshAlgoEd25519))
	if !ok || string(algo) != sshAlgoEd25519 {
		return nil, false
	}
	raw, rest, ok := takeSSHBytes(rest, ed25519.SignatureSize)
	if !ok || len(raw) != ed25519.SignatureSize || len(rest) != 0 {
		return nil, false
	}
	out := make([]byte, ed25519.SignatureSize)
	copy(out, raw)
	return out, true
}

func marshalEd25519Pub(pub ed25519.PublicKey) []byte {
	out := appendSSHString(nil, []byte(sshAlgoEd25519))
	return appendSSHString(out, pub)
}

func marshalEd25519Sig(raw []byte) []byte {
	out := appendSSHString(nil, []byte(sshAlgoEd25519))
	return appendSSHString(out, raw)
}

func verifyHostBind(hostBlob, sessionID, sigBlob []byte) bool {
	if len(sessionID) < MinSSHSessionID || len(sessionID) > MaxSSHSessionID {
		return false
	}
	pub, ok := parseEd25519Blob(hostBlob)
	if !ok {
		return false
	}
	raw, ok := parseEd25519Sig(sigBlob)
	if !ok {
		wipe(raw)
		return false
	}
	ok = ed25519.Verify(pub, sessionID, raw)
	wipe(raw)
	return ok
}

func sshProof(pinned, hostKey, sessionID, hostSig []byte) bool {
	return sshBytesEq(pinned, hostKey) && verifyHostBind(pinned, sessionID, hostSig)
}

func sshSignBody(pinned, sessionID, body []byte, user string, userBlob []byte) bool {
	key, data, flags, ok := parseSignBody(body)
	if !ok || flags != 0 || !canonicalSSHEd25519Blob(userBlob) || !sshBytesEq(key, userBlob) {
		return false
	}
	parts, ok := parseUserauth(data)
	if !ok || !validSSHUsername(parts.user) || parts.user != user {
		return false
	}
	return sshBytesEq(parts.sessionID, sessionID) && sshBytesEq(parts.hostKey, pinned) && sshBytesEq(parts.userKey, userBlob)
}

// sshSignData returns the exact bytes to sign: the data string inside the
// agent sign request, which is the userauth preimage. It is not a local-attestation message.
func sshSignData(body []byte) []byte {
	_, data, _, ok := parseSignBody(body)
	if !ok {
		return nil
	}
	return dup(data)
}

type userauthParts struct {
	sessionID []byte
	user      string
	userKey   []byte
	hostKey   []byte
}

func parseUserauth(data []byte) (userauthParts, bool) {
	var zero userauthParts
	if len(data) == 0 || len(data) > MaxSSHPreimage {
		return zero, false
	}
	sid, rest, ok := takeSSHBytes(data, MaxSSHSessionID)
	if !ok || len(sid) < MinSSHSessionID {
		return zero, false
	}
	if len(rest) < 1 || rest[0] != sshMsgUserAuthRequest {
		return zero, false
	}
	rest = rest[1:]
	user, rest, ok := takeSSHBytes(rest, MaxSSHUsername)
	if !ok {
		return zero, false
	}
	service, rest, ok := takeSSHBytes(rest, len(sshServiceConnection))
	if !ok || string(service) != sshServiceConnection {
		return zero, false
	}
	method, rest, ok := takeSSHBytes(rest, len(sshUserAuthMethod))
	if !ok || string(method) != sshUserAuthMethod {
		return zero, false
	}
	if len(rest) < 1 || rest[0] != 1 {
		return zero, false
	}
	rest = rest[1:]
	algo, rest, ok := takeSSHBytes(rest, len(sshAlgoEd25519))
	if !ok || string(algo) != sshAlgoEd25519 {
		return zero, false
	}
	userKey, rest, ok := takeSSHBytes(rest, sshEd25519BlobLen)
	if !ok || len(userKey) != sshEd25519BlobLen {
		return zero, false
	}
	hostKey, rest, ok := takeSSHBytes(rest, sshEd25519BlobLen)
	if !ok || len(hostKey) != sshEd25519BlobLen || len(rest) != 0 {
		return zero, false
	}
	return userauthParts{sessionID: sid, user: string(user), userKey: userKey, hostKey: hostKey}, true
}

func parseSignBody(body []byte) (key, data []byte, flags uint32, ok bool) {
	if len(body) < 1 || body[0] != sshAgentSignRequest {
		return nil, nil, 0, false
	}
	rest := body[1:]
	key, rest, ok = takeSSHBytes(rest, sshEd25519BlobLen)
	if !ok || len(key) != sshEd25519BlobLen {
		return nil, nil, 0, false
	}
	data, rest, ok = takeSSHBytes(rest, MaxSSHPreimage)
	if !ok || len(data) == 0 || len(data) > MaxSSHPreimage {
		return nil, nil, 0, false
	}
	if len(rest) != 4 {
		return nil, nil, 0, false
	}
	return key, data, binary.BigEndian.Uint32(rest), true
}

func parseSessionBind(rest []byte) (host, sid, sig []byte, ok bool) {
	host, rest, ok = takeSSHBytes(rest, sshEd25519BlobLen)
	if !ok || len(host) != sshEd25519BlobLen {
		return nil, nil, nil, false
	}
	sid, rest, ok = takeSSHBytes(rest, MaxSSHSessionID)
	if !ok || len(sid) < MinSSHSessionID {
		return nil, nil, nil, false
	}
	sig, rest, ok = takeSSHBytes(rest, sshEd25519SigLen)
	if !ok || len(sig) != sshEd25519SigLen || len(rest) != 1 || rest[0] != 0 {
		return nil, nil, nil, false
	}
	return host, sid, sig, true
}

const (
	extNameBad = iota
	extNameUnknown
	extNameOK
)

func takeExtName(body []byte) (string, []byte, int) {
	if len(body) < 1 || body[0] != sshAgentExtension || len(body) < 5 {
		return "", nil, extNameBad
	}
	n := binary.BigEndian.Uint32(body[1:5])
	if n == 0 || n > maxSSHExtName {
		return "", nil, extNameUnknown
	}
	if len(body) < 5+int(n) {
		return "", nil, extNameBad
	}
	return string(body[5 : 5+n]), body[5+n:], extNameOK
}

func takeSSHBytes(b []byte, max int) (v, rest []byte, ok bool) {
	if max < 0 || len(b) < 4 {
		return nil, b, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	if n > uint32(max) || len(b) < 4+int(n) {
		return nil, b, false
	}
	return b[4 : 4+int(n)], b[4+int(n):], true
}

func appendSSHString(dst, v []byte) []byte {
	dst = appendU32(dst, len(v))
	return append(dst, v...)
}

func readSSHFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxSSHFrame {
		return nil, ErrInvalid
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		wipe(buf)
		return nil, err
	}
	return buf, nil
}

func frameSSH(body []byte) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

func sshEmptyIdentities() []byte {
	return []byte{sshAgentIdentitiesAnswer, 0, 0, 0, 0}
}

func sshIdentities(blob []byte) []byte {
	body := []byte{sshAgentIdentitiesAnswer}
	body = appendU32(body, 1)
	body = appendSSHString(body, blob)
	body = appendSSHString(body, nil)
	return body
}

func sshSignResponse(sigBlob []byte) []byte {
	return appendSSHString([]byte{sshAgentSignResponse}, sigBlob)
}

func sshBytesEq(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func dup(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

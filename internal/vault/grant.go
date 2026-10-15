package vault

import (
	"crypto/sha256"
	"crypto/subtle"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	principalAgent      = "agent"
	agentStateActive    = "active"
	agentStateSuspended = "suspended"

	// OpHTTPRequest authorizes the broker to use the credential on one exact
	// resource. Authorizing it does not perform a request or reveal the credential.
	OpHTTPRequest = "http_request"
	// OpSign authorizes a future signing operation. Authorizing it does not sign
	// or reveal key material, and it does not authorize local attestation.
	OpSign = "sign"
	// OpHTTPBroker authorizes brokered HTTP requests inside one origin, one
	// allowed method set and one path prefix, with one credential injection
	// style. It is the only operation whose response carries upstream headers
	// and body bytes. An http_request grant does not authorize it, and it does
	// not authorize BrokerHTTP. See ADR 0025.
	OpHTTPBroker = "http_broker"

	// AgentTokenLen is the size of a per-agent bearer token from crypto/rand.
	AgentTokenLen = 32

	// GrantActive, GrantRevoked, and GrantExpired are capability lifecycle states.
	GrantActive  = "active"
	GrantRevoked = "revoked"
	GrantExpired = "expired"
)

// grantOperations is the closed set of capability operations. Secret retrieval
// is not in the set.
var grantOperations = []string{OpHTTPRequest, OpSign, OpHTTPBroker, OpLocalArtifactAttest, OpSSHUserAuth}

// GrantOperations returns a copy of the operation allowlist.
func GrantOperations() []string {
	return append([]string(nil), grantOperations...)
}

// Agent is a software principal. It is not a human user.
// Token is the one-time bearer token minted by CreateAgent. Only its SHA-256
// is stored. The human control plane writes it to a user-only file and wipes
// this copy; it is never recoverable from the vault.
type Agent struct {
	ID        string
	Label     string
	CreatedAt time.Time
	Token     []byte
}

// GrantSpec is a human request to issue one capability.
// Exactly one of CredentialID or CredentialClass must be set.
type GrantSpec struct {
	AgentID         string
	CredentialID    string
	CredentialClass string
	Operations      []string
	Resource        string
	ExpiresAt       time.Time
	// SSHUsername and SSHHostKey are required for ssh_userauth and forbidden
	// on every other operation. SSHHostKey is the canonical ssh-ed25519 blob.
	SSHUsername string
	SSHHostKey  []byte
	// HTTPMethods, HTTPInject and HTTPInjectName are required for http_broker
	// and forbidden on every other operation. Resource carries that grant's
	// origin and path prefix. HTTPInjectName is the header name, the basic
	// user, or the query parameter name, and is empty for bearer.
	HTTPMethods    []string
	HTTPInject     string
	HTTPInjectName string
}

// Grant is a persisted capability. It does not carry credential plaintext.
type Grant struct {
	ID              string
	AgentID         string
	CredentialID    string
	CredentialClass string
	Operations      []string
	Resource        string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
	// KeyID is the hex-encoded Ed25519 public key bound at issuance.
	// It is empty for grants that do not attest or authenticate SSH.
	KeyID string
	// SSHUsername is the exact account name bound to an ssh_userauth grant.
	// SSHHostKey is the canonical ssh-ed25519 server host public key blob.
	// Both are empty for every other operation. The resource string does not
	// constrain the account, the host, or anything that happens after authentication.
	SSHUsername string
	SSHHostKey  []byte
	// HTTPMethods, HTTPInject and HTTPInjectName are the http_broker scope.
	// Resource carries the origin and path prefix. They are empty for every
	// other operation. The credential value is not stored here.
	HTTPMethods    []string
	HTTPInject     string
	HTTPInjectName string
}

// Capability is the agent-visible description of one grant.
type Capability struct {
	GrantID         string
	AgentID         string
	CredentialID    string
	CredentialClass string
	Operations      []string
	Resource        string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
	Status          string
	// KeyID is the public key identity bound to an attestation or SSH grant.
	KeyID string
	// SSHUsername and SSHHostKey describe an ssh_userauth grant.
	// They are empty for every other operation.
	SSHUsername string
	SSHHostKey  []byte
	// HTTPMethods, HTTPInject and HTTPInjectName describe an http_broker
	// grant. HTTPInjectName names the injection slot, never its value.
	HTTPMethods    []string
	HTTPInject     string
	HTTPInjectName string
}

type agentRecord struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
	State     string    `json:"state"`
	// TokenHash is SHA-256 of this agent's bearer token. The token itself is
	// never stored. It is absent on an agent sealed before ADR 0024 and on
	// one whose token was revoked; neither can authenticate to the daemon.
	TokenHash []byte `json:"token_hash,omitempty"`
	// TokenGen counts the tokens this agent has been given. Issue and rotate
	// raise it, revoke keeps it, so a token minted after a revocation is
	// never the generation of the one it replaced. An agent sealed before
	// the generation existed reads as generation 1 when it holds a digest.
	TokenGen uint64 `json:"token_gen,omitempty"`
}

// tokenGen is the stored generation with the pre-generation shape normalized.
func (a agentRecord) tokenGen() uint64 {
	if a.TokenGen == 0 && len(a.TokenHash) == sha256.Size {
		return 1
	}
	return a.TokenGen
}

type grantRecord struct {
	ID              string     `json:"id"`
	AgentID         string     `json:"agent_id"`
	CredentialID    string     `json:"credential_id,omitempty"`
	CredentialClass string     `json:"credential_class,omitempty"`
	Operations      []string   `json:"operations"`
	Resource        string     `json:"resource"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	KeyID           string     `json:"key_id,omitempty"`
	SSHUsername     string     `json:"ssh_username,omitempty"`
	SSHHostKey      []byte     `json:"ssh_host_key,omitempty"`
	HTTPMethods     []string   `json:"http_methods,omitempty"`
	HTTPInject      string     `json:"http_inject,omitempty"`
	HTTPInjectName  string     `json:"http_inject_name,omitempty"`
}

// capabilityView is the slice of the vault an agent principal can call.
// It is not *Session, so a principal cannot be asserted back to credential retrieval.
type capabilityView interface {
	listCapabilities(agentID string) ([]Capability, error)
	authorizeCapability(agentID, credentialID, operation, resource string) (string, error)
	brokerHTTP(agentID string, req HTTPBrokerRequest) (HTTPBrokerResponse, error)
	brokerRequest(agentID string, req HTTPRequest) (HTTPResponse, error)
	localAttest(agentID string, req LocalAttestRequest) (LocalAttestation, error)
}

// agentBinder is one principal's view of a session. gen is the agent token
// generation that principal authenticated with, so the binding outlives the
// handshake: see bound.
type agentBinder struct {
	s   *Session
	gen uint64
}

// bound is the gate every agent-facing call passes. A daemon connection
// authenticates once (ADR 0024), so without this a daemon already serving
// would keep honouring a token the owner has rotated away or revoked: the
// reload makes the changed digest visible, and this is what acts on it.
func (b agentBinder) bound(agentID string) error {
	if b.s == nil {
		return ErrUnauthenticated
	}
	return b.s.requireAgentToken(agentID, b.gen)
}

func (b agentBinder) listCapabilities(agentID string) ([]Capability, error) {
	if err := b.bound(agentID); err != nil {
		return nil, err
	}
	return b.s.listCapabilities(agentID)
}

func (b agentBinder) authorizeCapability(agentID, credentialID, operation, resource string) (string, error) {
	if err := b.bound(agentID); err != nil {
		return "", err
	}
	return b.s.authorizeCapability(agentID, credentialID, operation, resource)
}

func (b agentBinder) brokerHTTP(agentID string, req HTTPBrokerRequest) (HTTPBrokerResponse, error) {
	if err := b.bound(agentID); err != nil {
		return HTTPBrokerResponse{}, err
	}
	return b.s.brokerHTTP(agentID, req)
}

func (b agentBinder) brokerRequest(agentID string, req HTTPRequest) (HTTPResponse, error) {
	if err := b.bound(agentID); err != nil {
		return HTTPResponse{}, err
	}
	return b.s.brokerRequest(agentID, req)
}

func (b agentBinder) localAttest(agentID string, req LocalAttestRequest) (LocalAttestation, error) {
	if err := b.bound(agentID); err != nil {
		return LocalAttestation{}, err
	}
	return b.s.localAttest(agentID, req)
}

// AgentPrincipal is the agent-facing handle for one identity.
// Its method set is capability listing, authorization, the HTTP broker, the
// GitHub issue read, local attestation, and one session-bound SSH userauth stream.
// It has no credential retrieval, grant issuance, clock, or way to select a different principal.
type AgentPrincipal struct {
	view capabilityView
	id   string
}

// Agent binds id to an agent-facing principal. The human control plane chooses
// the id. The returned principal cannot switch to another identity.
func (s *Session) Agent(id string) (*AgentPrincipal, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	defer s.end()
	return &AgentPrincipal{view: agentBinder{s: s}, id: id}, nil
}

// Capabilities lists grants for this principal only.
// Status uses the session clock.
func (a *AgentPrincipal) Capabilities() ([]Capability, error) {
	if a == nil || a.view == nil {
		return nil, ErrUnauthenticated
	}
	return a.view.listCapabilities(a.id)
}

// Authorize decides whether this principal may perform operation on resource
// with the named credential. A grant id is returned only when the decision is
// allow. Expiry uses the session clock. The credential plaintext is not returned.
func (a *AgentPrincipal) Authorize(credentialID, operation, resource string) (string, error) {
	if a == nil || a.view == nil {
		return "", ErrUnauthenticated
	}
	return a.view.authorizeCapability(a.id, credentialID, operation, resource)
}

// BrokerHTTP performs one authorized HTTP request with a stored credential.
// The credential is applied inside the broker. The request and response carry
// no credential plaintext, headers, or upstream URL dump. The response is a
// status code. It does not return a GitHub issue summary.
func (a *AgentPrincipal) BrokerHTTP(req HTTPBrokerRequest) (HTTPBrokerResponse, error) {
	if a == nil || a.view == nil {
		return HTTPBrokerResponse{}, ErrUnauthenticated
	}
	return a.view.brokerHTTP(a.id, req)
}

// BrokerRequest performs one prefix-scoped HTTP request on an http_broker
// grant. The credential is injected inside the broker and is not a request
// field. The response carries the status, the allowlisted response headers and
// the capped body with every occurrence of the credential redacted. An
// http_request grant does not authorize this call.
func (a *AgentPrincipal) BrokerRequest(req HTTPRequest) (HTTPResponse, error) {
	if a == nil || a.view == nil {
		return HTTPResponse{}, ErrUnauthenticated
	}
	return a.view.brokerRequest(a.id, req)
}

// LocalAttest signs one bounded payload with the vault-held Ed25519 key named
// by an exact local_artifact_attest grant. The private key is not returned.
// A sign, http_request, or http_broker grant does not authorize this call.
func (a *AgentPrincipal) LocalAttest(req LocalAttestRequest) (LocalAttestation, error) {
	if a == nil || a.view == nil {
		return LocalAttestation{}, ErrUnauthenticated
	}
	return a.view.localAttest(a.id, req)
}

// CreateAgent persists a new agent principal and mints its bearer token.
// The returned Agent.Token is the only copy; the vault seals only its SHA-256.
func (s *Session) CreateAgent(label string) (Agent, error) {
	if err := s.begin(); err != nil {
		return Agent{}, err
	}
	defer s.end()
	if err := validateLabel(label); err != nil {
		return Agent{}, s.denyAction(actionAgentCreate, err)
	}
	id, err := newID()
	if err != nil {
		return Agent{}, err
	}
	token, err := randBytes(AgentTokenLen)
	if err != nil {
		return Agent{}, err
	}
	sum := sha256.Sum256(token)
	rec := agentRecord{
		ID:        id,
		Label:     label,
		Kind:      principalAgent,
		CreatedAt: time.Now().UTC(),
		State:     agentStateActive,
		TokenHash: sum[:],
		TokenGen:  1,
	}
	next := append(append([]agentRecord{}, s.agents...), rec)
	partial := auditEvent{Action: actionAgentCreate, Result: resultAllowed, AgentID: id}
	if err := s.writeAudit(partial, s.creds, next, s.grants); err != nil {
		wipe(token)
		return Agent{}, err
	}
	out := rec.public()
	out.Token = token
	return out, nil
}

// AuthenticateAgentToken resolves one active agent principal from a bearer
// token and nothing else. The caller cannot name an agent, a human, the
// session, the vault, or the clock. The vault holds only SHA-256(token) and
// the comparison is constant time. Every attempt appends one daemon_auth row:
// the verified agent on success, the verified agent on a suspended principal,
// and no attribution at all for an unknown token. The token, its hash, and
// its length are never audit fields, log text, or error text.
//
// ponytail: a linear constant-time scan over the agent list, and repeated
// failures are ordinary expected denials rather than a detection class. The
// endpoint already restricts callers to the vault owner's uid. Upgrade path:
// a keyed index plus a daemon_auth failure class in the M5 lookback.
func (s *Session) AuthenticateAgentToken(token []byte) (*AgentPrincipal, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	defer s.end()
	if authenticateAgentTokenDelay > 0 {
		time.Sleep(authenticateAgentTokenDelay)
	}
	sum := sha256.Sum256(token)
	defer wipe(sum[:])
	matched, active, gen := "", false, uint64(0)
	if len(token) == AgentTokenLen {
		for i := range s.agents {
			if len(s.agents[i].TokenHash) != sha256.Size {
				continue
			}
			if subtle.ConstantTimeCompare(s.agents[i].TokenHash, sum[:]) == 1 {
				matched, active = s.agents[i].ID, s.agents[i].State == agentStateActive
				gen = s.agents[i].tokenGen()
				break
			}
		}
	}
	if matched == "" {
		return nil, s.finish(auditEvent{Action: actionDaemonAuth, Result: resultDenied}, ErrUnauthenticated)
	}
	if !active {
		return nil, s.finish(auditEvent{Action: actionDaemonAuth, Result: resultDeniedAgent, AgentID: matched}, ErrDeniedAgent)
	}
	if err := s.finish(auditEvent{Action: actionDaemonAuth, Result: resultAllowed, AgentID: matched}, nil); err != nil {
		return nil, err
	}
	// The principal is bound to this token, not just to its agent: see
	// requireAgentToken.
	return &AgentPrincipal{view: agentBinder{s: s, gen: gen}, id: matched}, nil
}

// requireAgentToken refuses a call whose principal was authenticated by a
// token the agent no longer holds. gen is the generation that authenticated
// it; generation 0 is a principal the human control plane bound by id, which
// has no token to be bound to. A digest that is gone — revoked, or the agent
// deleted — or a generation that has moved on after a reload is refused, and
// the refusal is audited as the daemon_auth denial it is. Nothing derived
// from the token reaches the row: not the material, not its digest, not the
// generation (ADR 0024).
//
// ponytail: one more indexed single-row read per agent call, and the check
// takes the session mutex separately from the operation that follows it, so a
// rotation committing in that gap is caught on the call after. Upgrade path:
// thread the binding through begin so one critical section covers both.
func (s *Session) requireAgentToken(agentID string, gen uint64) error {
	if gen == 0 {
		return nil
	}
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	idx := s.agentIndex(agentID)
	if idx < 0 {
		return s.finish(auditEvent{Action: actionDaemonAuth, Result: resultDenied}, ErrUnauthenticated)
	}
	if rec := s.agents[idx]; len(rec.TokenHash) != sha256.Size || rec.tokenGen() != gen {
		return s.finish(auditEvent{Action: actionDaemonAuth, Result: resultDeniedAgent, AgentID: rec.ID}, ErrUnauthenticated)
	}
	return nil
}

// IssueGrant persists a revocable, expiring capability for one agent.
// It does not grant raw-secret read authority.
func (s *Session) IssueGrant(spec GrantSpec) (Grant, error) {
	if err := s.begin(); err != nil {
		return Grant{}, err
	}
	defer s.end()
	now := time.Now().UTC()
	agentID := ""
	if safeID(spec.AgentID) != "" && s.agentExists(spec.AgentID) {
		agentID = spec.AgentID
	}
	deny := func(cause error) (Grant, error) {
		partial := auditEvent{Action: actionGrantCreate, Result: resultDenied, AgentID: agentID}
		if err := s.writeAudit(partial, s.creds, s.agents, s.grants); err != nil {
			return Grant{}, err
		}
		return Grant{}, cause
	}
	if agentID == "" {
		if safeID(spec.AgentID) == "" {
			return deny(ErrInvalid)
		}
		return deny(ErrAgentNotFound)
	}
	ops, opAudit, err := normalizeOps(spec.Operations)
	if err != nil {
		return deny(err)
	}
	if err := validateResource(spec.Resource); err != nil {
		return deny(err)
	}
	expires, err := requireTime(spec.ExpiresAt)
	if err != nil || !expires.After(now) {
		return deny(ErrInvalid)
	}
	credID, credType, err := s.bindGrantCredential(spec.CredentialID, spec.CredentialClass)
	if err != nil {
		return deny(err)
	}
	if err := attestGrantOK(ops, spec, credType); err != nil {
		return deny(err)
	}
	if err := sshGrantOK(ops, spec, credType); err != nil {
		return deny(err)
	}
	if err := brokerGrantOK(ops, spec); err != nil {
		return deny(err)
	}
	methods, _ := canonicalMethods(spec.HTTPMethods)
	keyID := ""
	if soleLocalAttest(ops) || soleSSH(ops) {
		secret, ok := s.copySecret(credID)
		if !ok {
			return deny(ErrInvalid)
		}
		keyID, err = attestKeyID(secret)
		wipe(secret)
		if err != nil {
			return deny(ErrInvalid)
		}
	}
	id, err := newID()
	if err != nil {
		return Grant{}, err
	}
	rec := grantRecord{
		ID:             id,
		AgentID:        agentID,
		Operations:     ops,
		Resource:       spec.Resource,
		CreatedAt:      now,
		ExpiresAt:      expires,
		KeyID:          keyID,
		SSHUsername:    spec.SSHUsername,
		SSHHostKey:     dup(spec.SSHHostKey),
		HTTPMethods:    methods,
		HTTPInject:     spec.HTTPInject,
		HTTPInjectName: spec.HTTPInjectName,
	}
	if spec.CredentialID != "" {
		rec.CredentialID = credID
	} else {
		rec.CredentialClass = credType
	}
	next := append(append([]grantRecord{}, s.grants...), rec)
	partial := auditEvent{
		Action:    actionGrantCreate,
		Result:    resultAllowed,
		AgentID:   agentID,
		GrantID:   id,
		CredID:    rec.CredentialID,
		CredType:  credType,
		Operation: opAudit,
	}
	if err := s.writeAudit(partial, s.creds, s.agents, next); err != nil {
		return Grant{}, err
	}
	return rec.public(), nil
}

// RevokeGrant marks a grant revoked. A second revocation fails closed.
func (s *Session) RevokeGrant(id string) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	if safeID(id) == "" {
		return s.finish(auditEvent{Action: actionGrantRevoke, Result: resultDenied}, ErrInvalid)
	}
	idx := -1
	for i := range s.grants {
		if s.grants[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return s.finish(auditEvent{Action: actionGrantRevoke, Result: resultDenied}, ErrGrantNotFound)
	}
	cur := s.grants[idx]
	ops := strings.Join(cur.Operations, ",")
	credType := s.auditCredType(cur)
	if cur.RevokedAt != nil {
		return s.finish(auditEvent{
			Action:    actionGrantRevoke,
			Result:    resultDenied,
			AgentID:   cur.AgentID,
			GrantID:   cur.ID,
			CredID:    cur.CredentialID,
			CredType:  credType,
			Operation: ops,
		}, ErrInvalid)
	}
	next := append([]grantRecord{}, s.grants...)
	revoked := time.Now().UTC()
	next[idx].RevokedAt = &revoked
	return s.writeAudit(auditEvent{
		Action:    actionGrantRevoke,
		Result:    resultAllowed,
		AgentID:   cur.AgentID,
		GrantID:   cur.ID,
		CredID:    cur.CredentialID,
		CredType:  credType,
		Operation: ops,
	}, s.creds, s.agents, next)
}

// IssueAgentToken mints the first bearer token for an agent that has none,
// which is how an agent created before ADR 0024, or one whose token was
// revoked, reaches the daemon without being recreated. It refuses an agent
// that still holds a token: replacing a live token is RotateAgentToken, so
// neither call can retire a working client by accident. The returned
// Agent.Token is the only copy.
func (s *Session) IssueAgentToken(id string) (Agent, error) {
	return s.mintAgentToken(actionAgentTokenIssue, id)
}

// RotateAgentToken replaces the token of an agent that holds one. The old
// token stops authenticating at once, including in a running daemon, which
// re-reads the vault (ADR 0024, amendment of 2026-10-13). The agent keeps its
// id, its state and every grant, so no client configuration changes.
func (s *Session) RotateAgentToken(id string) (Agent, error) {
	return s.mintAgentToken(actionAgentTokenRotate, id)
}

// mintAgentToken is issue and rotate, which differ only in whether a token
// must already be there. One body, so the digest, the generation and the
// audit row cannot drift apart between them.
func (s *Session) mintAgentToken(action, id string) (Agent, error) {
	if err := s.begin(); err != nil {
		return Agent{}, err
	}
	defer s.end()
	idx := s.agentIndex(id)
	if idx < 0 {
		return Agent{}, s.finish(auditEvent{Action: action, Result: resultDenied}, ErrAgentNotFound)
	}
	cur := s.agents[idx]
	held := len(cur.TokenHash) == sha256.Size
	if held && action == actionAgentTokenIssue {
		return Agent{}, s.finish(auditEvent{Action: action, Result: resultDeniedAgent, AgentID: cur.ID}, ErrAgentTokenPresent)
	}
	if !held && action == actionAgentTokenRotate {
		return Agent{}, s.finish(auditEvent{Action: action, Result: resultDeniedAgent, AgentID: cur.ID}, ErrAgentTokenAbsent)
	}
	token, err := randBytes(AgentTokenLen)
	if err != nil {
		return Agent{}, err
	}
	sum := sha256.Sum256(token)
	next := append([]agentRecord{}, s.agents...)
	next[idx].TokenHash = sum[:]
	next[idx].TokenGen = cur.tokenGen() + 1
	if err := s.writeAudit(auditEvent{Action: action, Result: resultAllowed, AgentID: cur.ID}, s.creds, next, s.grants); err != nil {
		wipe(token)
		return Agent{}, err
	}
	out := next[idx].public()
	out.Token = token
	return out, nil
}

// RevokeAgentToken clears an agent's token digest. The agent keeps its id,
// its state and its grants, and a later IssueAgentToken restores access to
// exactly those grants under a new generation. A daemon serving the old token
// refuses it on the next call.
func (s *Session) RevokeAgentToken(id string) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	idx := s.agentIndex(id)
	if idx < 0 {
		return s.finish(auditEvent{Action: actionAgentTokenRevoke, Result: resultDenied}, ErrAgentNotFound)
	}
	cur := s.agents[idx]
	if len(cur.TokenHash) != sha256.Size {
		return s.finish(auditEvent{Action: actionAgentTokenRevoke, Result: resultDeniedAgent, AgentID: cur.ID}, ErrAgentTokenAbsent)
	}
	next := append([]agentRecord{}, s.agents...)
	next[idx].TokenHash = nil
	next[idx].TokenGen = cur.tokenGen()
	return s.writeAudit(auditEvent{Action: actionAgentTokenRevoke, Result: resultAllowed, AgentID: cur.ID}, s.creds, next, s.grants)
}

func (s *Session) agentIndex(id string) int {
	if safeID(id) == "" {
		return -1
	}
	for i := range s.agents {
		if s.agents[i].ID == id {
			return i
		}
	}
	return -1
}

// RejectAgentTokenIssue records a metadata-free agent_token_issue denial.
func (s *Session) RejectAgentTokenIssue(cause error) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.denyAction(actionAgentTokenIssue, cause)
}

// RejectAgentTokenRotate records a metadata-free agent_token_rotate denial.
func (s *Session) RejectAgentTokenRotate(cause error) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.denyAction(actionAgentTokenRotate, cause)
}

// RejectAgentTokenRevoke records a metadata-free agent_token_revoke denial.
func (s *Session) RejectAgentTokenRevoke(cause error) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.denyAction(actionAgentTokenRevoke, cause)
}

// RejectAgentCreate records a metadata-free agent_create denial.
func (s *Session) RejectAgentCreate(cause error) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.denyAction(actionAgentCreate, cause)
}

// RejectGrantCreate records a metadata-free grant_create denial.
func (s *Session) RejectGrantCreate(cause error) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.denyAction(actionGrantCreate, cause)
}

// RejectGrantRevoke records a metadata-free grant_revoke denial.
func (s *Session) RejectGrantRevoke(cause error) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.denyAction(actionGrantRevoke, cause)
}

// RejectCapabilityList records a metadata-free capability_list denial.
func (s *Session) RejectCapabilityList(cause error) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.denyAction(actionCapList, cause)
}

// RejectAuthorize records a metadata-free capability_authorize denial.
func (s *Session) RejectAuthorize(cause error) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	return s.denyAction(actionAuthorize, cause)
}

func (s *Session) listCapabilities(agentID string) ([]Capability, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	defer s.end()
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
	caps := capabilitiesFor(s.grants, agentID, now)
	if err := s.finish(auditEvent{Action: actionCapList, Result: resultAllowed, AgentID: agentID}, nil); err != nil {
		return nil, err
	}
	return caps, nil
}

func (s *Session) authorizeCapability(agentID, credentialID, operation, resource string) (string, error) {
	if err := s.begin(); err != nil {
		return "", err
	}
	defer s.end()
	partial, cause := s.judge(agentID, credentialID, operation, resource)
	if cause == nil && operation == OpLocalArtifactAttest {
		partial, cause = s.screenAttestKey(partial)
	}
	if cause == nil && operation == OpSSHUserAuth {
		partial, cause = s.screenSSHKey(partial)
	}
	partial.Action = actionAuthorize
	if err := s.finish(partial, cause); err != nil {
		return "", err
	}
	if cause != nil {
		return "", cause
	}
	return partial.GrantID, nil
}

// judge is the M2 allow decision. It does not write an audit event and it does
// not read credential plaintext. A malformed caller string is not copied out.
func (s *Session) judge(agentID, credentialID, operation, resource string) (auditEvent, error) {
	now, err := s.evaluationTime()
	// Suspension is an ordinary denial, including a secret probe. The probe
	// token is not an audit field. Checking it first would raise another alert
	// for an agent that containment already suspended.
	if safeID(agentID) != "" && s.agentExists(agentID) && !s.agentActive(agentID) {
		partial := auditEvent{Result: resultDeniedAgent, AgentID: agentID}
		if !secretProbe(operation) && allowedOperation(operation) {
			partial.Operation = operation
		}
		if id, typ, ok := s.lookupCred(credentialID); ok {
			partial.CredID = id
			partial.CredType = typ
		}
		return partial, ErrDeniedAgent
	}
	// get_secret is the closed probe token. The caller string is not an audit field.
	if secretProbe(operation) {
		partial := auditEvent{Result: resultDeniedSecret}
		if safeID(agentID) != "" && s.agentExists(agentID) {
			partial.AgentID = agentID
		}
		if id, typ, ok := s.lookupCred(credentialID); ok {
			partial.CredID = id
			partial.CredType = typ
		}
		return partial, ErrInvalid
	}
	if err != nil || safeID(agentID) == "" || safeID(credentialID) == "" || !allowedOperation(operation) || validateResource(resource) != nil {
		return auditEvent{Result: resultDenied}, ErrInvalid
	}
	agentOK := s.agentExists(agentID)
	credID, credType, credOK := s.lookupCred(credentialID)
	result, grantID := decideAccess(s.grants, agentOK, agentID, credID, credType, credOK, operation, resource, now)
	partial := auditEvent{Result: result, Operation: operation, GrantID: grantID}
	if agentOK {
		partial.AgentID = agentID
	}
	if agentOK && credOK && result != resultDeniedAgent {
		partial.CredID = credID
		partial.CredType = credType
	}
	if result != resultAllowed {
		return partial, denialError(result)
	}
	return partial, nil
}

func (s *Session) writeAudit(partial auditEvent, creds []credential, agents []agentRecord, grants []grantRecord) error {
	ev, err := nextAudit(s.audit, s.id, partial)
	if err != nil {
		return err
	}
	if err := s.commitState(ev, creds, agents, grants); err != nil {
		return err
	}
	s.logf("%s agent=%s grant=%s result=%s", ev.Action, ev.AgentID, ev.GrantID, ev.Result)
	return nil
}

func (s *Session) finish(partial auditEvent, cause error) error {
	if err := s.writeAudit(partial, s.creds, s.agents, s.grants); err != nil {
		return err
	}
	return cause
}

func (s *Session) agentExists(id string) bool {
	return s.agentIndex(id) >= 0
}

func (s *Session) agentActive(id string) bool {
	for i := range s.agents {
		if s.agents[i].ID == id && s.agents[i].State == agentStateActive {
			return true
		}
	}
	return false
}

func secretProbe(operation string) bool {
	return operation == "get_secret"
}

func (s *Session) lookupCred(id string) (credID, credType string, ok bool) {
	for i := range s.creds {
		if s.creds[i].ID == id {
			return s.creds[i].ID, s.creds[i].Type, true
		}
	}
	return "", "", false
}

func (s *Session) bindGrantCredential(credID, class string) (string, string, error) {
	idSet := credID != ""
	classSet := class != ""
	if idSet == classSet {
		return "", "", ErrInvalid
	}
	if classSet {
		if err := validateType(class); err != nil {
			return "", "", err
		}
		return "", class, nil
	}
	if safeID(credID) == "" {
		return "", "", ErrInvalid
	}
	id, typ, ok := s.lookupCred(credID)
	if !ok {
		return "", "", ErrNotFound
	}
	return id, typ, nil
}

func (s *Session) auditCredType(g grantRecord) string {
	if g.CredentialClass != "" {
		return g.CredentialClass
	}
	_, typ, ok := s.lookupCred(g.CredentialID)
	if !ok {
		return ""
	}
	return typ
}

// decideAccess is deny-by-default. One active matching grant allows.
// Revocation wins over expiry when a full-scope grant carries both.
// Mismatch class follows the closest grant: scope, then operation, then credential.
func decideAccess(grants []grantRecord, agentOK bool, agentID, credID, credType string, credOK bool, op, resource string, now time.Time) (result, grantID string) {
	if !agentOK {
		return resultDeniedAgent, ""
	}
	if !credOK {
		return resultDeniedCredential, ""
	}
	var mine []grantRecord
	for _, g := range grants {
		if g.AgentID == agentID {
			mine = append(mine, g)
		}
	}
	if len(mine) == 0 {
		if len(grants) == 0 {
			return resultDeniedMissing, ""
		}
		return resultDeniedAgent, ""
	}
	var active, revoked, expired, scopeMismatch, opMismatch, credMismatch string
	for _, g := range mine {
		if !grantMatchesCred(g, credID, credType) {
			credMismatch = preferID(credMismatch, g.ID)
			continue
		}
		if !grantAllowsOp(g, op) {
			opMismatch = preferID(opMismatch, g.ID)
			continue
		}
		// A class grant or a grant with no key id is not signing authority.
		// Checked after the operation so a sign or http grant stays denied_operation.
		if !attestCredScope(g, op) || !sshCredScope(g, op) {
			credMismatch = preferID(credMismatch, g.ID)
			continue
		}
		if g.Resource != resource {
			scopeMismatch = preferID(scopeMismatch, g.ID)
			continue
		}
		if g.RevokedAt != nil {
			revoked = preferID(revoked, g.ID)
			continue
		}
		if !now.Before(g.ExpiresAt) {
			expired = preferID(expired, g.ID)
			continue
		}
		active = preferID(active, g.ID)
	}
	if active != "" {
		return resultAllowed, active
	}
	if revoked != "" {
		return resultDeniedRevoked, revoked
	}
	if expired != "" {
		return resultDeniedExpired, expired
	}
	if scopeMismatch != "" {
		return resultDeniedScope, scopeMismatch
	}
	if opMismatch != "" {
		return resultDeniedOperation, opMismatch
	}
	if credMismatch != "" {
		return resultDeniedCredential, credMismatch
	}
	return resultDeniedMissing, ""
}

func grantMatchesCred(g grantRecord, credID, credType string) bool {
	idSet := g.CredentialID != ""
	classSet := g.CredentialClass != ""
	if idSet == classSet {
		return false
	}
	if idSet {
		return g.CredentialID == credID
	}
	return g.CredentialClass == credType
}

func grantAllowsOp(g grantRecord, op string) bool {
	for _, allowed := range g.Operations {
		if allowed == op {
			return true
		}
	}
	return false
}

func preferID(current, id string) string {
	if current == "" || id < current {
		return id
	}
	return current
}

func capabilitiesFor(grants []grantRecord, agentID string, now time.Time) []Capability {
	var out []Capability
	for _, g := range grants {
		if g.AgentID != agentID {
			continue
		}
		out = append(out, g.capability(now))
	}
	slices.SortFunc(out, func(a, b Capability) int {
		return strings.Compare(a.GrantID, b.GrantID)
	})
	return out
}

func (g grantRecord) capability(now time.Time) Capability {
	return Capability{
		GrantID:         g.ID,
		AgentID:         g.AgentID,
		CredentialID:    g.CredentialID,
		CredentialClass: g.CredentialClass,
		Operations:      append([]string(nil), g.Operations...),
		Resource:        g.Resource,
		CreatedAt:       g.CreatedAt.UTC(),
		ExpiresAt:       g.ExpiresAt.UTC(),
		RevokedAt:       cloneTime(g.RevokedAt),
		Status:          grantStatus(g, now),
		KeyID:           g.KeyID,
		SSHUsername:     g.SSHUsername,
		SSHHostKey:      dup(g.SSHHostKey),
		HTTPMethods:     append([]string(nil), g.HTTPMethods...),
		HTTPInject:      g.HTTPInject,
		HTTPInjectName:  g.HTTPInjectName,
	}
}

func grantStatus(g grantRecord, now time.Time) string {
	if g.RevokedAt != nil {
		return GrantRevoked
	}
	if !now.Before(g.ExpiresAt) {
		return GrantExpired
	}
	return GrantActive
}

func (a agentRecord) public() Agent {
	return Agent{ID: a.ID, Label: a.Label, CreatedAt: a.CreatedAt.UTC()}
}

func (g grantRecord) public() Grant {
	return Grant{
		ID:              g.ID,
		AgentID:         g.AgentID,
		CredentialID:    g.CredentialID,
		CredentialClass: g.CredentialClass,
		Operations:      append([]string(nil), g.Operations...),
		Resource:        g.Resource,
		CreatedAt:       g.CreatedAt.UTC(),
		ExpiresAt:       g.ExpiresAt.UTC(),
		RevokedAt:       cloneTime(g.RevokedAt),
		KeyID:           g.KeyID,
		SSHUsername:     g.SSHUsername,
		SSHHostKey:      dup(g.SSHHostKey),
		HTTPMethods:     append([]string(nil), g.HTTPMethods...),
		HTTPInject:      g.HTTPInject,
		HTTPInjectName:  g.HTTPInjectName,
	}
}

func denialError(result string) error {
	switch result {
	case resultDeniedAgent:
		return ErrDeniedAgent
	case resultDeniedCredential:
		return ErrDeniedCredential
	case resultDeniedOperation:
		return ErrDeniedOperation
	case resultDeniedScope:
		return ErrDeniedScope
	case resultDeniedExpired:
		return ErrDeniedExpired
	case resultDeniedRevoked:
		return ErrDeniedRevoked
	case resultDeniedMissing:
		return ErrDeniedMissing
	case resultDeniedKey:
		return ErrDeniedKey
	default:
		return ErrInvalid
	}
}

func normalizeOps(ops []string) ([]string, string, error) {
	if len(ops) == 0 || len(ops) > len(grantOperations) {
		return nil, "", ErrInvalid
	}
	cp := append([]string(nil), ops...)
	slices.Sort(cp)
	prev := ""
	for _, op := range cp {
		if !allowedOperation(op) || op == prev {
			return nil, "", ErrInvalid
		}
		prev = op
	}
	return cp, strings.Join(cp, ","), nil
}

func allowedOperation(op string) bool {
	for _, allowed := range grantOperations {
		if op == allowed {
			return true
		}
	}
	return false
}

func validAuditOperation(op string) bool {
	if op == "" {
		return true
	}
	parts := strings.Split(op, ",")
	prev := ""
	for _, part := range parts {
		if !allowedOperation(part) || part <= prev {
			return false
		}
		prev = part
	}
	return true
}

func validateResource(resource string) error {
	if resource == "" || len(resource) > maxLabel || strings.ContainsAny(resource, "\x00\r\n*") || !utf8.ValidString(resource) {
		return ErrInvalid
	}
	return nil
}

// evaluationTime is the trusted instant for expiry and capability status.
// A nil clock is the process clock. Callers cannot supply this value.
func (s *Session) evaluationTime() (time.Time, error) {
	now := time.Now()
	if s.clock != nil {
		now = s.clock()
	}
	return requireTime(now)
}

func requireTime(t time.Time) (time.Time, error) {
	if t.IsZero() {
		return time.Time{}, ErrInvalid
	}
	u := t.UTC()
	if _, err := u.MarshalJSON(); err != nil {
		return time.Time{}, ErrInvalid
	}
	return u, nil
}

func validateAgentsAndGrants(doc document) error {
	agents := make(map[string]struct{}, len(doc.Agents))
	for _, a := range doc.Agents {
		if safeID(a.ID) == "" || validateLabel(a.Label) != nil || a.Kind != principalAgent || (a.State != agentStateActive && a.State != agentStateSuspended) {
			return ErrCorrupt
		}
		if _, err := requireTime(a.CreatedAt); err != nil {
			return ErrCorrupt
		}
		// Absent is a pre-ADR-0024 agent or a revoked token, neither of which
		// can authenticate. Any other length is not a SHA-256 digest and is
		// not silently accepted. A digest with no generation is the shape
		// sealed before generations existed; a generation with no digest is
		// a revoked token and keeps its count.
		if a.TokenHash != nil && len(a.TokenHash) != sha256.Size {
			return ErrCorrupt
		}
		if _, ok := agents[a.ID]; ok {
			return ErrCorrupt
		}
		agents[a.ID] = struct{}{}
	}
	creds := make(map[string]struct{}, len(doc.Credentials))
	credTypes := make(map[string]string, len(doc.Credentials))
	for _, c := range doc.Credentials {
		creds[c.ID] = struct{}{}
		credTypes[c.ID] = c.Type
	}
	seen := make(map[string]struct{}, len(doc.Grants))
	for _, g := range doc.Grants {
		if safeID(g.ID) == "" || safeID(g.AgentID) == "" {
			return ErrCorrupt
		}
		if _, ok := agents[g.AgentID]; !ok {
			return ErrCorrupt
		}
		if _, ok := seen[g.ID]; ok {
			return ErrCorrupt
		}
		seen[g.ID] = struct{}{}
		idSet := g.CredentialID != ""
		classSet := g.CredentialClass != ""
		if idSet == classSet {
			return ErrCorrupt
		}
		if idSet {
			if safeID(g.CredentialID) == "" {
				return ErrCorrupt
			}
			if _, ok := creds[g.CredentialID]; !ok {
				return ErrCorrupt
			}
		}
		if classSet && validateType(g.CredentialClass) != nil {
			return ErrCorrupt
		}
		if _, _, err := normalizeOps(g.Operations); err != nil {
			return ErrCorrupt
		}
		if !opsSorted(g.Operations) {
			return ErrCorrupt
		}
		if validateResource(g.Resource) != nil {
			return ErrCorrupt
		}
		created, err := requireTime(g.CreatedAt)
		if err != nil {
			return ErrCorrupt
		}
		expires, err := requireTime(g.ExpiresAt)
		if err != nil || !expires.After(created) {
			return ErrCorrupt
		}
		if g.RevokedAt != nil {
			revoked, err := requireTime(*g.RevokedAt)
			if err != nil || revoked.Before(created) {
				return ErrCorrupt
			}
		}
		if err := validateGrantKey(g, credTypes); err != nil {
			return err
		}
		if err := validateBrokerGrant(g); err != nil {
			return err
		}
	}
	return nil
}

func opsSorted(ops []string) bool {
	prev := ""
	for _, op := range ops {
		if op <= prev {
			return false
		}
		prev = op
	}
	return true
}

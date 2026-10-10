package vault

import (
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
	// or reveal key material.
	OpSign = "sign"
	// OpGitHubIssueState authorizes one typed GitHub issue-state read.
	// It does not authorize BrokerHTTP, and an http_request grant does not
	// authorize this response projection.
	OpGitHubIssueState = "github_issue_state"

	// GrantActive, GrantRevoked, and GrantExpired are capability lifecycle states.
	GrantActive  = "active"
	GrantRevoked = "revoked"
	GrantExpired = "expired"
)

// grantOperations is the closed set of capability operations. Secret retrieval
// is not in the set.
var grantOperations = []string{OpHTTPRequest, OpSign, OpGitHubIssueState}

// GrantOperations returns a copy of the operation allowlist.
func GrantOperations() []string {
	return append([]string(nil), grantOperations...)
}

// Agent is a software principal. It is not a human user.
type Agent struct {
	ID        string
	Label     string
	CreatedAt time.Time
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
}

type agentRecord struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
	State     string    `json:"state"`
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
}

// capabilityView is the slice of the vault an agent principal can call.
// It is not *Session, so a principal cannot be asserted back to credential retrieval.
type capabilityView interface {
	listCapabilities(agentID string) ([]Capability, error)
	authorizeCapability(agentID, credentialID, operation, resource string) (string, error)
	brokerHTTP(agentID string, req HTTPBrokerRequest) (HTTPBrokerResponse, error)
	githubIssueState(agentID string, req GitHubIssueRequest) (GitHubIssueState, error)
}

type agentBinder struct {
	s *Session
}

func (b agentBinder) listCapabilities(agentID string) ([]Capability, error) {
	if b.s == nil {
		return nil, ErrUnauthenticated
	}
	return b.s.listCapabilities(agentID)
}

func (b agentBinder) authorizeCapability(agentID, credentialID, operation, resource string) (string, error) {
	if b.s == nil {
		return "", ErrUnauthenticated
	}
	return b.s.authorizeCapability(agentID, credentialID, operation, resource)
}

func (b agentBinder) brokerHTTP(agentID string, req HTTPBrokerRequest) (HTTPBrokerResponse, error) {
	if b.s == nil {
		return HTTPBrokerResponse{}, ErrUnauthenticated
	}
	return b.s.brokerHTTP(agentID, req)
}

func (b agentBinder) githubIssueState(agentID string, req GitHubIssueRequest) (GitHubIssueState, error) {
	if b.s == nil {
		return GitHubIssueState{}, ErrUnauthenticated
	}
	return b.s.githubIssueState(agentID, req)
}

// AgentPrincipal is the agent-facing handle for one identity.
// Its method set is capability listing, authorization, and the HTTP broker.
// It has no credential retrieval, grant issuance, or way to select a different principal.
type AgentPrincipal struct {
	view capabilityView
	id   string
}

// Agent binds id to an agent-facing principal. The human control plane chooses
// the id. The returned principal cannot switch to another identity.
func (s *Session) Agent(id string) (*AgentPrincipal, error) {
	if err := s.live(); err != nil {
		return nil, err
	}
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

// GitHubIssueState reads one authorized GitHub issue and returns its state
// summary. The credential stays inside the broker. An http_request grant does
// not authorize this call.
func (a *AgentPrincipal) GitHubIssueState(req GitHubIssueRequest) (GitHubIssueState, error) {
	if a == nil || a.view == nil {
		return GitHubIssueState{}, ErrUnauthenticated
	}
	return a.view.githubIssueState(a.id, req)
}

// CreateAgent persists a new agent principal.
func (s *Session) CreateAgent(label string) (Agent, error) {
	if err := s.live(); err != nil {
		return Agent{}, err
	}
	if err := validateLabel(label); err != nil {
		return Agent{}, s.denyAction(actionAgentCreate, err)
	}
	id, err := newID()
	if err != nil {
		return Agent{}, err
	}
	rec := agentRecord{
		ID:        id,
		Label:     label,
		Kind:      principalAgent,
		CreatedAt: time.Now().UTC(),
		State:     agentStateActive,
	}
	next := append(append([]agentRecord{}, s.agents...), rec)
	partial := auditEvent{Action: actionAgentCreate, Result: resultAllowed, AgentID: id}
	if err := s.writeAudit(partial, s.creds, next, s.grants); err != nil {
		return Agent{}, err
	}
	return rec.public(), nil
}

// IssueGrant persists a revocable, expiring capability for one agent.
// It does not grant raw-secret read authority.
func (s *Session) IssueGrant(spec GrantSpec) (Grant, error) {
	if err := s.live(); err != nil {
		return Grant{}, err
	}
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
	id, err := newID()
	if err != nil {
		return Grant{}, err
	}
	rec := grantRecord{
		ID:         id,
		AgentID:    agentID,
		Operations: ops,
		Resource:   spec.Resource,
		CreatedAt:  now,
		ExpiresAt:  expires,
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
	if err := s.live(); err != nil {
		return err
	}
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

// RejectAgentCreate records a metadata-free agent_create denial.
func (s *Session) RejectAgentCreate(cause error) error {
	return s.denyAction(actionAgentCreate, cause)
}

// RejectGrantCreate records a metadata-free grant_create denial.
func (s *Session) RejectGrantCreate(cause error) error {
	return s.denyAction(actionGrantCreate, cause)
}

// RejectGrantRevoke records a metadata-free grant_revoke denial.
func (s *Session) RejectGrantRevoke(cause error) error {
	return s.denyAction(actionGrantRevoke, cause)
}

// RejectCapabilityList records a metadata-free capability_list denial.
func (s *Session) RejectCapabilityList(cause error) error {
	return s.denyAction(actionCapList, cause)
}

// RejectAuthorize records a metadata-free capability_authorize denial.
func (s *Session) RejectAuthorize(cause error) error {
	return s.denyAction(actionAuthorize, cause)
}

func (s *Session) listCapabilities(agentID string) ([]Capability, error) {
	if err := s.live(); err != nil {
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
	caps := capabilitiesFor(s.grants, agentID, now)
	if err := s.finish(auditEvent{Action: actionCapList, Result: resultAllowed, AgentID: agentID}, nil); err != nil {
		return nil, err
	}
	return caps, nil
}

func (s *Session) authorizeCapability(agentID, credentialID, operation, resource string) (string, error) {
	if err := s.live(); err != nil {
		return "", err
	}
	partial, cause := s.judge(agentID, credentialID, operation, resource)
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
	for i := range s.agents {
		if s.agents[i].ID == id {
			return true
		}
	}
	return false
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

func validateDocument(doc document) error {
	if err := validateStored(doc.Credentials); err != nil {
		return err
	}
	if err := validateAgentsAndGrants(doc); err != nil {
		return err
	}
	if err := validateHealthPolicyStored(doc.HealthPolicy); err != nil {
		return err
	}
	return validateDetection(doc.Detection)
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
		if _, ok := agents[a.ID]; ok {
			return ErrCorrupt
		}
		agents[a.ID] = struct{}{}
	}
	creds := make(map[string]struct{}, len(doc.Credentials))
	for _, c := range doc.Credentials {
		creds[c.ID] = struct{}{}
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

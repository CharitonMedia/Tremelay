package vault

import (
	"time"
)

const (
	// RoleOwner manages membership, inventory, agents, audit, approval, and revocation.
	RoleOwner = "owner"
	// RoleMember can see the minimum metadata needed to request access and can
	// inspect only their own requests.
	RoleMember = "member"

	memberActive  = "active"
	memberRemoved = "removed"

	requestPending     = "pending"
	requestConsumed    = "consumed"
	requestRejected    = "rejected"
	requestCancelled   = "cancelled"
	requestExpired     = "expired"
	requestInvalidated = "invalidated"

	decisionBootstrap = "bootstrap"
	decisionAttach    = "attach"
	decisionRemove    = "remove"
	decisionRole      = "role"
	decisionRequest   = "request"
	decisionCancel    = "cancel"
	decisionReject    = "reject"
	decisionApprove   = "approve"
	decisionExpire    = "expire"
	decisionGrant     = "grant"
	decisionRevoke    = "revoke"
	decisionAudit     = "audit"
	decisionInventory = "inventory"

	// actorSystem is the fixed audit actor for passphrase-holder bootstrap.
	// It is not a human identity and cannot be enrolled.
	actorSystem = "00000000000000000000000000000000"

	// maxApprovalWindow bounds how far ahead an approval deadline may sit.
	maxApprovalWindow = 24 * time.Hour
)

// orgRecord binds one vault to one organization. The binding does not change.
type orgRecord struct {
	ID      string `json:"id"`
	VaultID string `json:"vault_id"`
}

type membershipRecord struct {
	HumanID    string `json:"human_id"`
	Role       string `json:"role"`
	Generation uint64 `json:"generation"`
	State      string `json:"state"`
}

type grantProvenance struct {
	RequestID    string `json:"request_id"`
	OrgID        string `json:"org_id"`
	RequesterID  string `json:"requester_id"`
	RequesterGen uint64 `json:"requester_gen"`
	ApproverID   string `json:"approver_id"`
	ApproverGen  uint64 `json:"approver_gen"`
}

type requestRecord struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	VaultID      string    `json:"vault_id"`
	RequesterID  string    `json:"requester_id"`
	RequesterGen uint64    `json:"requester_gen"`
	AgentID      string    `json:"agent_id"`
	CredentialID string    `json:"credential_id"`
	KeyID        string    `json:"key_id"`
	Operation    string    `json:"operation"`
	Resource     string    `json:"resource"`
	ExpiresAt    time.Time `json:"expires_at"`
	Deadline     time.Time `json:"deadline"`
	Status       string    `json:"status"`
	GrantID      string    `json:"grant_id,omitempty"`
	ApproverID   string    `json:"approver_id,omitempty"`
	ApproverGen  uint64    `json:"approver_gen,omitempty"`
}

// sharedSnap is the shared-mode document section written by one commit.
// A nil snap keeps the session's current section, so an ordinary credential
// or health commit cannot erase membership or approval provenance.
type sharedSnap struct {
	org      *orgRecord
	members  []membershipRecord
	requests []requestRecord
}

// AccessRequest is the caller-visible request. Resource text stays out of
// the audit chain. Approval takes the ID, not a replacement of these fields.
type AccessRequest struct {
	ID           string
	AgentID      string
	CredentialID string
	Resource     string
	ExpiresAt    time.Time
	Deadline     time.Time
	Status       string
	GrantID      string
}

// AccessRequestSpec is a member's request for one local attestation grant.
// The operation is fixed. Callers cannot supply the evaluation clock.
type AccessRequestSpec struct {
	AgentID      string
	CredentialID string
	Resource     string
	ExpiresAt    time.Time
	Deadline     time.Time
}

// HumanPrincipal is one trusted-host identity bound to this vault.
// The host asserts the identity. The vault does not authenticate it.
// The handle cannot switch actor, recover the Session, set the clock,
// unwrap the DEK, or mint assertions.
type HumanPrincipal struct {
	s  *Session
	id string
}

func (s *Session) shared() bool {
	return s != nil && s.org != nil
}

func (s *Session) requireCurrent() error {
	if s == nil || s.defunct {
		return ErrStale
	}
	var seq int64
	if err := s.db.QueryRow(`SELECT audit_seq FROM vault WHERE id=?`, s.id).Scan(&seq); err != nil || seq < 0 {
		return ErrAudit
	}
	if uint64(seq) != s.header.AuditSeq {
		s.defunct = true
		return ErrStale
	}
	return nil
}

// BootstrapShared binds this legacy vault to a new organization and one
// initial owner. Authority is the unlocked passphrase session. Bound human
// and agent handles cannot call it. A vault that already has grants is
// rejected: those grants have no approval provenance.
func (s *Session) BootstrapShared(ownerID string) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	if s.shared() {
		return s.auditShared(auditEvent{Action: actionBootstrap, Result: resultDenied, Decision: decisionBootstrap, ActorID: actorSystem}, nil, nil, nil)
	}
	if safeID(ownerID) == "" || ownerID == actorSystem || s.agentExists(ownerID) {
		return s.auditShared(auditEvent{Action: actionBootstrap, Result: resultDenied, Decision: decisionBootstrap, ActorID: actorSystem}, ErrInvalid, nil, nil)
	}
	if len(s.grants) != 0 {
		return s.auditShared(auditEvent{Action: actionBootstrap, Result: resultDenied, Decision: decisionBootstrap, ActorID: actorSystem}, ErrDenied, nil, nil)
	}
	orgID, err := newID()
	if err != nil {
		return err
	}
	org := &orgRecord{ID: orgID, VaultID: s.id}
	members := []membershipRecord{{
		HumanID:    ownerID,
		Role:       RoleOwner,
		Generation: 1,
		State:      memberActive,
	}}
	partial := auditEvent{
		Action: actionBootstrap, Result: resultAllowed, Decision: decisionBootstrap,
		ActorID: actorSystem, OrgID: orgID, TargetID: ownerID,
	}
	return s.auditShared(partial, nil, &sharedSnap{org: org, members: members}, nil)
}

// BindHuman returns a handle for a host-asserted identity. It does not
// authenticate, enroll, or impersonate that identity. An unknown id yields a
// handle whose operations fail closed and are not stored as a trusted actor.
func (s *Session) BindHuman(id string) (*HumanPrincipal, error) {
	if err := s.begin(); err != nil {
		return nil, err
	}
	defer s.end()
	if !s.shared() {
		return nil, ErrDenied
	}
	if safeID(id) == "" || id == actorSystem {
		if err := s.auditShared(auditEvent{Action: actionAccessReq, Result: resultDenied, Decision: decisionRequest, OrgID: s.org.ID}, ErrInvalid, nil, nil); err != nil {
			return nil, err
		}
		return nil, ErrInvalid
	}
	return &HumanPrincipal{s: s, id: id}, nil
}

func (h *HumanPrincipal) begin() error {
	if h == nil || h.s == nil {
		return ErrUnauthenticated
	}
	return h.s.begin()
}

func (h *HumanPrincipal) active() (membershipRecord, error) {
	if err := h.s.requireCurrent(); err != nil {
		return membershipRecord{}, err
	}
	if !h.s.shared() {
		return membershipRecord{}, ErrDenied
	}
	m, ok := h.s.member(h.id)
	if !ok || m.State != memberActive || (m.Role != RoleOwner && m.Role != RoleMember) {
		return membershipRecord{}, ErrDenied
	}
	return m, nil
}

func (s *Session) member(id string) (membershipRecord, bool) {
	for _, m := range s.members {
		if m.HumanID == id {
			return m, true
		}
	}
	return membershipRecord{}, false
}

func (s *Session) activeOwners() int {
	n := 0
	for _, m := range s.members {
		if m.State == memberActive && m.Role == RoleOwner {
			n++
		}
	}
	return n
}

// RequestAccess asks an owner to approve one exact local attestation grant.
func (h *HumanPrincipal) RequestAccess(spec AccessRequestSpec) (AccessRequest, error) {
	if err := h.begin(); err != nil {
		return AccessRequest{}, err
	}
	defer h.s.end()
	m, err := h.active()
	if err != nil {
		return AccessRequest{}, h.denyRequest(err)
	}
	now, err := h.s.evaluationTime()
	if err != nil {
		return AccessRequest{}, h.denyRequest(err)
	}
	if spec.AgentID == "" || !h.s.agentActive(spec.AgentID) || safeID(spec.CredentialID) == "" {
		return AccessRequest{}, h.denyRequest(ErrInvalid)
	}
	cred, ok := h.s.credByID(spec.CredentialID)
	if !ok || cred.Type != CredTypeEd25519 {
		return AccessRequest{}, h.denyRequest(ErrInvalid)
	}
	if err := validateResource(spec.Resource); err != nil {
		return AccessRequest{}, h.denyRequest(err)
	}
	expires, err := requireTime(spec.ExpiresAt)
	if err != nil || !expires.After(now) {
		return AccessRequest{}, h.denyRequest(ErrInvalid)
	}
	deadline, err := requireTime(spec.Deadline)
	if err != nil || !deadline.After(now) || deadline.After(now.Add(maxApprovalWindow)) || !deadline.Before(expires) {
		return AccessRequest{}, h.denyRequest(ErrInvalid)
	}
	secret, ok := h.s.copySecret(spec.CredentialID)
	if !ok {
		return AccessRequest{}, h.denyRequest(ErrInvalid)
	}
	keyID, err := attestKeyID(secret)
	wipe(secret)
	if err != nil || !canonicalKeyID(keyID) {
		return AccessRequest{}, h.denyRequest(ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return AccessRequest{}, err
	}
	rec := requestRecord{
		ID: id, OrgID: h.s.org.ID, VaultID: h.s.id,
		RequesterID: m.HumanID, RequesterGen: m.Generation,
		AgentID: spec.AgentID, CredentialID: spec.CredentialID, KeyID: keyID,
		Operation: OpLocalArtifactAttest, Resource: spec.Resource,
		ExpiresAt: expires, Deadline: deadline, Status: requestPending,
	}
	next := append(append([]requestRecord{}, h.s.requests...), rec)
	partial := h.event(actionAccessReq, resultAllowed, decisionRequest, spec.AgentID, id, "")
	partial.CredID = spec.CredentialID
	partial.CredType = CredTypeEd25519
	if err := h.s.auditShared(partial, nil, &sharedSnap{org: h.s.org, members: h.s.members, requests: next}, nil); err != nil {
		return AccessRequest{}, err
	}
	return rec.public(), nil
}

// Cancel withdraws the caller's own pending request.
func (h *HumanPrincipal) Cancel(requestID string) error {
	if err := h.begin(); err != nil {
		return err
	}
	defer h.s.end()
	m, err := h.active()
	if err != nil {
		return h.denyRequest(err)
	}
	rec, ok := h.s.request(requestID)
	if !ok || rec.RequesterID != m.HumanID || rec.RequesterGen != m.Generation || rec.Status != requestPending {
		return h.denyCancel(requestID, ErrDenied)
	}
	next := h.s.cloneRequests()
	for i := range next {
		if next[i].ID == rec.ID {
			next[i].Status = requestCancelled
		}
	}
	return h.s.auditShared(h.event(actionAccessCancel, resultAllowed, decisionCancel, "", rec.ID, ""), nil, &sharedSnap{org: h.s.org, members: h.s.members, requests: next}, nil)
}

// Requests returns this caller's own requests.
func (h *HumanPrincipal) Requests() ([]AccessRequest, error) {
	if err := h.begin(); err != nil {
		return nil, err
	}
	defer h.s.end()
	m, err := h.active()
	if err != nil {
		return nil, h.denyRequest(err)
	}
	var out []AccessRequest
	for _, rec := range h.s.requests {
		if rec.RequesterID == m.HumanID {
			out = append(out, rec.public())
		}
	}
	return out, nil
}

// Approve consumes one pending request and issues its original grant.
// The caller supplies the request id. Scope, key, and expiry are reread
// from the stored request and checked against the session clock.
func (h *HumanPrincipal) Approve(requestID string) (Grant, error) {
	if err := h.begin(); err != nil {
		return Grant{}, err
	}
	defer h.s.end()
	owner, err := h.owner()
	if err != nil {
		return Grant{}, h.denyApprove(requestID, err)
	}
	rec, ok := h.s.request(requestID)
	if !ok {
		return Grant{}, h.denyApprove(requestID, ErrDenied)
	}
	if rec.Status != requestPending || rec.OrgID != h.s.org.ID || rec.VaultID != h.s.id {
		return Grant{}, h.denyApprove(rec.ID, ErrDenied)
	}
	if owner.HumanID == rec.RequesterID {
		return Grant{}, h.denyApprove(rec.ID, ErrDenied)
	}
	now, err := h.s.evaluationTime()
	if err != nil {
		return Grant{}, h.denyApprove(rec.ID, err)
	}
	reqMember, mok := h.s.member(rec.RequesterID)
	if !mok || reqMember.State != memberActive || reqMember.Generation != rec.RequesterGen {
		return h.terminal(rec, requestInvalidated, actionAccessExpire, decisionExpire, ErrDenied)
	}
	if !now.Before(rec.Deadline) || !now.Before(rec.ExpiresAt) {
		return h.terminal(rec, requestExpired, actionAccessExpire, decisionExpire, ErrDeniedExpired)
	}
	if !h.s.agentActive(rec.AgentID) || rec.Operation != OpLocalArtifactAttest {
		return h.terminal(rec, requestInvalidated, actionAccessExpire, decisionExpire, ErrDenied)
	}
	cred, cok := h.s.credByID(rec.CredentialID)
	if !cok || cred.Type != CredTypeEd25519 {
		return h.terminal(rec, requestInvalidated, actionAccessExpire, decisionExpire, ErrDenied)
	}
	secret, sok := h.s.copySecret(rec.CredentialID)
	if !sok {
		return h.terminal(rec, requestInvalidated, actionAccessExpire, decisionExpire, ErrDenied)
	}
	keyID, kerr := attestKeyID(secret)
	wipe(secret)
	if kerr != nil || keyID != rec.KeyID {
		return h.terminal(rec, requestInvalidated, actionAccessExpire, decisionExpire, ErrDeniedKey)
	}
	grantID, err := newID()
	if err != nil {
		return Grant{}, err
	}
	prov := &grantProvenance{
		RequestID: rec.ID, OrgID: h.s.org.ID,
		RequesterID: rec.RequesterID, RequesterGen: rec.RequesterGen,
		ApproverID: owner.HumanID, ApproverGen: owner.Generation,
	}
	grant := grantRecord{
		ID: grantID, AgentID: rec.AgentID, CredentialID: rec.CredentialID,
		Operations: []string{OpLocalArtifactAttest}, Resource: rec.Resource,
		CreatedAt: now, ExpiresAt: rec.ExpiresAt, KeyID: rec.KeyID, Provenance: prov,
	}
	reqs := h.s.cloneRequests()
	for i := range reqs {
		if reqs[i].ID == rec.ID {
			reqs[i].Status = requestConsumed
			reqs[i].GrantID = grantID
			reqs[i].ApproverID = owner.HumanID
			reqs[i].ApproverGen = owner.Generation
		}
	}
	grants := append(append([]grantRecord{}, h.s.grants...), grant)
	approve := h.event(actionAccessApprove, resultAllowed, decisionApprove, rec.RequesterID, rec.ID, grantID)
	approve.CredID = rec.CredentialID
	approve.CredType = CredTypeEd25519
	issued := h.event(actionSharedGrant, resultAllowed, decisionGrant, rec.AgentID, rec.ID, grantID)
	issued.CredID = rec.CredentialID
	issued.CredType = CredTypeEd25519
	snap := &sharedSnap{org: h.s.org, members: h.s.members, requests: reqs}
	if err := h.s.commitShared([]auditEvent{approve, issued}, h.s.agents, grants, snap, true); err != nil {
		return Grant{}, err
	}
	return grant.public(), nil
}

// Reject marks another person's pending request rejected. It issues nothing.
func (h *HumanPrincipal) Reject(requestID string) error {
	if err := h.begin(); err != nil {
		return err
	}
	defer h.s.end()
	owner, err := h.owner()
	if err != nil {
		return h.denyApprove(requestID, err)
	}
	rec, ok := h.s.request(requestID)
	if !ok || rec.Status != requestPending || owner.HumanID == rec.RequesterID {
		return h.denyApprove(requestID, ErrDenied)
	}
	_, err = h.terminal(rec, requestRejected, actionAccessReject, decisionReject, nil)
	return err
}

// RevokeGrant revokes one grant. Later use stops. A signature already
// returned is not recalled.
func (h *HumanPrincipal) RevokeGrant(id string) error {
	if err := h.begin(); err != nil {
		return err
	}
	defer h.s.end()
	if _, err := h.owner(); err != nil {
		return h.denyRevoke(id, err)
	}
	if safeID(id) == "" {
		return h.denyRevoke("", ErrInvalid)
	}
	idx := -1
	for i := range h.s.grants {
		if h.s.grants[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 || h.s.grants[idx].Provenance == nil {
		return h.denyRevoke(id, ErrGrantNotFound)
	}
	if h.s.grants[idx].RevokedAt != nil {
		return h.denyRevoke(id, ErrInvalid)
	}
	next := append([]grantRecord{}, h.s.grants...)
	revoked := h.s.mustNow()
	next[idx].RevokedAt = &revoked
	g := next[idx]
	partial := h.event(actionSharedRevoke, resultAllowed, decisionRevoke, g.AgentID, g.Provenance.RequestID, g.ID)
	partial.CredID = g.CredentialID
	partial.CredType = CredTypeEd25519
	return h.s.auditShared(partial, nil, nil, next)
}

// Attach enrolls a trusted-host identity that this vault did not create.
// Re-enrollment of a removed identity bumps the generation and does not
// revive old requests or grants.
func (h *HumanPrincipal) Attach(humanID, role string) error {
	if err := h.begin(); err != nil {
		return err
	}
	defer h.s.end()
	return h.mutateMember(humanID, role, true)
}

// Remove drops an active member. The last owner cannot be removed.
func (h *HumanPrincipal) Remove(humanID string) error {
	if err := h.begin(); err != nil {
		return err
	}
	defer h.s.end()
	if _, err := h.owner(); err != nil {
		return h.denyMember(actionMemberRemove, decisionRemove, humanID, err)
	}
	m, ok := h.s.member(humanID)
	if !ok || m.State != memberActive {
		return h.denyMember(actionMemberRemove, decisionRemove, humanID, ErrDenied)
	}
	if m.Role == RoleOwner && h.s.activeOwners() < 2 {
		return h.denyMember(actionMemberRemove, decisionRemove, humanID, ErrDenied)
	}
	return h.writeMember(m, memberRemoved, m.Role, actionMemberRemove, decisionRemove)
}

// AssignRole changes owner or member. Demotion and promotion bump the
// generation. The last owner cannot be demoted.
func (h *HumanPrincipal) AssignRole(humanID, role string) error {
	if err := h.begin(); err != nil {
		return err
	}
	defer h.s.end()
	if _, err := h.owner(); err != nil {
		return h.denyMember(actionMemberRole, decisionRole, humanID, err)
	}
	if role != RoleOwner && role != RoleMember {
		return h.denyMember(actionMemberRole, decisionRole, humanID, ErrInvalid)
	}
	m, ok := h.s.member(humanID)
	if !ok || m.State != memberActive || m.Role == role {
		return h.denyMember(actionMemberRole, decisionRole, humanID, ErrDenied)
	}
	if m.Role == RoleOwner && role == RoleMember && h.s.activeOwners() < 2 {
		return h.denyMember(actionMemberRole, decisionRole, humanID, ErrDenied)
	}
	return h.writeMember(m, memberActive, role, actionMemberRole, decisionRole)
}

// CreateAgent registers an agent. The actor is the owner, not the agent.
func (h *HumanPrincipal) CreateAgent(label string) (Agent, error) {
	if err := h.begin(); err != nil {
		return Agent{}, err
	}
	defer h.s.end()
	if _, err := h.owner(); err != nil {
		if aerr := h.s.finish(auditEvent{Action: actionAgentCreate, Result: resultDenied}, err); aerr != nil {
			return Agent{}, aerr
		}
		return Agent{}, ErrDenied
	}
	h.s.boundActor = h.id
	defer func() { h.s.boundActor = "" }()
	agent, err := h.s.createAgentUnlocked(label)
	if err != nil {
		return Agent{}, err
	}
	return agent, nil
}

// Put stores a credential. Shared mode has no plaintext retrieval.
func (h *HumanPrincipal) Put(label, typ string, secret []byte, opt PutOptions) (Credential, error) {
	if err := h.begin(); err != nil {
		return Credential{}, err
	}
	defer h.s.end()
	if _, err := h.owner(); err != nil {
		return h.s.denyPut(ErrDenied)
	}
	h.s.boundActor = h.id
	defer func() { h.s.boundActor = "" }()
	return h.s.putUnlocked(label, typ, secret, opt)
}

// Replace changes credential bytes. A shared attestation grant stays pinned
// to the previous key identity.
func (h *HumanPrincipal) Replace(id string, secret []byte, opt LifecycleOptions) (Credential, error) {
	if err := h.begin(); err != nil {
		return Credential{}, err
	}
	defer h.s.end()
	if _, err := h.owner(); err != nil {
		if aerr := h.s.denyAction(actionReplace, ErrDenied); aerr != nil {
			return Credential{}, aerr
		}
		return Credential{}, ErrDenied
	}
	h.s.boundActor = h.id
	defer func() { h.s.boundActor = "" }()
	return h.s.replaceUnlocked(id, secret, opt)
}

// Credentials returns inventory metadata. Members do not receive labels.
// Secrets are never returned.
func (h *HumanPrincipal) Credentials() ([]Credential, error) {
	if err := h.begin(); err != nil {
		return nil, err
	}
	defer h.s.end()
	m, err := h.active()
	if err != nil {
		return nil, h.denyRequest(err)
	}
	out := make([]Credential, len(h.s.creds))
	for i := range h.s.creds {
		out[i] = h.s.creds[i].public()
		if m.Role != RoleOwner {
			out[i].Label = ""
		}
	}
	return out, nil
}

// Agents returns agent metadata. Members do not receive labels.
func (h *HumanPrincipal) Agents() ([]Agent, error) {
	if err := h.begin(); err != nil {
		return nil, err
	}
	defer h.s.end()
	m, err := h.active()
	if err != nil {
		return nil, h.denyRequest(err)
	}
	out := make([]Agent, len(h.s.agents))
	for i := range h.s.agents {
		out[i] = h.s.agents[i].public()
		if m.Role != RoleOwner {
			out[i].Label = ""
		}
	}
	return out, nil
}

// Audit returns the human audit view for an owner.
func (h *HumanPrincipal) Audit(f AuditFilter) ([]AuditRecord, error) {
	if err := h.begin(); err != nil {
		return nil, err
	}
	defer h.s.end()
	if _, err := h.owner(); err != nil {
		if aerr := h.s.auditShared(h.event(actionSharedAudit, resultDenied, decisionAudit, "", "", ""), ErrDenied, nil, nil); aerr != nil {
			return nil, aerr
		}
		return nil, ErrDenied
	}
	if err := h.s.auditShared(h.event(actionSharedAudit, resultAllowed, decisionAudit, "", "", ""), nil, nil, nil); err != nil {
		return nil, err
	}
	return h.s.auditHistoryUnlocked(f)
}

func (h *HumanPrincipal) owner() (membershipRecord, error) {
	m, err := h.active()
	if err != nil {
		return membershipRecord{}, err
	}
	if m.Role != RoleOwner {
		return membershipRecord{}, ErrDenied
	}
	return m, nil
}

func (h *HumanPrincipal) mutateMember(humanID, role string, attach bool) error {
	if _, err := h.owner(); err != nil {
		return h.denyMember(actionMemberAttach, decisionAttach, humanID, err)
	}
	if !attach || (role != RoleOwner && role != RoleMember) || safeID(humanID) == "" || humanID == actorSystem || h.s.agentExists(humanID) {
		return h.denyMember(actionMemberAttach, decisionAttach, humanID, ErrInvalid)
	}
	if existing, ok := h.s.member(humanID); ok {
		if existing.State == memberActive {
			return h.denyMember(actionMemberAttach, decisionAttach, humanID, ErrDenied)
		}
		return h.writeMember(existing, memberActive, role, actionMemberAttach, decisionAttach)
	}
	members := append(append([]membershipRecord{}, h.s.members...), membershipRecord{
		HumanID: humanID, Role: role, Generation: 1, State: memberActive,
	})
	partial := h.event(actionMemberAttach, resultAllowed, decisionAttach, humanID, "", "")
	return h.s.auditShared(partial, nil, &sharedSnap{org: h.s.org, members: members, requests: h.s.requests}, nil)
}

func (h *HumanPrincipal) writeMember(prev membershipRecord, state, role, action, decision string) error {
	members := append([]membershipRecord{}, h.s.members...)
	for i := range members {
		if members[i].HumanID != prev.HumanID {
			continue
		}
		members[i].State = state
		members[i].Role = role
		members[i].Generation = prev.Generation + 1
	}
	requests := h.s.cloneRequests()
	for i := range requests {
		if requests[i].Status == requestPending && requests[i].RequesterID == prev.HumanID {
			requests[i].Status = requestInvalidated
		}
	}
	partial := h.event(action, resultAllowed, decision, prev.HumanID, "", "")
	return h.s.auditShared(partial, nil, &sharedSnap{org: h.s.org, members: members, requests: requests}, nil)
}

func (h *HumanPrincipal) terminal(rec requestRecord, status, action, decision string, cause error) (Grant, error) {
	next := h.s.cloneRequests()
	for i := range next {
		if next[i].ID == rec.ID && next[i].Status == requestPending {
			next[i].Status = status
		}
	}
	result := resultAllowed
	if cause != nil {
		result = resultDenied
	}
	partial := h.event(action, result, decision, rec.RequesterID, rec.ID, "")
	if err := h.s.auditShared(partial, cause, &sharedSnap{org: h.s.org, members: h.s.members, requests: next}, nil); err != nil {
		return Grant{}, err
	}
	return Grant{}, cause
}

func (h *HumanPrincipal) event(action, result, decision, target, requestID, grantID string) auditEvent {
	actor := ""
	if m, ok := h.s.member(h.id); ok && m.HumanID == h.id {
		actor = h.id
	}
	org := ""
	if h.s.org != nil {
		org = h.s.org.ID
	}
	if safeID(target) == "" {
		target = ""
	}
	if safeID(requestID) == "" {
		requestID = ""
	}
	if safeID(grantID) == "" {
		grantID = ""
	}
	return auditEvent{
		Action: action, Result: result, Decision: decision,
		ActorID: actor, OrgID: org, TargetID: target, RequestID: requestID, GrantID: grantID,
	}
}

func (h *HumanPrincipal) denyRequest(cause error) error {
	if cause == nil {
		cause = ErrDenied
	}
	if err := h.s.auditShared(h.event(actionAccessReq, resultDenied, decisionRequest, "", "", ""), cause, nil, nil); err != nil {
		return err
	}
	return cause
}

func (h *HumanPrincipal) denyCancel(id string, cause error) error {
	if _, ok := h.s.request(id); !ok {
		id = ""
	}
	if err := h.s.auditShared(h.event(actionAccessCancel, resultDenied, decisionCancel, "", id, ""), cause, nil, nil); err != nil {
		return err
	}
	return cause
}

func (h *HumanPrincipal) denyApprove(id string, cause error) error {
	if cause == nil {
		cause = ErrDenied
	}
	if _, ok := h.s.request(id); !ok {
		id = ""
	}
	if err := h.s.auditShared(h.event(actionAccessApprove, resultDenied, decisionApprove, "", id, ""), cause, nil, nil); err != nil {
		return err
	}
	return cause
}

func (h *HumanPrincipal) denyRevoke(id string, cause error) error {
	if _, ok := h.s.grantByID(id); !ok {
		id = ""
	}
	if err := h.s.auditShared(h.event(actionSharedRevoke, resultDenied, decisionRevoke, "", "", id), cause, nil, nil); err != nil {
		return err
	}
	return cause
}

func (h *HumanPrincipal) denyMember(action, decision, humanID string, cause error) error {
	target := ""
	if safeID(humanID) != "" && humanID != actorSystem {
		target = ""
		if _, ok := h.s.member(humanID); ok {
			target = humanID
		}
	}
	if err := h.s.auditShared(h.event(action, resultDenied, decision, target, "", ""), cause, nil, nil); err != nil {
		return err
	}
	return cause
}

func (s *Session) auditShared(partial auditEvent, cause error, snap *sharedSnap, grants []grantRecord) error {
	if grants == nil {
		grants = s.grants
	}
	if err := s.commitShared([]auditEvent{partial}, s.agents, grants, snap, false); err != nil {
		return err
	}
	return cause
}

func (s *Session) commitShared(partials []auditEvent, agents []agentRecord, grants []grantRecord, snap *sharedSnap, notify bool) error {
	if err := s.requireCurrent(); err != nil {
		return err
	}
	events := make([]auditEvent, 0, len(partials)+1)
	chain := s.audit
	for _, partial := range partials {
		ev, err := nextAudit(append(append([]auditEvent{}, chain...), events...), s.id, partial)
		if err != nil {
			return err
		}
		events = append(events, ev)
	}
	if notify && len(events) > 0 {
		resp, err := nextAudit(append(append([]auditEvent{}, chain...), events...), s.id, noticePartial(actionRespond, resultDecisionNotify, events[0], Classification{Class: ClassApproval, Severity: SeverityHigh}))
		if err != nil {
			return err
		}
		events = append(events, resp)
	}
	return s.commitBatch(events, s.creds, agents, grants, false, nil, snap)
}

func (s *Session) cloneRequests() []requestRecord {
	return append([]requestRecord{}, s.requests...)
}

func (s *Session) request(id string) (requestRecord, bool) {
	if safeID(id) == "" {
		return requestRecord{}, false
	}
	for _, rec := range s.requests {
		if rec.ID == id {
			return rec, true
		}
	}
	return requestRecord{}, false
}

func (s *Session) mustNow() time.Time {
	now, err := s.evaluationTime()
	if err != nil {
		return time.Now().UTC()
	}
	return now
}

func (r requestRecord) public() AccessRequest {
	return AccessRequest{
		ID: r.ID, AgentID: r.AgentID, CredentialID: r.CredentialID, Resource: r.Resource,
		ExpiresAt: r.ExpiresAt, Deadline: r.Deadline, Status: r.Status, GrantID: r.GrantID,
	}
}

// decisionGrants presents shared grants whose membership no longer
// authorizes them as revoked, so a newer grant can still match.
func (s *Session) decisionGrants() []grantRecord {
	if s == nil || !s.shared() {
		return s.grants
	}
	out := make([]grantRecord, len(s.grants))
	copy(out, s.grants)
	revoked := s.mustNow()
	for i := range out {
		if out[i].RevokedAt == nil && !s.provenanceLive(out[i].Provenance) {
			out[i].RevokedAt = &revoked
		}
	}
	return out
}

func (s *Session) provenanceLive(p *grantProvenance) bool {
	if !s.shared() || p == nil || s.org == nil || p.OrgID != s.org.ID {
		return false
	}
	if p.RequesterID == "" || p.RequesterID == p.ApproverID {
		return false
	}
	req, ok := s.member(p.RequesterID)
	if !ok || req.State != memberActive || req.Generation != p.RequesterGen {
		return false
	}
	approver, ok := s.member(p.ApproverID)
	if !ok || approver.State != memberActive || approver.Role != RoleOwner || approver.Generation != p.ApproverGen {
		return false
	}
	return true
}

// sharedGrantLive reports whether a shared-mode grant may still be used.
// Legacy vaults are unchanged. A stale session fails closed.
func (s *Session) sharedGrantLive(id string) error {
	if s == nil || !s.shared() {
		return nil
	}
	if err := s.requireCurrent(); err != nil {
		return err
	}
	g, ok := s.grantByID(id)
	if !ok || g.Provenance == nil || !s.provenanceLive(g.Provenance) || g.RevokedAt != nil {
		return ErrDeniedRevoked
	}
	now, err := s.evaluationTime()
	if err != nil || !now.Before(g.ExpiresAt) {
		return ErrDeniedExpired
	}
	return nil
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
	if err := validateDetection(doc.Detection); err != nil {
		return err
	}
	return validateSharedState(doc.Organization, doc.Memberships, doc.Requests, doc.Credentials, doc.Agents, doc.Grants)
}

func sharedMatchesVault(doc document, vaultID string) error {
	if doc.Organization == nil {
		return nil
	}
	if doc.Organization.VaultID != vaultID {
		return ErrCorrupt
	}
	return nil
}

func validateSharedState(org *orgRecord, members []membershipRecord, requests []requestRecord, creds []credential, agents []agentRecord, grants []grantRecord) error {
	shared := org != nil
	if !shared {
		if len(members) != 0 || len(requests) != 0 {
			return ErrCorrupt
		}
		for _, g := range grants {
			if g.Provenance != nil {
				return ErrCorrupt
			}
		}
		return nil
	}
	if safeID(org.ID) == "" || safeID(org.VaultID) == "" || org.ID == actorSystem {
		return ErrCorrupt
	}
	agentIDs := map[string]struct{}{}
	for _, a := range agents {
		agentIDs[a.ID] = struct{}{}
	}
	seenHuman := map[string]membershipRecord{}
	owners := 0
	for _, m := range members {
		if safeID(m.HumanID) == "" || m.HumanID == actorSystem || m.Generation == 0 {
			return ErrCorrupt
		}
		if m.Role != RoleOwner && m.Role != RoleMember {
			return ErrCorrupt
		}
		if m.State != memberActive && m.State != memberRemoved {
			return ErrCorrupt
		}
		if _, dup := seenHuman[m.HumanID]; dup {
			return ErrCorrupt
		}
		if _, isAgent := agentIDs[m.HumanID]; isAgent {
			return ErrCorrupt
		}
		seenHuman[m.HumanID] = m
		if m.State == memberActive && m.Role == RoleOwner {
			owners++
		}
	}
	if owners < 1 {
		return ErrCorrupt
	}
	credIDs := map[string]string{}
	for _, c := range creds {
		credIDs[c.ID] = c.Type
	}
	seenReq := map[string]requestRecord{}
	for _, r := range requests {
		if safeID(r.ID) == "" || r.OrgID != org.ID || r.VaultID != org.VaultID {
			return ErrCorrupt
		}
		if _, dup := seenReq[r.ID]; dup {
			return ErrCorrupt
		}
		mem, ok := seenHuman[r.RequesterID]
		if !ok || r.RequesterGen == 0 || r.RequesterGen > mem.Generation {
			return ErrCorrupt
		}
		if _, ok := agentIDs[r.AgentID]; !ok || safeID(r.CredentialID) == "" || credIDs[r.CredentialID] != CredTypeEd25519 {
			return ErrCorrupt
		}
		if r.Operation != OpLocalArtifactAttest || !canonicalKeyID(r.KeyID) || validateResource(r.Resource) != nil {
			return ErrCorrupt
		}
		if _, err := requireTime(r.ExpiresAt); err != nil {
			return ErrCorrupt
		}
		deadline, err := requireTime(r.Deadline)
		if err != nil || !deadline.Before(r.ExpiresAt) {
			return ErrCorrupt
		}
		switch r.Status {
		case requestPending:
			if r.RequesterGen != mem.Generation || mem.State != memberActive || r.GrantID != "" || r.ApproverID != "" {
				return ErrCorrupt
			}
		case requestConsumed:
			if safeID(r.GrantID) == "" || safeID(r.ApproverID) == "" || r.ApproverGen == 0 || r.ApproverID == r.RequesterID {
				return ErrCorrupt
			}
			ap, aok := seenHuman[r.ApproverID]
			if !aok || r.ApproverGen > ap.Generation {
				return ErrCorrupt
			}
		case requestRejected, requestCancelled, requestExpired, requestInvalidated:
			if r.GrantID != "" {
				return ErrCorrupt
			}
		default:
			return ErrCorrupt
		}
		seenReq[r.ID] = r
	}
	used := map[string]struct{}{}
	for _, g := range grants {
		if g.Provenance == nil {
			return ErrCorrupt
		}
		p := g.Provenance
		if p.OrgID != org.ID || safeID(p.RequestID) == "" || p.RequesterGen == 0 || p.ApproverGen == 0 || p.RequesterID == p.ApproverID {
			return ErrCorrupt
		}
		req, ok := seenReq[p.RequestID]
		if !ok || req.Status != requestConsumed || req.GrantID != g.ID {
			return ErrCorrupt
		}
		if _, dup := used[p.RequestID]; dup {
			return ErrCorrupt
		}
		used[p.RequestID] = struct{}{}
		if p.RequesterID != req.RequesterID || p.RequesterGen != req.RequesterGen || p.ApproverID != req.ApproverID || p.ApproverGen != req.ApproverGen {
			return ErrCorrupt
		}
		if g.AgentID != req.AgentID || g.CredentialID != req.CredentialID || g.KeyID != req.KeyID || g.Resource != req.Resource {
			return ErrCorrupt
		}
		if g.CredentialClass != "" || !soleLocalAttest(g.Operations) {
			return ErrCorrupt
		}
	}
	for _, r := range requests {
		if r.Status == requestConsumed {
			if _, ok := used[r.ID]; !ok {
				return ErrCorrupt
			}
		}
	}
	return nil
}

func sharedAuditClear(ev auditEvent) error {
	if ev.AgentID != "" || ev.Operation != "" || ev.Class != "" || ev.RefSeq != 0 || ev.Reasons != "" || ev.CredGen != 0 {
		return ErrAudit
	}
	return nil
}

func canonicalSharedAudit(ev auditEvent) bool {
	if ev.Result != resultAllowed && ev.Result != resultDenied {
		return false
	}
	if !sharedDecision(ev.Decision) {
		return false
	}
	if ev.ActorID != "" && ev.ActorID != actorSystem && safeID(ev.ActorID) == "" {
		return false
	}
	if ev.Result == resultAllowed && (ev.ActorID == "" || safeID(ev.OrgID) == "") {
		return false
	}
	if ev.OrgID != "" && safeID(ev.OrgID) == "" {
		return false
	}
	if ev.TargetID != "" && safeID(ev.TargetID) == "" {
		return false
	}
	if ev.RequestID != "" && safeID(ev.RequestID) == "" {
		return false
	}
	if ev.GrantID != "" && safeID(ev.GrantID) == "" {
		return false
	}
	if ev.ActorID == actorSystem && ev.Action != actionBootstrap {
		return false
	}
	return true
}

func sharedDecision(d string) bool {
	switch d {
	case decisionBootstrap, decisionAttach, decisionRemove, decisionRole, decisionRequest,
		decisionCancel, decisionReject, decisionApprove, decisionExpire, decisionGrant, decisionRevoke, decisionAudit, decisionInventory:
		return true
	default:
		return false
	}
}

func validSharedAudit(ev auditEvent) error {
	if ev.V != auditSharedVersion || sharedAuditClear(ev) != nil || !canonicalSharedAudit(ev) {
		return ErrAudit
	}
	switch ev.Action {
	case actionBootstrap:
		if ev.Result == resultAllowed && (ev.ActorID != actorSystem || ev.TargetID == "" || ev.Decision != decisionBootstrap) {
			return ErrAudit
		}
	case actionAccessApprove:
		if ev.Result == resultAllowed && (ev.RequestID == "" || ev.GrantID == "" || ev.Decision != decisionApprove) {
			return ErrAudit
		}
	case actionSharedGrant:
		if ev.Result == resultAllowed && (ev.GrantID == "" || ev.RequestID == "" || ev.TargetID == "" || ev.CredID == "" || ev.CredType != CredTypeEd25519 || ev.Decision != decisionGrant) {
			return ErrAudit
		}
	case actionSharedRevoke:
		if ev.Result == resultAllowed && (ev.GrantID == "" || ev.Decision != decisionRevoke) {
			return ErrAudit
		}
	case actionMemberAttach, actionMemberRemove, actionMemberRole:
		if ev.Result == resultAllowed && ev.TargetID == "" {
			return ErrAudit
		}
	case actionAccessReq:
		if ev.Result == resultAllowed && (ev.RequestID == "" || ev.CredType != CredTypeEd25519) {
			return ErrAudit
		}
	case actionAccessCancel, actionAccessReject, actionAccessExpire, actionSharedAudit, actionInventory:
	default:
		return ErrAudit
	}
	return nil
}

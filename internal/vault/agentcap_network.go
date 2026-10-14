package vault

import (
	"context"
	"net/http"
	"strconv"
	"strings"
)

// The network result is a closed projection, never an upstream message.
type capNetworkResult struct {
	operation string
	status    int
	issue     GitHubIssueState
}

func networkOperation(op string) bool {
	return op == OpHTTPRequest || op == OpGitHubIssueState
}

func capEntryScopeOK(op, resource, keyID string) bool {
	if op == OpLocalArtifactAttest {
		return canonicalKeyID(keyID) && validateResource(resource) == nil
	}
	if op == OpSSHUserAuth {
		return keyID == "" && validateResource(resource) == nil
	}
	if !networkOperation(op) || keyID != "" {
		return false
	}
	method, target, ok := splitPolicyResource(resource)
	if !ok {
		return false
	}
	canonical, _, _, class := classifyTarget(method, target)
	if class != targetOK || canonical != resource {
		return false
	}
	if op == OpGitHubIssueState {
		_, _, _, ok = githubIssueScope(resource)
	}
	return ok
}

func githubIssueScope(resource string) (owner, repo string, number int64, ok bool) {
	const prefix = "GET https://api.github.com/repos/"
	if !strings.HasPrefix(resource, prefix) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(resource, prefix), "/")
	if len(parts) != 4 || parts[2] != "issues" {
		return
	}
	target, n, err := canonicalGitHubIssue(parts[0], parts[1], parts[3])
	if err != nil || resource != http.MethodGet+" "+target {
		return
	}
	return parts[0], parts[1], n, true
}

func (s *Session) capGrantSupported(g grantRecord) bool {
	if len(g.Operations) != 1 || g.CredentialClass != "" || safeID(g.CredentialID) == "" {
		return false
	}
	op := g.Operations[0]
	if op == OpSSHUserAuth {
		c, ok := s.credByID(g.CredentialID)
		return sshGrantShape(g) && validateResource(g.Resource) == nil && ok && c.Type == CredTypeEd25519
	}
	if !capEntryScopeOK(op, g.Resource, g.KeyID) {
		return false
	}
	if networkOperation(op) {
		_, ok := s.credByID(g.CredentialID)
		return ok
	}
	return true
}

func (b agentBinder) agentCapNetwork(ctx context.Context, agentID string, bound agentCapGrant) (capNetworkResult, error) {
	if b.s == nil {
		return capNetworkResult{}, ErrUnauthenticated
	}
	return b.s.agentCapNetwork(ctx, agentID, bound)
}

func (s *Session) agentCapNetwork(ctx context.Context, agentID string, bound agentCapGrant) (capNetworkResult, error) {
	if err := s.begin(); err != nil {
		return capNetworkResult{}, err
	}
	defer s.end()
	if err := s.requireCurrent(); err != nil {
		return capNetworkResult{}, err
	}
	partial, err := s.judgeExactNetwork(agentID, bound)
	if err != nil {
		if capHost(err) {
			return capNetworkResult{}, err
		}
		err = s.failExactNetwork(partial, "", err)
		return capNetworkResult{}, err
	}
	method, target, _ := splitPolicyResource(bound.resource)
	call := brokerAttempt{credentialID: bound.credID, method: method, target: target, operation: bound.operation, bound: &bound, ctx: ctx}
	out := capNetworkResult{operation: bound.operation}
	if bound.operation == OpGitHubIssueState {
		owner, repo, number, ok := githubIssueScope(bound.resource)
		if !ok {
			return capNetworkResult{}, ErrInvalid
		} // checked before audit above
		call.prepare = prepareGitHub
		call.accept = func(body []byte) error {
			st, err := parseGitHubIssueState(body, owner, repo, number)
			if err == nil {
				out.issue = st
			}
			return err
		}
	}
	status, err := s.brokerExchange(agentID, call)
	if err != nil {
		return capNetworkResult{}, err
	}
	out.status = status
	return out, nil
}

// judgeExactNetwork never searches for an alternative grant. Both the stored
// scope and the credential generation must still be those bound at discovery.
func (s *Session) judgeExactNetwork(agentID string, bound agentCapGrant) (auditEvent, error) {
	// A trusted callback may have locked the session while its mutex was released.
	if err := s.live(); err != nil {
		return auditEvent{}, err
	}
	if err := s.requireCurrent(); err != nil {
		return auditEvent{}, err
	}
	bare := s.boundAgentDenial(agentID)
	g, ok := s.grantByID(bound.grantID)
	if !ok || g.AgentID != agentID || !networkOperation(bound.operation) || !s.capGrantSupported(g) ||
		g.CredentialID != bound.credID || g.Resource != bound.resource || g.KeyID != bound.keyID || g.Operations[0] != bound.operation {
		return bare, ErrInvalid
	}
	ev := auditEvent{AgentID: agentID, GrantID: g.ID, CredID: g.CredentialID, CredType: s.auditCredType(g), Operation: bound.operation}
	if !s.agentActive(agentID) {
		ev.Result = resultDeniedAgent
		return ev, ErrDeniedAgent
	}
	if g.RevokedAt != nil {
		ev.Result = resultDeniedRevoked
		return ev, ErrDeniedRevoked
	}
	now, err := s.evaluationTime()
	if err != nil || !now.Before(g.ExpiresAt) {
		ev.Result = resultDeniedExpired
		return ev, ErrDeniedExpired
	}
	c, ok := s.credByID(g.CredentialID)
	if !ok || c.Gen != bound.credGen || c.Lifecycle.State != StateActive {
		ev.Result = resultDeniedCredential
		return ev, ErrDeniedCredential
	}
	ev.Result = resultAllowed
	return ev, nil
}

// Recheck after a callback and before both credential transmission and result
// release. Audit errors are host errors and outrank a routine refusal.
func (s *Session) checkExactNetwork(agentID string, call brokerAttempt, sent bool) error {
	if call.bound == nil {
		return nil
	}
	ev, err := s.judgeExactNetwork(agentID, *call.bound)
	if err == nil && call.ctx != nil && call.ctx.Err() != nil {
		ev.Result, err = resultDeniedDestination, ErrBrokerUpstream
		if sent {
			ev.Result = resultUpstreamError
		}
	}
	if err == nil {
		return nil
	}
	if capHost(err) {
		return err
	}
	return s.failExactNetwork(ev, call.method, err)
}

func (s *Session) failExactNetwork(ev auditEvent, method string, cause error) error {
	if ev.Result == resultDenied {
		// A missing/stale scope is not safely attributable to a broker grant.
		ev.Action = actionAgentCap
		return s.finish(ev, cause)
	}
	_, err := s.failExchange(ev, method, cause)
	return err
}

func encodeNetworkResult(out capNetworkResult) ([]byte, error) {
	var fields []capWire
	add := func(id byte, value string) {
		fields = append(fields, capWire{id: id, typ: capTypeString, val: []byte(value)})
	}
	switch out.operation {
	case OpHTTPRequest:
		if out.status < 200 || out.status > 599 || out.status/100 == 3 {
			return nil, ErrInvalid
		}
		add(capFieldHTTPStatus, strconv.Itoa(out.status))
	case OpGitHubIssueState:
		st := out.issue
		if st.Number < 1 || st.Number > githubMaxIssueNumber || (st.State != "open" && st.State != "closed") || st.Comments < 0 || st.Comments > githubMaxComments {
			return nil, ErrInvalid
		}
		add(capFieldIssueNumber, strconv.FormatInt(st.Number, 10))
		add(capFieldIssueState, st.State)
		add(capFieldIssueLocked, strconv.FormatBool(st.Locked))
		add(capFieldIssueComments, strconv.FormatInt(st.Comments, 10))
	default:
		return nil, ErrInvalid
	}
	return encodeCap(capMethodInvoke, fields)
}

func decodeNetworkResult(fields map[byte]capWire) (capResponse, error) {
	if raw, ok := capString(fields, capFieldHTTPStatus); ok && len(fields) == 1 {
		n, good := githubExactInt([]byte(raw), 200, 599)
		if !good || n/100 == 3 {
			return capResponse{}, ErrInvalid
		}
		return capResponse{method: capMethodInvoke, network: capNetworkResult{operation: OpHTTPRequest, status: int(n)}}, nil
	}
	num, nok := capString(fields, capFieldIssueNumber)
	state, sok := capString(fields, capFieldIssueState)
	locked, lok := capString(fields, capFieldIssueLocked)
	comments, cok := capString(fields, capFieldIssueComments)
	n, ngood := githubExactInt([]byte(num), 1, githubMaxIssueNumber)
	c, cgood := githubExactInt([]byte(comments), 0, githubMaxComments)
	l, lgood := githubExactBool([]byte(locked))
	if len(fields) != 4 || !nok || !sok || !lok || !cok || !ngood || !cgood || !lgood || (state != "open" && state != "closed") {
		return capResponse{}, ErrInvalid
	}
	return capResponse{method: capMethodInvoke, network: capNetworkResult{operation: OpGitHubIssueState, issue: GitHubIssueState{Number: n, State: state, Locked: l, Comments: c}}}, nil
}

package vault

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// The network result is a closed projection, never an upstream message.
type capNetworkResult struct {
	operation string
	status    int
	response  HTTPResponse
}

func networkOperation(op string) bool {
	return op == OpHTTPRequest || op == OpHTTPBroker
}

func capEntryScopeOK(op, resource, keyID string) bool {
	if op == OpLocalArtifactAttest {
		return canonicalKeyID(keyID) && validateResource(resource) == nil
	}
	if op == OpSSHUserAuth {
		return keyID == "" && validateResource(resource) == nil
	}
	if keyID != "" {
		return false
	}
	if op == OpHTTPBroker {
		_, _, _, ok := brokerScope(resource)
		return ok
	}
	if op != OpHTTPRequest {
		return false
	}
	method, target, ok := splitPolicyResource(resource)
	if !ok {
		return false
	}
	canonical, _, _, class := classifyTarget(method, target)
	return class == targetOK && canonical == resource
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
	if op == OpHTTPBroker && !brokerGrantShape(g) {
		return false
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

func (b agentBinder) agentCapNetwork(ctx context.Context, agentID string, bound agentCapGrant, req HTTPRequest) (capNetworkResult, error) {
	if err := b.bound(agentID); err != nil {
		return capNetworkResult{}, err
	}
	return b.s.agentCapNetwork(ctx, agentID, bound, req)
}

func (s *Session) agentCapNetwork(ctx context.Context, agentID string, bound agentCapGrant, req HTTPRequest) (capNetworkResult, error) {
	if err := s.begin(); err != nil {
		return capNetworkResult{}, err
	}
	defer s.end()
	partial, err := s.judgeExactNetwork(agentID, bound)
	if err != nil {
		if capHost(err) {
			return capNetworkResult{}, err
		}
		err = s.failExactNetwork(partial, "", err)
		return capNetworkResult{}, err
	}
	out := capNetworkResult{operation: bound.operation}
	if bound.operation == OpHTTPBroker {
		// The handle pins one origin, method set and prefix. The invoke
		// message supplies the rest of the request, so the pinned scope is
		// enforced here, before the destination is resolved.
		origin, prefix, ok := brokerGrantScope(bound.resource)
		if !ok {
			return capNetworkResult{}, ErrInvalid
		} // checked before audit above
		req.CredentialID, req.Origin = bound.credID, origin
		if cause := boundScopeDenial(bound, prefix, req); cause != nil {
			partial.Result = boundScopeResult(cause)
			return capNetworkResult{}, s.failExactNetwork(partial, req.Method, cause)
		}
		resp, err := s.brokerRequestUnlocked(ctx, agentID, req, &bound)
		if err != nil {
			return capNetworkResult{}, err
		}
		out.status, out.response = resp.StatusCode, resp
		return out, nil
	}
	method, target, _ := splitPolicyResource(bound.resource)
	status, err := s.brokerExchange(agentID, brokerAttempt{
		credentialID: bound.credID, method: method, target: target,
		operation: bound.operation, bound: &bound, ctx: ctx,
	})
	if err != nil {
		return capNetworkResult{}, err
	}
	out.status = status
	return out, nil
}

// boundScopeDenial checks the invoke message against the scope the handle
// pinned. It runs before destination resolution and before any secret copy.
func boundScopeDenial(bound agentCapGrant, prefix string, req HTTPRequest) error {
	if !methodAllowed(strings.Split(bound.methods, ","), req.Method) {
		return ErrDeniedMethod
	}
	if !pathUnderPrefix(prefix, req.Path) {
		return ErrDeniedPath
	}
	return nil
}

func boundScopeResult(cause error) string {
	if errors.Is(cause, ErrDeniedMethod) {
		return resultDeniedMethod
	}
	return resultDeniedPath
}

// brokerScopePinned reports whether a grant still carries the method set and
// credential placement a handle was bound to. A rescoped grant is stale.
func brokerScopePinned(g grantRecord, bound agentCapGrant) bool {
	return strings.Join(g.HTTPMethods, ",") == bound.methods && formatInjection(grantInjectionOf(g)) == bound.inject
}

// judgeExactNetwork never searches for an alternative grant. Both the stored
// scope and the credential generation must still be those bound at discovery.
func (s *Session) judgeExactNetwork(agentID string, bound agentCapGrant) (auditEvent, error) {
	// A trusted callback may have locked the session while its mutex was released.
	if err := s.live(); err != nil {
		return auditEvent{}, err
	}
	if err := s.adoptLocked(); err != nil {
		return auditEvent{}, err
	}
	bare := s.boundAgentDenial(agentID)
	g, ok := s.grantByID(bound.grantID)
	if !ok || g.AgentID != agentID || !networkOperation(bound.operation) || !s.capGrantSupported(g) ||
		g.CredentialID != bound.credID || g.Resource != bound.resource || g.KeyID != bound.keyID || g.Operations[0] != bound.operation ||
		!brokerScopePinned(g, bound) {
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
	if out.status < 200 || out.status > 599 || out.status/100 == 3 {
		return nil, ErrInvalid
	}
	fields := []capWire{{id: capFieldHTTPStatus, typ: capTypeString, val: []byte(strconv.Itoa(out.status))}}
	switch out.operation {
	case OpHTTPRequest:
	case OpHTTPBroker:
		block := encodeHeaderBlock(out.response.Headers)
		if len(out.response.Body) > maxAgentBody || len(block) > maxAgentHeaderBytes {
			return nil, ErrInvalid
		}
		fields = append(fields,
			capWire{id: capFieldHTTPHeaders, typ: capTypeString, val: []byte(block)},
			capWire{id: capFieldHTTPBody, typ: capTypeBytes, val: out.response.Body},
			capWire{id: capFieldHTTPTruncated, typ: capTypeString, val: []byte(strconv.FormatBool(out.response.Truncated))},
		)
	default:
		return nil, ErrInvalid
	}
	return encodeCap(capMethodInvoke, fields)
}

func decodeNetworkResult(fields map[byte]capWire) (capResponse, error) {
	raw, ok := capString(fields, capFieldHTTPStatus)
	status, good := exactCapInt(raw, 200, 599)
	if !ok || !good || status/100 == 3 {
		return capResponse{}, ErrInvalid
	}
	if len(fields) == 1 {
		return capResponse{method: capMethodInvoke, network: capNetworkResult{operation: OpHTTPRequest, status: int(status)}}, nil
	}
	block, bok := capString(fields, capFieldHTTPHeaders)
	body, dok := fields[capFieldHTTPBody]
	trunc, tok := capString(fields, capFieldHTTPTruncated)
	headers, hok := parseHeaderBlock(block)
	if len(fields) != 4 || !bok || !dok || !tok || !hok || body.typ != capTypeBytes || len(body.val) > maxAgentBody {
		return capResponse{}, ErrInvalid
	}
	truncated, lok := exactCapBool(trunc)
	if !lok {
		return capResponse{}, ErrInvalid
	}
	for name := range headers {
		if !allowedResponseHeader(name) {
			return capResponse{}, ErrInvalid
		}
	}
	return capResponse{method: capMethodInvoke, network: capNetworkResult{
		operation: OpHTTPBroker,
		status:    int(status),
		response:  HTTPResponse{StatusCode: int(status), Headers: headers, Body: body.val, Truncated: truncated},
	}}, nil
}

// exactCapInt accepts one canonical decimal spelling inside a closed range.
func exactCapInt(s string, low, high int64) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != s || n < low || n > high {
		return 0, false
	}
	return n, true
}

func exactCapBool(s string) (bool, bool) {
	switch s {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// encodeBrokerInvoke carries the agent's request shape on the invoke message.
// The handle, not these fields, selects the credential and the destination.
func encodeBrokerInvoke(handle [32]byte, req HTTPRequest) ([]byte, error) {
	block := encodeHeaderBlock(req.Headers)
	if !brokerMethod(req.Method) || len(req.Body) > maxAgentBody || len(block) > maxAgentHeaderBytes || len(req.Query) > maxAgentQuery {
		return nil, ErrInvalid
	}
	fields := []capWire{
		{id: capFieldHandle, typ: capTypeBytes, val: handle[:]},
		{id: capFieldHTTPMethod, typ: capTypeString, val: []byte(req.Method)},
		{id: capFieldHTTPPath, typ: capTypeString, val: []byte(req.Path)},
	}
	if req.Query != "" {
		fields = append(fields, capWire{id: capFieldHTTPQuery, typ: capTypeString, val: []byte(req.Query)})
	}
	if block != "" {
		fields = append(fields, capWire{id: capFieldHTTPHeaders, typ: capTypeString, val: []byte(block)})
	}
	if len(req.Body) > 0 {
		fields = append(fields, capWire{id: capFieldHTTPBody, typ: capTypeBytes, val: req.Body})
	}
	return encodeCap(capMethodInvoke, fields)
}

// brokerInvokeFields reads the request shape off an invoke message. It
// validates only the wire shape; scope and header policy are decided inside
// the session.
func brokerInvokeFields(fields map[byte]capWire) (HTTPRequest, bool) {
	method, mok := capString(fields, capFieldHTTPMethod)
	path, pok := capString(fields, capFieldHTTPPath)
	if !mok || !pok || !brokerMethod(method) {
		return HTTPRequest{}, false
	}
	req := HTTPRequest{Method: method, Path: path}
	want := 3
	if query, ok := capString(fields, capFieldHTTPQuery); ok {
		if query == "" || len(query) > maxAgentQuery {
			return HTTPRequest{}, false
		}
		req.Query = query
		want++
	}
	if block, ok := capString(fields, capFieldHTTPHeaders); ok {
		headers, good := parseHeaderBlock(block)
		if !good || block == "" {
			return HTTPRequest{}, false
		}
		req.Headers = headers
		want++
	}
	if body, ok := fields[capFieldHTTPBody]; ok {
		if body.typ != capTypeBytes || len(body.val) == 0 || len(body.val) > maxAgentBody {
			return HTTPRequest{}, false
		}
		req.Body = body.val
		want++
	}
	return req, len(fields) == want
}

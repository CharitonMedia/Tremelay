package vault

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	brokerTimeout   = 10 * time.Second
	maxBrokerBody   = 64 << 10
	targetInvalid   = 0
	targetMalformed = 1
	targetSSRF      = 2
	targetOrigin    = 3
	targetOK        = 4
	brokerBodyOK    = 0
	brokerBodyBad   = 1
	brokerBodyRedir = 2
)

// HTTPBrokerRequest is the agent-facing broker call.
// It names a credential and an HTTP target. It has no header, body, or secret field.
type HTTPBrokerRequest struct {
	CredentialID string
	Method       string
	Target       string
}

// HTTPBrokerResponse is the broker-defined result of a completed upstream call.
// StatusCode is the upstream status. Upstream body bytes are not a field.
type HTTPBrokerResponse struct {
	StatusCode int
}

var (
	errRedirectRefused = errors.New("redirect refused")
	errDestination     = errors.New("destination refused")
	errBrokerTransport = errors.New("broker transport failed")
)

// brokerAttempt is one authorized broker call. prepare may set broker-owned
// headers. accept, when set, sees a retained HTTP 200 body before the
// completed audit and must not keep that body. A nil accept is the status-only
// path: any non-redirect 200–599 status is returned and the body is wiped.
type brokerAttempt struct {
	credentialID string
	method       string
	target       string
	operation    string
	prepare      func(*http.Request)
	accept       func([]byte) error
}

// brokerHTTP is the trusted broker path for one agent id.
// Credential bytes are copied only after policy, destination, and abuse-hook
// checks succeed, and only into the outbound Authorization header.
func (s *Session) brokerHTTP(agentID string, req HTTPBrokerRequest) (HTTPBrokerResponse, error) {
	if err := s.begin(); err != nil {
		return HTTPBrokerResponse{}, err
	}
	defer s.end()
	return s.brokerHTTPUnlocked(agentID, req)
}

func (s *Session) brokerHTTPUnlocked(agentID string, req HTTPBrokerRequest) (HTTPBrokerResponse, error) {
	status, err := s.brokerExchange(agentID, brokerAttempt{
		credentialID: req.CredentialID,
		method:       req.Method,
		target:       req.Target,
		operation:    OpHTTPRequest,
	})
	if err != nil {
		return HTTPBrokerResponse{}, err
	}
	return HTTPBrokerResponse{StatusCode: status}, nil
}

func (s *Session) brokerExchange(agentID string, call brokerAttempt) (int, error) {
	if err := s.live(); err != nil {
		return 0, err
	}
	// A suspended agent is an ordinary denial before request-shape checks and
	// destination classification, so an unsupported method stays attributed
	// and a later SSRF or origin target cannot raise another alert.
	// Malformed caller fields stay off the event.
	if s.agentExists(agentID) && !s.agentActive(agentID) {
		method := ""
		if brokerMethod(call.method) {
			method = call.method
		}
		return s.failExchange(s.destinationEvent(agentID, call.credentialID, resultDeniedAgent, call.operation), method, ErrDeniedAgent)
	}
	if safeID(call.credentialID) == "" || !brokerMethod(call.method) {
		return s.failExchange(auditEvent{Result: resultDenied}, "", ErrInvalid)
	}
	resource, host, port, class := classifyTarget(call.method, call.target)
	switch class {
	case targetInvalid:
		return s.failExchange(auditEvent{Result: resultDenied}, call.method, ErrInvalid)
	case targetMalformed:
		return s.failExchange(s.policyDenial(agentID, call.credentialID, call.method, call.target, resultDeniedMalformed, call.operation), call.method, ErrDeniedMalformed)
	case targetSSRF:
		return s.failExchange(s.policyDenial(agentID, call.credentialID, call.method, call.target, resultDeniedSSRF, call.operation), call.method, ErrDeniedSSRF)
	case targetOrigin:
		return s.failExchange(s.policyDenial(agentID, call.credentialID, call.method, call.target, resultDeniedOrigin, call.operation), call.method, ErrDeniedOrigin)
	}
	partial, cause := s.judge(agentID, call.credentialID, call.operation, resource)
	if cause != nil {
		if partial.Result == resultDeniedScope {
			if class, id, ok := reclassifyScope(s.grants, agentID, partial.CredID, partial.CredType, call.method, call.target, call.operation); ok {
				partial.Result = class
				partial.GrantID = id
				cause = brokerDenial(class)
			}
		}
		return s.failExchange(partial, call.method, cause)
	}
	if call.method == http.MethodDelete && s.policy.Destructive == DestructiveDeny {
		partial.Result = resultDeniedDestructive
		return s.failExchange(partial, call.method, ErrDeniedDestructive)
	}
	ctx, cancel := context.WithTimeout(context.Background(), brokerTimeout)
	defer cancel()
	ips, err := s.lookupBroker(ctx, host)
	if err != nil || len(ips) == 0 {
		partial.Result = resultDeniedDestination
		return s.failExchange(partial, call.method, ErrDeniedDestination)
	}
	if !publicIPs(ips) {
		partial.Result = resultDeniedSSRF
		return s.failExchange(partial, call.method, ErrDeniedSSRF)
	}
	// ponytail: pin the first validated address. A mixed answer set was refused
	// above. Upgrade path: dial any address in the already-validated set,
	// still without a second lookup.
	pin := normalizeIP(ips[0])
	if !isPublicIP(pin) {
		partial.Result = resultDeniedSSRF
		return s.failExchange(partial, call.method, ErrDeniedSSRF)
	}
	upstream, err := http.NewRequestWithContext(ctx, call.method, call.target, nil)
	if err != nil || upstream.URL == nil || upstream.URL.String() != call.target || upstream.URL.User != nil {
		partial.Result = resultUpstreamError
		return s.failExchange(partial, call.method, ErrBrokerUpstream)
	}
	if call.prepare != nil {
		call.prepare(upstream)
	}
	if upstream.URL == nil || upstream.URL.String() != call.target || upstream.URL.User != nil || upstream.Host != upstream.URL.Host || upstream.Method != call.method || upstream.Body != nil {
		partial.Result = resultUpstreamError
		return s.failExchange(partial, call.method, ErrBrokerUpstream)
	}
	seq := s.header.AuditSeq
	if err := s.abuseHook(AbuseDecision{
		AgentID:      partial.AgentID,
		GrantID:      partial.GrantID,
		CredentialID: partial.CredID,
		Action:       actionClass(call.method),
		Class:        resultAllowed,
	}); err != nil {
		partial.Result = resultDeniedAbuse
		_, err := s.brokerAudit(partial, ErrDeniedAbuse)
		return 0, err
	}
	if s.header.AuditSeq != seq || s.defunct {
		return 0, ErrStale
	}
	secret, ok := s.copySecret(partial.CredID)
	if !ok || !safeHeaderSecret(secret) {
		wipe(secret)
		partial.Result = resultUpstreamError
		return s.failExchange(partial, call.method, ErrBrokerUpstream)
	}
	defer wipe(secret)
	if err := s.brokerCommit(partial, resultAllowed); err != nil {
		return 0, err
	}
	// ponytail: bearer header only. Upgrade path: a typed credential adapter
	// that still cannot accept a caller-supplied authorization header.
	upstream.Header.Del("Authorization")
	upstream.Header.Set("Authorization", "Bearer "+string(secret))
	defer upstream.Header.Del("Authorization")
	if call.accept == nil {
		return s.finishStatus(partial, upstream, pin, port, call.method)
	}
	return s.finishAccepted(partial, upstream, pin, port, call.method, call.accept)
}

func (s *Session) failExchange(ev auditEvent, method string, cause error) (int, error) {
	_, err := s.brokerDeny(ev, method, cause)
	return 0, err
}

func (s *Session) failTransport(partial auditEvent, method string, err error) (int, error) {
	if errors.Is(err, errRedirectRefused) {
		partial.Result = resultDeniedRedirect
		return s.failExchange(partial, method, ErrDeniedRedirect)
	}
	if errors.Is(err, errDestination) {
		partial.Result = resultDeniedSSRF
		return s.failExchange(partial, method, ErrDeniedSSRF)
	}
	partial.Result = resultUpstreamError
	return s.failExchange(partial, method, ErrBrokerUpstream)
}

func (s *Session) finishStatus(partial auditEvent, upstream *http.Request, pin net.IP, port, method string) (int, error) {
	resp, err := s.doBroker(upstream, pin, port)
	if err != nil {
		if resp != nil && resp.Body != nil {
			discardBody(resp.Body)
		}
		return s.failTransport(partial, method, err)
	}
	status, kind := takeStatus(resp)
	return s.finishKind(partial, method, status, kind)
}

func (s *Session) finishAccepted(partial auditEvent, upstream *http.Request, pin net.IP, port, method string, accept func([]byte) error) (int, error) {
	resp, err := s.roundTrip(upstream, pin, port)
	if err != nil {
		if resp != nil && resp.Body != nil {
			discardBody(resp.Body)
		}
		return s.failTransport(partial, method, err)
	}
	var body []byte
	var readErr error
	if resp != nil && resp.Body != nil {
		body, readErr = readCapped(resp.Body, githubIssueMaxBody)
	}
	defer wipe(body)
	code := 0
	if resp != nil {
		code = resp.StatusCode
	}
	status, kind := responseClass(code, readErr)
	if kind == brokerBodyOK && status != http.StatusOK {
		kind = brokerBodyBad
	}
	if kind == brokerBodyOK && accept(body) != nil {
		kind = brokerBodyBad
	}
	return s.finishKind(partial, method, status, kind)
}

func (s *Session) finishKind(partial auditEvent, method string, status, kind int) (int, error) {
	switch kind {
	case brokerBodyRedir:
		partial.Result = resultDeniedRedirect
		return s.failExchange(partial, method, ErrDeniedRedirect)
	case brokerBodyBad:
		partial.Result = resultUpstreamError
		return s.failExchange(partial, method, ErrBrokerUpstream)
	}
	if err := s.brokerCommit(partial, resultCompleted); err != nil {
		return 0, err
	}
	return status, nil
}

func (s *Session) brokerDeny(ev auditEvent, method string, cause error) (HTTPBrokerResponse, error) {
	_ = s.abuseHook(AbuseDecision{
		AgentID:      ev.AgentID,
		GrantID:      ev.GrantID,
		CredentialID: ev.CredID,
		Action:       actionClass(method),
		Class:        ev.Result,
	})
	return s.brokerAudit(ev, cause)
}

func (s *Session) brokerAudit(partial auditEvent, cause error) (HTTPBrokerResponse, error) {
	partial.Action = actionBroker
	if err := s.finish(partial, cause); err != nil {
		return HTTPBrokerResponse{}, err
	}
	return HTTPBrokerResponse{}, cause
}

func (s *Session) brokerCommit(partial auditEvent, result string) error {
	partial.Action = actionBroker
	partial.Result = result
	return s.finish(partial, nil)
}

func (s *Session) destinationEvent(agentID, credentialID, result, operation string) auditEvent {
	ev := auditEvent{Result: result, Operation: operation}
	if safeID(agentID) == "" || !s.agentExists(agentID) {
		return ev
	}
	ev.AgentID = agentID
	if id, typ, ok := s.lookupCred(credentialID); ok {
		ev.CredID = id
		ev.CredType = typ
	}
	return ev
}

// policyDenial records a destination-class refusal. The raw target is used
// only to find an exact grant id. It is not an audit field.
func (s *Session) policyDenial(agentID, credentialID, method, target, result, operation string) auditEvent {
	ev := s.destinationEvent(agentID, credentialID, result, operation)
	resource := method + " " + target
	if ev.AgentID == "" || ev.CredID == "" || validateResource(resource) != nil {
		return ev
	}
	var id string
	for i := range s.grants {
		g := s.grants[i]
		if g.AgentID == ev.AgentID && g.Resource == resource && grantAllowsOp(g, operation) && grantMatchesCred(g, ev.CredID, ev.CredType) {
			id = preferID(id, g.ID)
		}
	}
	ev.GrantID = id
	return ev
}

func (s *Session) copySecret(id string) ([]byte, bool) {
	for i := range s.creds {
		if s.creds[i].ID == id {
			return append([]byte(nil), s.creds[i].Secret...), true
		}
	}
	return nil, false
}

func (s *Session) lookupBroker(ctx context.Context, host string) ([]net.IP, error) {
	if s.resolve != nil {
		return s.resolve(ctx, host)
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func (s *Session) doBroker(req *http.Request, ip net.IP, port string) (*http.Response, error) {
	resp, err := s.roundTrip(req, ip, port)
	if err != nil || s.httpDo != nil {
		return resp, err
	}
	if resp == nil || resp.Body == nil {
		return resp, nil
	}
	buf, readErr := readLimited(resp.Body)
	_ = resp.Body.Close()
	wipe(buf)
	if readErr != nil {
		return nil, errBrokerTransport
	}
	resp.Body = http.NoBody
	return resp, nil
}

func (s *Session) roundTrip(req *http.Request, ip net.IP, port string) (*http.Response, error) {
	var resp *http.Response
	var err error
	s.duringCallback(func() {
		resp, err = s.roundTripInner(req, ip, port)
	})
	return resp, err
}

func (s *Session) roundTripInner(req *http.Request, ip net.IP, port string) (*http.Response, error) {
	if s.httpDo != nil {
		return s.httpDo(req)
	}
	dial := s.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: brokerTimeout}).DialContext
	}
	transport, err := pinnedTransportDial(ip, port, dial)
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()
	resp, err := brokerClient(transport).Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			discardBody(resp.Body)
			resp.Body = nil
		}
		if errors.Is(err, errRedirectRefused) || errors.Is(err, errDestination) {
			return nil, err
		}
		return nil, errBrokerTransport
	}
	return resp, nil
}

// refuseRedirect stops every redirect. A 3xx is not followed, including chains.
// The next hop does not inherit the credential.
func refuseRedirect(*http.Request, []*http.Request) error {
	return errRedirectRefused
}

// refuseProxy ignores HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY.
func refuseProxy(*http.Request) (*url.URL, error) {
	return nil, nil
}

func brokerClient(transport *http.Transport) *http.Client {
	return &http.Client{
		Timeout:       brokerTimeout,
		CheckRedirect: refuseRedirect,
		Transport:     transport,
	}
}

// pinnedTransportDial dials one already-checked address.
// The address argument from the HTTP stack is ignored, so a proxy or a
// second resolution cannot move the credential-bearing connection.
func pinnedTransportDial(ip net.IP, port string, dial func(context.Context, string, string) (net.Conn, error)) (*http.Transport, error) {
	target, err := pinTarget(ip, port)
	if err != nil || dial == nil {
		return nil, errDestination
	}
	return &http.Transport{
		Proxy: refuseProxy,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errDestination
			}
			pinned, err := pinTarget(ip, port)
			if err != nil || pinned != target {
				return nil, errDestination
			}
			return dial(ctx, network, target)
		},
		TLSHandshakeTimeout:   brokerTimeout,
		ResponseHeaderTimeout: brokerTimeout,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
	}, nil
}

func pinTarget(ip net.IP, port string) (string, error) {
	ip = normalizeIP(ip)
	if !isPublicIP(ip) || !dialPort(port) {
		return "", errDestination
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func publicIPs(ips []net.IP) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return false
		}
	}
	return true
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	// To4 converts IPv4 and IPv4-mapped IPv6 to a 4-byte address.
	if v4 := ip.To4(); v4 != nil {
		return append(net.IP(nil), v4...)
	}
	return append(net.IP(nil), ip...)
}

// takeStatus returns the upstream status and wipes the body.
// Upstream bytes are not a broker result. Redirects stay refused.
func takeStatus(resp *http.Response) (int, int) {
	if resp == nil {
		return 0, brokerBodyBad
	}
	var readErr error
	if resp.Body != nil {
		buf, err := readLimited(resp.Body)
		_ = resp.Body.Close()
		wipe(buf)
		readErr = err
	}
	return responseClass(resp.StatusCode, readErr)
}

func responseClass(code int, readErr error) (int, int) {
	if code >= 300 && code < 400 {
		return 0, brokerBodyRedir
	}
	if readErr != nil || code < 200 || code > 599 {
		return 0, brokerBodyBad
	}
	return code, brokerBodyOK
}

func readCapped(body io.ReadCloser, n int) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	buf, err := io.ReadAll(io.LimitReader(body, int64(n)+1))
	_ = body.Close()
	if err != nil || len(buf) > n {
		wipe(buf)
		return nil, errBrokerTransport
	}
	return buf, nil
}

func readLimited(body io.Reader) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(body, maxBrokerBody+1))
	if err != nil {
		wipe(buf)
		return nil, err
	}
	return buf, nil
}

func discardBody(body io.ReadCloser) {
	buf, _ := readLimited(body)
	_ = body.Close()
	wipe(buf)
}

func safeHeaderSecret(secret []byte) bool {
	if len(secret) == 0 || len(secret) > MaxSecret {
		return false
	}
	for _, b := range secret {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func brokerMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func classifyTarget(method, target string) (resource, host, port string, class int) {
	if !brokerMethod(method) || target == "" || len(method)+1+len(target) > maxLabel || hasControl(target) || strings.Contains(target, "*") || !utf8.ValidString(target) {
		return "", "", "", targetInvalid
	}
	// ponytail: reject every ambiguous or encoded form instead of rewriting it.
	// Upgrade path: a documented encoding allowlist if a caller must send one.
	u, err := url.Parse(target)
	hostName := ""
	if err == nil && u != nil {
		hostName = u.Hostname()
	}
	if hostName != "" && specialDestination(hostName) {
		return "", "", "", targetSSRF
	}
	ambiguous := strings.ContainsAny(target, " \\@#%")
	if err != nil || u == nil || u.Scheme == "" || u.Host == "" || ambiguous {
		if ambiguous {
			return "", "", "", targetMalformed
		}
		return "", "", "", targetInvalid
	}
	if ip := net.ParseIP(hostName); ip != nil && isPublicIP(ip) {
		return "", "", "", targetOrigin
	}
	if u.Scheme != "https" {
		return "", "", "", targetOrigin
	}
	host, port, built, ok := canonicalForm(u)
	if !ok || built != target {
		return "", "", "", targetMalformed
	}
	resource = method + " " + built
	if validateResource(resource) != nil {
		return "", "", "", targetInvalid
	}
	return resource, host, port, targetOK
}

func canonicalForm(u *url.URL) (host, port, built string, ok bool) {
	if u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.ForceQuery {
		return "", "", "", false
	}
	host = u.Hostname()
	port = u.Port()
	if host == "" || strings.Contains(host, ":") || net.ParseIP(host) != nil || !dnsNameOK(host) {
		return "", "", "", false
	}
	if port != "" && !portOK(port) {
		return "", "", "", false
	}
	if u.RawPath != "" && u.RawPath != u.Path {
		return "", "", "", false
	}
	if !pathOK(u.Path) {
		return "", "", "", false
	}
	if strings.ContainsAny(u.RawQuery, " #@%\\") {
		return "", "", "", false
	}
	var b strings.Builder
	b.WriteString("https://")
	b.WriteString(host)
	if port != "" {
		b.WriteByte(':')
		b.WriteString(port)
	}
	b.WriteString(u.Path)
	if u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}
	if port == "" {
		port = "443"
	}
	return host, port, b.String(), true
}

func dnsNameOK(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || looksLikeObfuscatedIP(host) {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	letter := false
	for _, label := range labels {
		if !labelOK(label) {
			return false
		}
		for i := 0; i < len(label); i++ {
			if label[i] >= 'a' && label[i] <= 'z' {
				letter = true
			}
		}
	}
	if !letter {
		return false
	}
	return !specialUseName(host)
}

func specialDestination(host string) bool {
	folded := strings.ToLower(strings.TrimSuffix(host, "."))
	if folded == "" {
		return false
	}
	if ip := net.ParseIP(folded); ip != nil {
		return !isPublicIP(ip)
	}
	if looksLikeObfuscatedIP(folded) {
		return true
	}
	return specialUseName(folded)
}

func specialUseName(host string) bool {
	switch {
	case host == "localhost" || strings.HasSuffix(host, ".localhost"):
		return true
	case strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".localdomain") || strings.HasSuffix(host, ".arpa") || strings.HasSuffix(host, ".onion"):
		return true
	case host == "test" || strings.HasSuffix(host, ".test") || host == "invalid" || strings.HasSuffix(host, ".invalid"):
		return true
	default:
		return false
	}
}

func labelOK(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func looksLikeObfuscatedIP(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	labels := strings.Split(host, ".")
	if len(labels) == 1 {
		return decimalLabel(labels[0]) || hexLabel(labels[0])
	}
	if len(labels) < 2 || len(labels) > 4 {
		return false
	}
	for _, label := range labels {
		if !decimalLabel(label) && !hexLabel(label) {
			return false
		}
	}
	return true
}

func decimalLabel(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func hexLabel(s string) bool {
	if !strings.HasPrefix(s, "0x") || len(s) == 2 {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func pathOK(path string) bool {
	if path == "" || path[0] != '/' || strings.Contains(path, "//") || strings.Contains(path, "\\") {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.' || c == '_' || c == '-' || c == '~':
			default:
				return false
			}
		}
	}
	return true
}

func portOK(port string) bool {
	if port == "" || len(port) > 5 || port[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535 && n != 443
}

func dialPort(port string) bool {
	return port == "443" || portOK(port)
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

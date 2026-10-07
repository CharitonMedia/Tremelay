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

// brokerHTTP is the trusted broker path for one agent id.
// Credential bytes are copied only after policy, destination, and abuse-hook
// checks succeed, and only into the outbound Authorization header.
func (s *Session) brokerHTTP(agentID string, req HTTPBrokerRequest) (HTTPBrokerResponse, error) {
	if err := s.live(); err != nil {
		return HTTPBrokerResponse{}, err
	}
	if safeID(req.CredentialID) == "" || !brokerMethod(req.Method) {
		return s.brokerDeny(auditEvent{Result: resultDenied}, "", ErrInvalid)
	}
	resource, host, port, class := classifyTarget(req.Method, req.Target)
	switch class {
	case targetInvalid:
		return s.brokerDeny(auditEvent{Result: resultDenied}, req.Method, ErrInvalid)
	case targetMalformed:
		return s.brokerDeny(s.policyDenial(agentID, req.CredentialID, req.Method, req.Target, resultDeniedMalformed), req.Method, ErrDeniedMalformed)
	case targetSSRF:
		return s.brokerDeny(s.policyDenial(agentID, req.CredentialID, req.Method, req.Target, resultDeniedSSRF), req.Method, ErrDeniedSSRF)
	case targetOrigin:
		return s.brokerDeny(s.policyDenial(agentID, req.CredentialID, req.Method, req.Target, resultDeniedOrigin), req.Method, ErrDeniedOrigin)
	}
	partial, cause := s.judge(agentID, req.CredentialID, OpHTTPRequest, resource)
	if cause != nil {
		if partial.Result == resultDeniedScope {
			if class, id, ok := reclassifyScope(s.grants, agentID, partial.CredID, partial.CredType, req.Method, req.Target); ok {
				partial.Result = class
				partial.GrantID = id
				cause = brokerDenial(class)
			}
		}
		return s.brokerDeny(partial, req.Method, cause)
	}
	ctx, cancel := context.WithTimeout(context.Background(), brokerTimeout)
	defer cancel()
	ips, err := s.lookupBroker(ctx, host)
	if err != nil || len(ips) == 0 {
		partial.Result = resultDeniedDestination
		return s.brokerDeny(partial, req.Method, ErrDeniedDestination)
	}
	if !publicIPs(ips) {
		partial.Result = resultDeniedSSRF
		return s.brokerDeny(partial, req.Method, ErrDeniedSSRF)
	}
	// ponytail: pin the first validated address. A mixed answer set was refused
	// above. Upgrade path: dial any address in the already-validated set,
	// still without a second lookup.
	pin := normalizeIP(ips[0])
	if !isPublicIP(pin) {
		partial.Result = resultDeniedSSRF
		return s.brokerDeny(partial, req.Method, ErrDeniedSSRF)
	}
	upstream, err := http.NewRequestWithContext(ctx, req.Method, req.Target, nil)
	if err != nil || upstream.URL == nil || upstream.URL.String() != req.Target || upstream.URL.User != nil {
		partial.Result = resultUpstreamError
		return s.brokerDeny(partial, req.Method, ErrBrokerUpstream)
	}
	if err := s.abuseHook(AbuseDecision{
		AgentID:      partial.AgentID,
		GrantID:      partial.GrantID,
		CredentialID: partial.CredID,
		Action:       actionClass(req.Method),
		Class:        resultAllowed,
	}); err != nil {
		partial.Result = resultDeniedAbuse
		return s.brokerAudit(partial, ErrDeniedAbuse)
	}
	secret, ok := s.copySecret(partial.CredID)
	if !ok || !safeHeaderSecret(secret) {
		wipe(secret)
		partial.Result = resultUpstreamError
		return s.brokerDeny(partial, req.Method, ErrBrokerUpstream)
	}
	defer wipe(secret)
	if err := s.brokerCommit(partial, resultAllowed); err != nil {
		return HTTPBrokerResponse{}, err
	}
	// ponytail: bearer header only. Upgrade path: a typed credential adapter.
	upstream.Header.Set("Authorization", "Bearer "+string(secret))
	defer upstream.Header.Del("Authorization")
	resp, err := s.doBroker(upstream, pin, port)
	if err != nil {
		if resp != nil && resp.Body != nil {
			discardBody(resp.Body)
		}
		if errors.Is(err, errRedirectRefused) {
			partial.Result = resultDeniedRedirect
			return s.brokerDeny(partial, req.Method, ErrDeniedRedirect)
		}
		if errors.Is(err, errDestination) {
			partial.Result = resultDeniedSSRF
			return s.brokerDeny(partial, req.Method, ErrDeniedSSRF)
		}
		partial.Result = resultUpstreamError
		return s.brokerDeny(partial, req.Method, ErrBrokerUpstream)
	}
	status, kind := takeStatus(resp)
	switch kind {
	case brokerBodyRedir:
		partial.Result = resultDeniedRedirect
		return s.brokerDeny(partial, req.Method, ErrDeniedRedirect)
	case brokerBodyBad:
		partial.Result = resultUpstreamError
		return s.brokerDeny(partial, req.Method, ErrBrokerUpstream)
	}
	if err := s.brokerCommit(partial, resultCompleted); err != nil {
		return HTTPBrokerResponse{}, err
	}
	return HTTPBrokerResponse{StatusCode: status}, nil
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

func (s *Session) destinationEvent(agentID, credentialID, result string) auditEvent {
	ev := auditEvent{Result: result, Operation: OpHTTPRequest}
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
func (s *Session) policyDenial(agentID, credentialID, method, target, result string) auditEvent {
	ev := s.destinationEvent(agentID, credentialID, result)
	resource := method + " " + target
	if ev.AgentID == "" || ev.CredID == "" || validateResource(resource) != nil {
		return ev
	}
	var id string
	for i := range s.grants {
		g := s.grants[i]
		if g.AgentID == ev.AgentID && g.Resource == resource && grantAllowsOp(g, OpHTTPRequest) && grantMatchesCred(g, ev.CredID, ev.CredType) {
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
	buf, readErr := readLimited(resp.Body)
	_ = resp.Body.Close()
	wipe(buf)
	if readErr != nil {
		return nil, errBrokerTransport
	}
	resp.Body = http.NoBody
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
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return 0, brokerBodyRedir
	}
	if readErr != nil || resp.StatusCode < 200 || resp.StatusCode > 599 {
		return 0, brokerBodyBad
	}
	return resp.StatusCode, brokerBodyOK
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

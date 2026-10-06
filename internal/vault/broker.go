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
	targetBlocked   = 1
	targetOK        = 2
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
// Credential bytes are copied only after authorization and destination checks
// succeed, and only into the outbound Authorization header.
func (s *Session) brokerHTTP(agentID string, req HTTPBrokerRequest) (HTTPBrokerResponse, error) {
	if err := s.live(); err != nil {
		return HTTPBrokerResponse{}, err
	}
	if safeID(req.CredentialID) == "" || !brokerMethod(req.Method) {
		return s.brokerAudit(auditEvent{Result: resultDenied}, ErrInvalid)
	}
	resource, host, port, class := classifyTarget(req.Method, req.Target)
	switch class {
	case targetInvalid:
		return s.brokerAudit(auditEvent{Result: resultDenied}, ErrInvalid)
	case targetBlocked:
		return s.brokerAudit(s.destinationEvent(agentID, req.CredentialID), ErrDeniedDestination)
	}
	partial, cause := s.judge(agentID, req.CredentialID, OpHTTPRequest, resource)
	if cause != nil {
		return s.brokerAudit(partial, cause)
	}
	ctx, cancel := context.WithTimeout(context.Background(), brokerTimeout)
	defer cancel()
	ips, err := s.lookupBroker(ctx, host)
	if err != nil || !publicIPs(ips) {
		partial.Result = resultDeniedDestination
		return s.brokerAudit(partial, ErrDeniedDestination)
	}
	pin := normalizeIP(ips[0])
	upstream, err := http.NewRequestWithContext(ctx, req.Method, req.Target, nil)
	if err != nil || upstream.URL == nil || upstream.URL.String() != req.Target || upstream.URL.User != nil {
		partial.Result = resultUpstreamError
		return s.brokerAudit(partial, ErrBrokerUpstream)
	}
	secret, ok := s.copySecret(partial.CredID)
	if !ok || !safeHeaderSecret(secret) {
		wipe(secret)
		partial.Result = resultUpstreamError
		return s.brokerAudit(partial, ErrBrokerUpstream)
	}
	defer wipe(secret)
	if err := s.brokerCommit(partial, resultAllowed); err != nil {
		return HTTPBrokerResponse{}, err
	}
	// ponytail: bearer header only. Upgrade path: a typed credential adapter after M3.
	upstream.Header.Set("Authorization", "Bearer "+string(secret))
	defer upstream.Header.Del("Authorization")
	resp, err := s.doBroker(upstream, pin, port)
	if err != nil {
		if resp != nil && resp.Body != nil {
			discardBody(resp.Body)
		}
		if errors.Is(err, errRedirectRefused) || errors.Is(err, errDestination) {
			partial.Result = resultDeniedDestination
			return s.brokerAudit(partial, ErrDeniedDestination)
		}
		partial.Result = resultUpstreamError
		return s.brokerAudit(partial, ErrBrokerUpstream)
	}
	status, kind := takeStatus(resp)
	switch kind {
	case brokerBodyRedir:
		partial.Result = resultDeniedDestination
		return s.brokerAudit(partial, ErrDeniedDestination)
	case brokerBodyBad:
		partial.Result = resultUpstreamError
		return s.brokerAudit(partial, ErrBrokerUpstream)
	}
	if err := s.brokerCommit(partial, resultCompleted); err != nil {
		return HTTPBrokerResponse{}, err
	}
	return HTTPBrokerResponse{StatusCode: status}, nil
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

func (s *Session) destinationEvent(agentID, credentialID string) auditEvent {
	ev := auditEvent{Result: resultDeniedDestination, Operation: OpHTTPRequest}
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
	transport, err := pinnedTransport(ip, port)
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:       brokerTimeout,
		CheckRedirect: refuseRedirect,
		Transport:     transport,
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			discardBody(resp.Body)
			resp.Body = nil
		}
		return nil, err
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
func refuseRedirect(*http.Request, []*http.Request) error {
	return errRedirectRefused
}

// pinnedTransport dials one already-checked address.
// ponytail: one resolver answer, first address only. Upgrade path: M4 rebinding policy.
func pinnedTransport(ip net.IP, port string) (*http.Transport, error) {
	target, err := pinTarget(ip, port)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: brokerTimeout}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errDestination
			}
			return dialer.DialContext(ctx, network, target)
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

func isPublicIP(ip net.IP) bool {
	ip = normalizeIP(ip)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0:
			return false
		case v4[0] == 100 && v4[1]&0xc0 == 64:
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0:
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2:
			return false
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100:
			return false
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
			return false
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19):
			return false
		case v4[0] == 192 && v4[1] == 88 && v4[2] == 99 && v4[3] == 2:
			// 192.88.99.2 is the 6a44 relay anycast and is not globally reachable.
			return false
		case v4[0] >= 240:
			return false
		}
		return true
	}
	return ipv6Public(ip)
}

// ipv6Public reports whether ip is an ordinary public IPv6 destination.
// Global unicast is 2000::/3. Everything else is refused, which covers
// deprecated site-local fec0::/10, NAT64 64:ff9b::/96 and 64:ff9b:1::/48,
// discard-only 100::/64, and unique-local space that IsPrivate missed.
// ponytail: the exception list is the IANA special-purpose ranges inside
// 2000::/3 that are not ordinary public servers. Upgrade path: refresh it
// from the IANA IPv6 Special-Purpose Address Registry.
func ipv6Public(ip net.IP) bool {
	if len(ip) != net.IPv6len || ip[0]&0xe0 != 0x20 {
		return false
	}
	switch {
	case ip[0] == 0x20 && ip[1] == 0x01 && ip[2]&0xfe == 0x00:
		// 2001::/23 IETF Protocol Assignments, including benchmarking and TEREDO.
		return false
	case ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8:
		// 2001:db8::/32 documentation.
		return false
	case ip[0] == 0x20 && ip[1] == 0x02:
		// 2002::/16 6to4.
		return false
	case ip[0] == 0x26 && ip[1] == 0x20 && ip[2] == 0x00 && ip[3] == 0x4f && ip[4] == 0x80 && ip[5] == 0x00:
		// 2620:4f:8000::/48 AS112 direct delegation.
		return false
	case ip[0] == 0x3f && ip[1] == 0xff && ip[2]&0xf0 == 0x00:
		// 3fff::/20 documentation. The next four bits are 0, so 3fff:1000:: is outside it.
		return false
	default:
		return true
	}
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
	// Upgrade path: a canonicalizer with an explicit encoding allowlist in M4.
	if strings.ContainsAny(target, " \\@#%") {
		return "", "", "", targetBlocked
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", "", targetInvalid
	}
	host, port, built, ok := canonicalForm(u)
	if !ok || built != target {
		return "", "", "", targetBlocked
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
	switch {
	case host == "localhost" || strings.HasSuffix(host, ".localhost"):
		return false
	case strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".localdomain") || strings.HasSuffix(host, ".arpa") || strings.HasSuffix(host, ".onion"):
		return false
	default:
		return true
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

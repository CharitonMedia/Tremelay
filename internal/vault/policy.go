package vault

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
)

const (
	actionRead  = "read"
	actionWrite = "write"
)

// AbuseDecision is the secret-free input to the broker abuse-control hook.
// It identifies the principal, grant, and credential by id and carries the
// action class and policy decision. It has no URL, header, body, or secret.
type AbuseDecision struct {
	AgentID      string
	GrantID      string
	CredentialID string
	Action       string
	Class        string
}

// SetAbuseGuard installs the process-local hook that can veto an otherwise
// allowed broker call. A nil guard allows. The hook runs after policy and
// destination checks and before the credential is copied. It cannot turn a
// denial into an allow. Agent principals have no method that sets it.
func (s *Session) SetAbuseGuard(fn func(AbuseDecision) error) error {
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	s.abuseGuard = fn
	return nil
}

func (s *Session) abuseHook(d AbuseDecision) error {
	if s == nil {
		return nil
	}
	// Snapshot under the lock. SetAbuseGuard may replace or clear the hook
	// while the callback runs.
	guard := s.abuseGuard
	if guard == nil {
		return nil
	}
	var err error
	s.duringCallback(func() {
		err = guard(d)
	})
	return err
}

// transmissionAuthorized reports whether a broker result is written only
// after the broker has decided the credential may be sent.
func transmissionAuthorized(result string) bool {
	switch result {
	case resultAllowed, resultCompleted, resultUpstreamError:
		return true
	default:
		return false
	}
}

type httpPolicy struct {
	method string
	host   string
	port   string
	path   string
	query  string
	action string
}

func actionClass(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return actionRead
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return actionWrite
	default:
		return ""
	}
}

func requestPolicy(method, target string) (httpPolicy, bool) {
	_, host, port, class := classifyTarget(method, target)
	if class != targetOK {
		return httpPolicy{}, false
	}
	u, err := url.Parse(target)
	if err != nil || u.Path == "" {
		return httpPolicy{}, false
	}
	return httpPolicy{
		method: method,
		host:   host,
		port:   port,
		path:   u.Path,
		query:  u.RawQuery,
		action: actionClass(method),
	}, true
}

func policyFromResource(resource string) (httpPolicy, bool) {
	method, target, ok := splitPolicyResource(resource)
	if !ok {
		return httpPolicy{}, false
	}
	return requestPolicy(method, target)
}

func splitPolicyResource(resource string) (method, target string, ok bool) {
	for i := 0; i < len(resource); i++ {
		if resource[i] != ' ' {
			continue
		}
		method = resource[:i]
		target = resource[i+1:]
		return method, target, method != "" && target != "" && !containsByte(target, ' ')
	}
	return "", "", false
}

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

// reclassifyScope turns an M2 scope miss into the closest explicit HTTP
// policy mismatch. Grants that are not canonical HTTP policies are ignored.
// The winner is deterministic: higher specificity, then the lowest grant id.
func reclassifyScope(grants []grantRecord, agentID, credID, credType, method, target, operation string) (result, grantID string, ok bool) {
	req, good := requestPolicy(method, target)
	if !good {
		return "", "", false
	}
	found := false
	var bestScore int
	var bestID string
	var bestClass string
	for i := range grants {
		g := grants[i]
		if g.AgentID != agentID || !grantMatchesCred(g, credID, credType) || !grantAllowsOp(g, operation) {
			continue
		}
		pol, parsed := policyFromResource(g.Resource)
		if !parsed {
			continue
		}
		score, class := policyDistance(pol, req)
		if class == resultAllowed {
			continue
		}
		if !found || score > bestScore || (score == bestScore && g.ID < bestID) {
			found = true
			bestScore = score
			bestID = g.ID
			bestClass = class
		}
	}
	if !found {
		return "", "", false
	}
	return bestClass, bestID, true
}

func policyDistance(grant, req httpPolicy) (score int, class string) {
	origin := grant.host == req.host && grant.port == req.port
	path := grant.path == req.path && grant.query == req.query
	action := grant.action != "" && grant.action == req.action
	method := grant.method == req.method
	if origin {
		score += 8
	}
	if path {
		score += 4
	}
	if action {
		score += 2
	}
	if method {
		score += 1
	}
	switch {
	case !origin:
		return score, resultDeniedOrigin
	case !path:
		return score, resultDeniedPath
	case !action:
		return score, resultDeniedAction
	case !method:
		return score, resultDeniedMethod
	default:
		return score, resultAllowed
	}
}

func brokerDenial(result string) error {
	switch result {
	case resultDeniedOrigin:
		return ErrDeniedOrigin
	case resultDeniedSSRF:
		return ErrDeniedSSRF
	case resultDeniedRedirect:
		return ErrDeniedRedirect
	case resultDeniedMethod:
		return ErrDeniedMethod
	case resultDeniedPath:
		return ErrDeniedPath
	case resultDeniedAction:
		return ErrDeniedAction
	case resultDeniedMalformed:
		return ErrDeniedMalformed
	case resultDeniedAbuse:
		return ErrDeniedAbuse
	case resultDeniedDestructive:
		return ErrDeniedDestructive
	case resultDeniedDestination:
		return ErrDeniedDestination
	default:
		return denialError(result)
	}
}

// ipv4Special and ipv6Special are the special-purpose ranges that must not
// receive a brokered credential. Stdlib unicast checks still run first.
// ponytail: the list is the IANA special-purpose set used for credential
// egress, including the deprecated 6to4 relay 192.88.99.0/24. Upgrade path:
// refresh it from the IANA IPv4 and IPv6 special-purpose registries.
var ipv4Special = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var (
	ipv6Global  = netip.MustParsePrefix("2000::/3")
	ipv6Special = []netip.Prefix{
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("::ffff:0:0/96"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2620:4f:8000::/48"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fec0::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

func isPublicIP(ip net.IP) bool {
	ip = normalizeIP(ip)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return !prefixContains(ipv4Special, addr)
	}
	if !ipv6Global.Contains(addr) {
		return false
	}
	return !prefixContains(ipv6Special, addr)
}

func prefixContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

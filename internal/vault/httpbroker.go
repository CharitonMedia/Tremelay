package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// InjectBearer sends the secret as `Authorization: Bearer <secret>`.
	InjectBearer = "bearer"
	// InjectHeader sends the secret as the value of the grant's named header.
	InjectHeader = "header"
	// InjectBasic sends the grant's user and the secret as RFC 7617 basic auth.
	InjectBasic = "basic"
	// InjectQuery sends the URL-encoded secret as the grant's named query parameter.
	InjectQuery = "query"

	// maxAgentBody caps both the agent-supplied request body and the returned
	// response body. Each fits inside one MaxAgentCapMessage capability frame
	// together with its metadata.
	maxAgentBody = 32 << 10
	// maxAgentHeaders, maxAgentHeaderBytes and maxAgentQuery bound the
	// caller-controlled parts of a brokered request.
	maxAgentHeaders     = 16
	maxAgentHeaderName  = 64
	maxAgentHeaderValue = 1 << 10
	maxAgentHeaderBytes = 4 << 10
	maxAgentQuery       = 1 << 10
	// maxInjectName bounds a grant's header or query parameter name.
	maxInjectName = 64
	// maxBasicUser bounds a basic-auth user stored on a grant.
	maxBasicUser = 256
)

// injectionStyles is the closed set of credential placements.
var injectionStyles = []string{InjectBearer, InjectHeader, InjectBasic, InjectQuery}

// InjectionStyles returns a copy of the credential-injection allowlist.
func InjectionStyles() []string {
	return append([]string(nil), injectionStyles...)
}

// refusedAgentHeaders are names an agent may never set. They choose the
// credential, the destination, or the framing of the brokered request.
//
// Accept-Encoding, Range and If-Range choose the *form* of the response
// bytes, which is the same thing: an encoding the transport did not negotiate
// is never decoded, and a byte range is shorter than any credential form, so
// either one hands redaction bytes it cannot match. Expect changes the
// framing handshake.
var refusedAgentHeaders = []string{
	"authorization", "proxy-authorization", "cookie", "host",
	"content-length", "transfer-encoding", "expect",
	"accept-encoding", "range", "if-range",
	"x-http-method-override", "x-http-method", "x-method-override",
	"x-original-url", "x-original-uri", "x-rewrite-url", "forwarded",
	"x-forwarded-host", "x-forwarded-prefix", "x-forwarded-proto",
	"x-forwarded-port", "x-forwarded-ssl", "x-forwarded-for",
	"connection", "keep-alive", "proxy-connection", "te", "trailer", "trailers", "upgrade",
}

// brokerResponseHeaders is the closed set of upstream response headers an
// agent may see. Set-Cookie, authentication and transport headers are absent
// by construction, not by subtraction.
// Rate-limit headers are named one by one: an open X-RateLimit-* prefix let
// an upstream put the credential in a header name, which is never scanned.
var brokerResponseHeaders = []string{
	"Content-Type", "Content-Length", "ETag", "Last-Modified", "Link", "Retry-After",
	"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
	"X-RateLimit-Used", "X-RateLimit-Resource",
}

// HTTPRequest is the agent-facing brokered request. It names the credential
// and the granted origin, and supplies the method, the path under the grant's
// prefix, the query, non-auth headers, and a size-capped body. It has no
// credential, authorization header, or redirect field.
type HTTPRequest struct {
	CredentialID string
	Origin       string
	Method       string
	Path         string
	Query        string
	Headers      map[string]string
	Body         []byte
}

// HTTPResponse is the agent-visible projection of one brokered response.
// Headers carry only the allowlisted names. Body is capped at maxAgentBody and
// has every occurrence of the credential replaced. Truncated reports that the
// upstream body was longer than the cap.
type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	Truncated  bool
}

// grantInjection is where the broker places the secret for one grant.
// The zero value is the legacy bearer header.
type grantInjection struct {
	style string
	name  string
}

func grantInjectionOf(g grantRecord) grantInjection {
	return grantInjection{style: g.HTTPInject, name: g.HTTPInjectName}
}

func soleBroker(ops []string) bool {
	return len(ops) == 1 && ops[0] == OpHTTPBroker
}

// brokerScope splits an http_broker grant resource into its canonical origin
// host, port and path prefix. The resource text is the whole destination
// policy: `https://host[:port]/prefix`, in the ADR 0006 canonical form.
func brokerScope(resource string) (host, port, prefix string, ok bool) {
	if resource == "" || len(resource) > maxLabel || hasControl(resource) || strings.ContainsAny(resource, " \\@#%*") {
		return "", "", "", false
	}
	u, err := url.Parse(resource)
	if err != nil || u == nil {
		return "", "", "", false
	}
	host, port, built, good := canonicalForm(u)
	if !good || built != resource || u.RawQuery != "" || specialDestination(host) || !prefixOK(u.Path) {
		return "", "", "", false
	}
	return host, port, u.Path, true
}

// prefixOK keeps one spelling per prefix. canonicalForm already refused dot
// segments, `//`, backslashes and percent-encoding.
func prefixOK(path string) bool {
	return pathOK(path) && (path == "/" || !strings.HasSuffix(path, "/"))
}

// brokerOriginOK reports whether origin is the canonical scheme, host and
// optional port of a granted destination, with no path, query or fragment.
func brokerOriginOK(origin string) bool {
	_, _, prefix, ok := brokerScope(origin + "/")
	return ok && prefix == "/"
}

// brokerGrantScope returns the grant's origin text and path prefix.
func brokerGrantScope(resource string) (origin, prefix string, ok bool) {
	_, _, prefix, ok = brokerScope(resource)
	if !ok {
		return "", "", false
	}
	return resource[:len(resource)-len(prefix)], prefix, true
}

// pathUnderPrefix matches on segment boundaries. `/repos/o/r` covers
// `/repos/o/r` and `/repos/o/r/issues`, and does not cover `/repos/o/rx`.
func pathUnderPrefix(prefix, path string) bool {
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	return rest == "" || rest[0] == '/'
}

// canonicalMethods sorts and deduplicates a grant's allowed method set.
func canonicalMethods(methods []string) ([]string, bool) {
	if len(methods) == 0 || len(methods) > 6 {
		return nil, false
	}
	out := append([]string(nil), methods...)
	slices.Sort(out)
	prev := ""
	for _, m := range out {
		if !brokerMethod(m) || m == prev {
			return nil, false
		}
		prev = m
	}
	return out, true
}

func methodAllowed(methods []string, method string) bool {
	return slices.Contains(methods, method)
}

// injectionOK validates a grant's credential placement. A named header must
// not be one of the names an agent is refused, so the two rules cannot
// disagree about who owns that header.
func injectionOK(style, name string) bool {
	switch style {
	case InjectBearer:
		return name == ""
	case InjectHeader:
		return headerNameOK(name) && !refusedHeaderName(name)
	case InjectBasic:
		return basicUserOK(name)
	case InjectQuery:
		return queryNameOK(name)
	default:
		return false
	}
}

// headerNameOK is the strict subset of RFC 7230 token every real API uses.
func headerNameOK(name string) bool {
	if name == "" || len(name) > maxAgentHeaderName {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !letter && !(c >= '0' && c <= '9') && c != '-' {
			return false
		}
	}
	return (name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')
}

func headerValueOK(value string) bool {
	if value == "" || len(value) > maxAgentHeaderValue {
		return false
	}
	if value[0] == ' ' || value[0] == '\t' || value[len(value)-1] == ' ' || value[len(value)-1] == '\t' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

// basicUserOK keeps the stored user out of the `user:pass` separator and out
// of header-splitting range.
func basicUserOK(user string) bool {
	if user == "" || len(user) > maxBasicUser {
		return false
	}
	for i := 0; i < len(user); i++ {
		if c := user[i]; c < 0x21 || c > 0x7e || c == ':' {
			return false
		}
	}
	return true
}

// queryNameOK restricts a parameter name to unreserved characters so the
// broker never has to escape it.
func queryNameOK(name string) bool {
	if name == "" || len(name) > maxInjectName {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !letter && !(c >= '0' && c <= '9') && c != '-' && c != '_' && c != '.' && c != '~' {
			return false
		}
	}
	return true
}

// refusedHeaderName is case-insensitive because HTTP header names are.
func refusedHeaderName(name string) bool {
	folded := strings.ToLower(name)
	return slices.Contains(refusedAgentHeaders, folded)
}

// formatInjection is the disclosed injection text: the style, and the slot
// name when the style has one. It never carries the credential value.
func formatInjection(inj grantInjection) string {
	if inj.name == "" {
		return inj.style
	}
	return inj.style + ":" + inj.name
}

func parseInjection(text string) (grantInjection, bool) {
	style, name, _ := strings.Cut(text, ":")
	inj := grantInjection{style: style, name: name}
	return inj, injectionOK(style, name)
}

// encodeHeaderBlock is the wire form of a header map: canonical `Name: value`
// lines in name order. Names and values are already restricted to printable
// ASCII without colons in the name and without newlines, so the block parses
// one way.
func encodeHeaderBlock(h map[string]string) string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(h[name])
		b.WriteByte('\n')
	}
	return b.String()
}

func parseHeaderBlock(block string) (map[string]string, bool) {
	if block == "" {
		return nil, true
	}
	if !strings.HasSuffix(block, "\n") {
		return nil, false
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(block, "\n"), "\n") {
		name, value, found := strings.Cut(line, ": ")
		if !found || !headerNameOK(name) || !headerValueOK(value) {
			return nil, false
		}
		if _, dup := out[name]; dup || len(out) >= maxAgentHeaders {
			return nil, false
		}
		out[name] = value
	}
	return out, true
}

// brokerGrantOK validates the http_broker scope fields at issuance.
// They are required for that operation and forbidden on every other one.
func brokerGrantOK(ops []string, spec GrantSpec) error {
	if !soleBroker(ops) {
		if len(spec.HTTPMethods) != 0 || spec.HTTPInject != "" || spec.HTTPInjectName != "" {
			return ErrInvalid
		}
		return nil
	}
	if spec.CredentialClass != "" || spec.CredentialID == "" || spec.SSHUsername != "" || len(spec.SSHHostKey) != 0 {
		return ErrInvalid
	}
	if _, _, _, ok := brokerScope(spec.Resource); !ok {
		return ErrInvalid
	}
	if _, ok := canonicalMethods(spec.HTTPMethods); !ok {
		return ErrInvalid
	}
	if !injectionOK(spec.HTTPInject, spec.HTTPInjectName) {
		return ErrInvalid
	}
	return nil
}

// brokerGrantShape reports whether a stored grant is a usable http_broker policy.
func brokerGrantShape(g grantRecord) bool {
	if !soleBroker(g.Operations) || g.CredentialClass != "" || safeID(g.CredentialID) == "" || g.KeyID != "" {
		return false
	}
	if g.SSHUsername != "" || len(g.SSHHostKey) != 0 {
		return false
	}
	if _, _, _, ok := brokerScope(g.Resource); !ok {
		return false
	}
	canonical, ok := canonicalMethods(g.HTTPMethods)
	return ok && slices.Equal(canonical, g.HTTPMethods) && injectionOK(g.HTTPInject, g.HTTPInjectName)
}

// validateBrokerGrant fails a stored document closed when an http_broker grant
// lost its scope, or when another operation carries broker scope fields.
func validateBrokerGrant(g grantRecord) error {
	if !soleBroker(g.Operations) {
		if len(g.HTTPMethods) != 0 || g.HTTPInject != "" || g.HTTPInjectName != "" {
			return ErrCorrupt
		}
		return nil
	}
	if !brokerGrantShape(g) {
		return ErrCorrupt
	}
	return nil
}

// decideBroker is the deny-by-default http_broker decision. Origin, path
// prefix and method must all match one active, unrevoked grant. The closest
// grant supplies the denial class, scored origin, then path, then method, with
// the lowest grant id breaking ties.
func decideBroker(grants []grantRecord, agentOK bool, agentID, credID, credType string, credOK bool, origin, method, path string, now time.Time) (result, grantID string) {
	if !agentOK {
		return resultDeniedAgent, ""
	}
	if !credOK {
		return resultDeniedCredential, ""
	}
	var active, revoked, expired string
	bestScore, bestID, bestClass := -1, "", ""
	mine := 0
	for i := range grants {
		g := grants[i]
		if g.AgentID != agentID || !soleBroker(g.Operations) || !grantMatchesCred(g, credID, credType) {
			continue
		}
		mine++
		gOrigin, prefix, ok := brokerGrantScope(g.Resource)
		if !ok {
			continue
		}
		originOK := gOrigin == origin
		pathMatch := pathUnderPrefix(prefix, path)
		methodOK := methodAllowed(g.HTTPMethods, method)
		score := 0
		if originOK {
			score += 4
		}
		if pathMatch {
			score += 2
		}
		if methodOK {
			score += 1
		}
		class := ""
		switch {
		case !originOK:
			class = resultDeniedOrigin
		case !pathMatch:
			class = resultDeniedPath
		case !methodOK:
			class = resultDeniedMethod
		}
		if class != "" {
			if score > bestScore || (score == bestScore && g.ID < bestID) {
				bestScore, bestID, bestClass = score, g.ID, class
			}
			continue
		}
		switch {
		case g.RevokedAt != nil:
			revoked = preferID(revoked, g.ID)
		case !now.Before(g.ExpiresAt):
			expired = preferID(expired, g.ID)
		default:
			active = preferID(active, g.ID)
		}
	}
	switch {
	case active != "":
		return resultAllowed, active
	case revoked != "":
		return resultDeniedRevoked, revoked
	case expired != "":
		return resultDeniedExpired, expired
	case bestID != "":
		return bestClass, bestID
	case mine == 0:
		return resultDeniedMissing, ""
	}
	return resultDeniedScope, ""
}

// judgeBroker is the prefix-scoped allow decision. It writes no audit event
// and does not read credential plaintext.
func (s *Session) judgeBroker(agentID, credentialID, origin, method, path string) (auditEvent, error) {
	now, err := s.evaluationTime()
	if err != nil || safeID(agentID) == "" || safeID(credentialID) == "" || !brokerMethod(method) {
		return auditEvent{Result: resultDenied}, ErrInvalid
	}
	agentOK := s.agentExists(agentID)
	credID, credType, credOK := s.lookupCred(credentialID)
	result, grantID := decideBroker(s.grants, agentOK, agentID, credID, credType, credOK, origin, method, path, now)
	partial := auditEvent{Result: result, Operation: OpHTTPBroker, GrantID: grantID}
	if agentOK {
		partial.AgentID = agentID
	}
	if agentOK && credOK && result != resultDeniedAgent {
		partial.CredID = credID
		partial.CredType = credType
	}
	if result != resultAllowed {
		return partial, brokerDenial(result)
	}
	return partial, nil
}

// brokerRequest is the trusted prefix-scoped broker path for one agent id.
func (s *Session) brokerRequest(agentID string, req HTTPRequest) (HTTPResponse, error) {
	if err := s.begin(); err != nil {
		return HTTPResponse{}, err
	}
	defer s.end()
	return s.brokerRequestUnlocked(context.Background(), agentID, req, nil)
}

// brokerRequestUnlocked validates the caller-controlled request shape and runs
// the shared broker exchange. bound is non-nil only for the capability
// adapter, which has already pinned one grant and checked the request against
// that grant's method set and path prefix.
func (s *Session) brokerRequestUnlocked(ctx context.Context, agentID string, req HTTPRequest, bound *agentCapGrant) (HTTPResponse, error) {
	if err := s.live(); err != nil {
		return HTTPResponse{}, err
	}
	headers, headersOK := canonicalAgentHeaders(req.Headers)
	shapeOK := headersOK && brokerOriginOK(req.Origin) && strings.HasPrefix(req.Path, "/") &&
		len(req.Body) <= maxAgentBody && len(req.Query) <= maxAgentQuery && !bodyMisplaced(req.Method, req.Body)
	var out HTTPResponse
	status, err := s.brokerExchange(agentID, brokerAttempt{
		credentialID: req.CredentialID,
		method:       req.Method,
		target:       brokerTarget(req.Origin, req.Path, req.Query),
		operation:    OpHTTPBroker,
		origin:       req.Origin,
		path:         req.Path,
		query:        req.Query,
		headers:      headers,
		body:         req.Body,
		malformed:    !shapeOK,
		prepare:      func(r *http.Request) { applyAgentHeaders(r, headers) },
		capture: func(inj grantInjection, secret []byte, upstream http.Header, body []byte, truncated bool) error {
			projected, perr := projectResponse(inj, secret, upstream, body, truncated)
			if perr != nil {
				return perr
			}
			out = projected
			return nil
		},
		bound: bound,
		ctx:   ctx,
	})
	if err != nil {
		return HTTPResponse{}, err
	}
	out.StatusCode = status
	return out, nil
}

// bodyMisplaced reports a body on a method that must not carry one. GET, HEAD
// and DELETE are sent without a body so the request has one framing.
func bodyMisplaced(method string, body []byte) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodDelete:
		return len(body) > 0
	default:
		return false
	}
}

func brokerTarget(origin, path, query string) string {
	target := origin + path
	if query != "" {
		target += "?" + query
	}
	return target
}

// canonicalAgentHeaders validates the agent's non-auth headers and returns
// them in canonical form. Authorization, Proxy-Authorization, Cookie, Host,
// Content-Length, Transfer-Encoding and the hop-by-hop names are refused.
func canonicalAgentHeaders(headers map[string]string) (map[string]string, bool) {
	if len(headers) > maxAgentHeaders {
		return nil, false
	}
	out := make(map[string]string, len(headers))
	total := 0
	for name, value := range headers {
		if !headerNameOK(name) || !headerValueOK(value) || refusedHeaderName(name) {
			return nil, false
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, duplicate := out[canonical]; duplicate {
			return nil, false
		}
		total += len(canonical) + len(value)
		out[canonical] = value
	}
	if total > maxAgentHeaderBytes {
		return nil, false
	}
	return out, true
}

// injectionCollides refuses a request that would write the grant's own
// credential slot. Header names are compared case-insensitively because HTTP
// treats them that way; query parameter names are compared the same way so a
// different spelling cannot shadow the injected parameter.
func injectionCollides(headers map[string]string, query string, inj grantInjection) bool {
	switch inj.style {
	case InjectHeader:
		for name := range headers {
			if strings.EqualFold(name, inj.name) {
				return true
			}
		}
	case InjectQuery:
		if queryParamNamed(query, inj.name) {
			return true
		}
	}
	return false
}

// queryParamNamed reports a form-encoded parameter with this name. It reads a
// query string and a form request body alike: Rack and Spring take `_method`
// from either, and retarget the method of a POST with it.
func queryParamNamed(query, want string) bool {
	for _, pair := range strings.Split(query, "&") {
		name := pair
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name = pair[:i]
		}
		if strings.EqualFold(name, want) {
			return true
		}
	}
	return false
}

func applyAgentHeaders(r *http.Request, headers map[string]string) {
	for name, value := range headers {
		r.Header.Set(name, value)
	}
}

// injectCredential places the secret according to the grant. The caller cannot
// reach this slot: the collision check above already refused the name.
func injectCredential(r *http.Request, inj grantInjection, secret []byte) error {
	switch inj.style {
	case "", InjectBearer:
		r.Header.Del("Authorization")
		r.Header.Set("Authorization", "Bearer "+string(secret))
	case InjectHeader:
		r.Header.Del(inj.name)
		r.Header.Set(inj.name, string(secret))
	case InjectBasic:
		pair := []byte(inj.name + ":" + string(secret))
		defer wipe(pair)
		r.Header.Del("Authorization")
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(pair))
	case InjectQuery:
		pair := inj.name + "=" + url.QueryEscape(string(secret))
		if r.URL.RawQuery == "" {
			r.URL.RawQuery = pair
		} else {
			r.URL.RawQuery += "&" + pair
		}
	default:
		return ErrInvalid
	}
	return nil
}

func clearCredential(r *http.Request, inj grantInjection) {
	switch inj.style {
	case InjectHeader:
		r.Header.Del(inj.name)
	case InjectQuery:
		r.URL.RawQuery = ""
	default:
		r.Header.Del("Authorization")
	}
}

// credentialForms are the spellings of the credential the broker removes from
// agent-visible bytes: raw, URL-encoded with either percent-escape case, all
// four standard/URL-safe padded/raw base64 variants, lower/upper hex and
// JSON-string-escaped, and for basic auth the `user:pass` pair in those same
// spellings. An upstream that echoes the credential usually echoes one of
// these.
//
// ponytail: a closed list of literal spellings, not an encoding-aware scan.
// Upgrade path: decode the body by Content-Type before matching, if a real
// upstream is found that re-encodes credentials some other way.
func credentialForms(inj grantInjection, secret []byte) [][]byte {
	var forms [][]byte
	add := func(b []byte) {
		if len(b) == 0 {
			return
		}
		for _, existing := range forms {
			if bytes.Equal(existing, b) {
				return
			}
		}
		forms = append(forms, b)
	}
	spellings := func(raw string) {
		add([]byte(raw))
		escaped := []byte(url.QueryEscape(raw))
		add(escaped)
		lowerEscaped := append([]byte(nil), escaped...)
		for i := 0; i+2 < len(lowerEscaped); i++ {
			if lowerEscaped[i] != '%' {
				continue
			}
			for j := i + 1; j <= i+2; j++ {
				if lowerEscaped[j] >= 'A' && lowerEscaped[j] <= 'F' {
					lowerEscaped[j] += 'a' - 'A'
				}
			}
			i += 2
		}
		add(lowerEscaped)
		rawBytes := []byte(raw)
		add([]byte(base64.StdEncoding.EncodeToString(rawBytes)))
		add([]byte(base64.RawStdEncoding.EncodeToString(rawBytes)))
		add([]byte(base64.URLEncoding.EncodeToString(rawBytes)))
		add([]byte(base64.RawURLEncoding.EncodeToString(rawBytes)))
		encodedHex := hex.EncodeToString(rawBytes)
		add([]byte(encodedHex))
		add([]byte(strings.ToUpper(encodedHex)))
		if quoted, err := json.Marshal(raw); err == nil && len(quoted) >= 2 {
			inner := quoted[1 : len(quoted)-1]
			add(inner)
			if bytes.Contains(inner, []byte{'/'}) {
				add(bytes.ReplaceAll(inner, []byte("/"), []byte("\\/")))
			}
		}
	}
	spellings(string(secret))
	if inj.style == InjectBasic {
		spellings(inj.name + ":" + string(secret))
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return forms
}

func wipeForms(forms [][]byte) {
	for i := range forms {
		wipe(forms[i])
	}
}

// bodyNotRedactable reports an upstream response whose bytes redaction cannot
// read from headers alone: a content coding the transport did not transparently
// decode, or a partial-content fragment, which can carry a slice of a
// credential shorter than any whole form. Transparent gzip is unaffected: the
// transport strips Content-Encoding when it decodes the body itself. Every
// coding in every Content-Encoding field counts: a response that lists
// `identity, deflate` is deflate-coded, whatever the first value says.
func bodyNotRedactable(status int, h http.Header) bool {
	for _, field := range h.Values("Content-Encoding") {
		for _, coding := range strings.Split(field, ",") {
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding != "" && coding != "identity" {
				return true
			}
		}
	}
	return status == http.StatusPartialContent || h.Get("Content-Range") != ""
}

// brokerReadableBody is the capped upstream body that is both checked and
// projected. A body cut at the cap can end inside a rune, so a trailing valid
// but incomplete multi-byte sequence is dropped; an illegal byte is a full
// (error) rune to utf8.FullRune, so it stays and bodyNotText withholds it.
func brokerReadableBody(body []byte, truncated bool) []byte {
	if !truncated {
		return body
	}
	for drop := 1; drop < utf8.UTFMax && drop <= len(body); drop++ {
		if tail := body[len(body)-drop:]; utf8.RuneStart(tail[0]) {
			if !utf8.FullRune(tail) {
				return body[:len(body)-drop]
			}
			break
		}
	}
	return body
}

// bodyNotText reports a body the credential scan cannot read: bytes that are
// not valid UTF-8, or that carry a NUL. Redaction looks for spellings of a
// credential in text, so anything else — a compressed stream the upstream did
// not declare, an archive, a binary framing, a stream nested inside another —
// is withheld rather than projected unscanned. An upstream that still wants to
// hand the agent the credential can encode it as text; that residual is ADR
// 0025's, and no byte-level check closes it.
//
// The caller passes the bytes it will project, already through
// brokerReadableBody; trimming again here would judge fewer bytes than the
// agent receives.
func bodyNotText(body []byte) bool {
	if bytes.IndexByte(body, 0) >= 0 {
		return true
	}
	return !utf8.Valid(body)
}

// projectResponse builds the agent-visible response: the allowlisted headers
// and the capped body, both with every credential form removed. A form that
// survives redaction withholds the whole response rather than disclosing it.
func projectResponse(inj grantInjection, secret []byte, upstream http.Header, body []byte, truncated bool) (HTTPResponse, error) {
	forms := credentialForms(inj, secret)
	defer wipeForms(forms)
	out := HTTPResponse{
		Headers:   projectHeaders(upstream, forms),
		Body:      redactForms(append([]byte(nil), body...), forms, truncated),
		Truncated: truncated,
	}
	if len(out.Body) > maxAgentBody {
		// Redaction can grow a body past the cap, so this cut can split a rune
		// too; drop it before partialTail looks for a credential prefix.
		readable := brokerReadableBody(out.Body[:maxAgentBody], true)
		wipe(out.Body[len(readable):])
		out.Body = readable
		out.Truncated = true
		if n := partialTail(out.Body, forms); n > 0 {
			wipe(out.Body[len(out.Body)-n:])
			out.Body = out.Body[:len(out.Body)-n]
		}
	}
	if containsCredentialForm(out.Body, forms) {
		wipe(out.Body)
		return HTTPResponse{}, ErrBrokerUpstream
	}
	for _, value := range out.Headers {
		if containsCredentialForm([]byte(value), forms) {
			wipe(out.Body)
			return HTTPResponse{}, ErrBrokerUpstream
		}
	}
	if len(out.Body) > 0 && (!utf8.Valid(out.Body) || bytes.Contains(out.Body, []byte{0})) {
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(out.Body)))
		base64.StdEncoding.Encode(encoded, out.Body)
		leaked := containsCredentialForm(encoded, forms)
		wipe(encoded)
		if leaked {
			wipe(out.Body)
			return HTTPResponse{}, ErrBrokerUpstream
		}
	}
	mcpJSON, err := json.Marshal(brokerBody(out))
	if err != nil {
		wipe(out.Body)
		return HTTPResponse{}, ErrBrokerUpstream
	}
	if containsCredentialForm(mcpJSON, forms) {
		wipe(mcpJSON)
		wipe(out.Body)
		return HTTPResponse{}, ErrBrokerUpstream
	}
	wipe(mcpJSON)
	return out, nil
}

// projectHeaders keeps only the allowlisted response headers. Multiple values
// are joined; a value that is not bounded printable text is dropped.
func projectHeaders(upstream http.Header, forms [][]byte) map[string]string {
	out := make(map[string]string, maxAgentHeaders)
	names := make([]string, 0, len(upstream))
	for name := range upstream {
		if allowedResponseHeader(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if len(out) >= maxAgentHeaders {
			break
		}
		value := string(redactForms([]byte(strings.Join(upstream.Values(name), ", ")), forms, false))
		if !headerValueOK(value) {
			continue
		}
		out[http.CanonicalHeaderKey(name)] = value
	}
	return out
}

func allowedResponseHeader(name string) bool {
	for _, allowed := range brokerResponseHeaders {
		if strings.EqualFold(name, allowed) {
			return true
		}
	}
	return false
}

// redactForms rewrites buf with every credential form replaced by the fixed
// marker. The scan is one left-to-right pass over the whole capped buffer, so
// a credential split across upstream read boundaries is still matched and
// marker bytes are never rescanned. A truncated buffer also loses a trailing
// partial form, so a credential cut by the cap cannot leak its prefix.
func redactForms(buf []byte, forms [][]byte, truncated bool) []byte {
	if len(forms) == 0 {
		return buf
	}
	out := make([]byte, 0, len(buf))
	for i := 0; i < len(buf); {
		if n := matchFormAt(buf, i, forms); n > 0 {
			out = append(out, redacted...)
			i += n
			continue
		}
		out = append(out, buf[i])
		i++
	}
	if truncated {
		out = out[:len(out)-partialTail(out, forms)]
	}
	if len(out) < len(buf) {
		wipe(buf[len(out):])
	}
	return out
}

// matchFormAt returns the length of the longest form starting at i.
func matchFormAt(buf []byte, i int, forms [][]byte) int {
	for _, form := range forms {
		if len(buf)-i >= len(form) && formPrefixEqual(buf[i:i+len(form)], form) {
			return len(form)
		}
	}
	return 0
}

func containsCredentialForm(buf []byte, forms [][]byte) bool {
	for i := range buf {
		if matchFormAt(buf, i, forms) > 0 {
			return true
		}
	}
	return false
}

// formPrefixEqual compares percent-escape hex digits case-insensitively,
// whole hex spellings case-insensitively on a-f/A-F, and every other byte
// exactly.
func formPrefixEqual(got, form []byte) bool {
	if len(got) > len(form) {
		return false
	}
	if isHexSpelling(form) {
		for i := range got {
			if foldHex(got[i]) != foldHex(form[i]) {
				return false
			}
		}
		return true
	}
	for i := range got {
		if got[i] == form[i] {
			continue
		}
		if !percentHexDigit(form, i) || foldHex(got[i]) != foldHex(form[i]) {
			return false
		}
	}
	return true
}

func percentHexDigit(form []byte, i int) bool {
	switch {
	case i > 0 && form[i-1] == '%' && i+1 < len(form):
		return isHex(form[i]) && isHex(form[i+1])
	case i > 1 && form[i-2] == '%':
		return isHex(form[i-1]) && isHex(form[i])
	default:
		return false
	}
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isHexSpelling(form []byte) bool {
	if len(form) == 0 {
		return false
	}
	for _, c := range form {
		if !isHex(c) {
			return false
		}
	}
	return true
}

func foldHex(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + 'a' - 'A'
	}
	return c
}

// partialTail is the longest proper prefix of any form that ends buf.
func partialTail(buf []byte, forms [][]byte) int {
	best := 0
	for _, form := range forms {
		for k := len(form) - 1; k > best; k-- {
			if k <= len(buf) && formPrefixEqual(buf[len(buf)-k:], form) {
				best = k
				break
			}
		}
	}
	return best
}

// readTruncating reads at most n bytes and reports whether more remained.
// io.ReadAll assembles the upstream reads, so the returned buffer is one
// contiguous value for redaction regardless of upstream chunking.
func readTruncating(body io.ReadCloser, n int) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	buf, err := io.ReadAll(io.LimitReader(body, int64(n)+1))
	_ = body.Close()
	if err != nil {
		wipe(buf)
		return nil, false, errBrokerTransport
	}
	if len(buf) > n {
		wipe(buf[n:])
		return buf[:n], true, nil
	}
	return buf, false, nil
}

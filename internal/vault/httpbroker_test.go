package vault

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// These tests use a private synthetic TLS upstream and disposable random
// credentials. No DNS resolver, external account, or real API is reached.
const (
	brokerTestOrigin = "https://svc.example"
	brokerTestPrefix = "/v1/repos/o/r"
)

type httpBrokerEnv struct {
	t         *testing.T
	s         *Session
	path      string
	pass      []byte
	logs      *bytes.Buffer
	principal *AgentPrincipal
	agentID   string
	credID    string
	secret    []byte
	grant     Grant
	server    *httptest.Server
	// handler is the synthetic upstream. Tests replace it per case.
	handler func(http.ResponseWriter, *http.Request)
	// seen is the last request the upstream actually received.
	seen     *http.Request
	lookups  int
	requests int
}

// newHTTPBrokerEnv issues one http_broker grant with the given injection and
// wires the session to a synthetic TLS upstream.
func newHTTPBrokerEnv(t *testing.T, inject, injectName string, methods ...string) *httpBrokerEnv {
	t.Helper()
	e := &httpBrokerEnv{t: t, logs: &bytes.Buffer{}}
	e.path, e.pass, e.s = mustCreate(t, log.New(e.logs, "", 0))
	// A hostile secret: it contains the characters JSON, URL and header
	// encodings each treat specially.
	e.secret = []byte("Sk" + randHex(t, 20) + `/\"&=`)
	cred, err := e.s.Put("api", "api_key", e.secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e.credID = cred.ID
	agent, err := e.s.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	e.agentID = agent.ID
	if e.principal, err = e.s.Agent(agent.ID); err != nil {
		t.Fatal(err)
	}
	if len(methods) == 0 {
		methods = []string{http.MethodGet}
	}
	e.grant, err = e.s.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpHTTPBroker},
		Resource: brokerTestOrigin + brokerTestPrefix, ExpiresAt: time.Now().UTC().Add(time.Hour),
		HTTPMethods: methods, HTTPInject: inject, HTTPInjectName: injectName,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.handler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	e.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests++
		e.seen = r.Clone(context.Background())
		e.handler(w, r)
	}))
	t.Cleanup(e.server.Close)
	fixture, err := url.Parse(e.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	e.s.resolve = func(_ context.Context, host string) ([]net.IP, error) {
		e.lookups++
		if host != "svc.example" {
			return nil, errors.New("unexpected destination")
		}
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	client := e.server.Client()
	client.Timeout = brokerTimeout
	client.CheckRedirect = refuseRedirect
	t.Cleanup(client.CloseIdleConnections)
	// This is the test-only origin replacement already used by the credential
	// fixture. It is unreachable from shipping code or tool arguments.
	e.s.httpDo = func(req *http.Request) (*http.Response, error) {
		out := req.Clone(req.Context())
		out.URL.Scheme, out.URL.Host, out.Host = fixture.Scheme, fixture.Host, fixture.Host
		return client.Do(out)
	}
	return e
}

func (e *httpBrokerEnv) request(path string) HTTPRequest {
	return HTTPRequest{CredentialID: e.credID, Origin: brokerTestOrigin, Method: http.MethodGet, Path: path}
}

// forms is every spelling of the credential a leak check looks for.
func (e *httpBrokerEnv) forms() []string {
	return secretForms(e.secret)
}

// assertNoLeak checks the vault file, the audit rows, the host log, the
// process environment and the supplied outputs for any credential spelling.
func (e *httpBrokerEnv) assertNoLeak(t *testing.T, outputs ...string) {
	t.Helper()
	rows := append([]auditEvent(nil), e.s.audit...)
	if err := verifyChain(rows); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(e.path, e.pass); err != nil {
		t.Fatal(err)
	}
	db, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	surfaces := append(outputs, string(db), e.logs.String(), string(mustJSON(t, rows)), strings.Join(os.Environ(), "\n"))
	for _, row := range rows {
		surfaces = append(surfaces, row.Result+row.Operation+row.GrantID+row.CredID+row.CredType+row.Reasons)
	}
	for _, surface := range surfaces {
		if containsForm(surface, e.forms()) {
			t.Fatal("credential-derived bytes escaped to an agent-visible or plaintext surface")
		}
	}
}

func (e *httpBrokerEnv) lastResult(t *testing.T) string {
	t.Helper()
	for i := len(e.s.audit) - 1; i >= 0; i-- {
		if e.s.audit[i].Action == actionBroker {
			return e.s.audit[i].Result
		}
	}
	t.Fatal("no broker audit row")
	return ""
}

// echoHandler reflects the credential the upstream was sent back at the agent,
// in the body and in both an allowlisted and a dropped response header.
func (e *httpBrokerEnv) echoHandler(w http.ResponseWriter, r *http.Request) {
	echo := r.Header.Get("Authorization") + " " + r.URL.RawQuery + " " + r.Header.Get("X-Api-Key")
	if user, pass, ok := r.BasicAuth(); ok {
		echo += " " + user + ":" + pass
	}
	for _, form := range e.forms() {
		echo += " " + form
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("ETag", echo)
	w.Header().Set("Set-Cookie", "s="+echo)
	w.Header().Set("X-RateLimit-Remaining", "9")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "echo: "+echo)
}

// TestBrokerUpstreamEchoIsRedacted is the central adversarial case: for every
// injection style the upstream reflects the credential back in the body and in
// an allowlisted header, and the agent still receives none of it.
func TestBrokerUpstreamEchoIsRedacted(t *testing.T) {
	for _, style := range []struct{ inject, name string }{
		{InjectBearer, ""},
		{InjectHeader, "X-Api-Key"},
		{InjectBasic, "svc-user"},
		{InjectQuery, "access_token"},
	} {
		t.Run(style.inject, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, style.inject, style.name)
			e.handler = e.echoHandler
			resp, err := e.principal.BrokerRequest(e.request(brokerTestPrefix + "/issues"))
			if err != nil {
				t.Fatalf("authorized broker request failed: %v", err)
			}
			if resp.StatusCode != http.StatusOK || resp.Truncated {
				t.Fatalf("status %d truncated %v", resp.StatusCode, resp.Truncated)
			}
			if !strings.HasPrefix(string(resp.Body), "echo: ") || !bytes.Contains(resp.Body, []byte(redacted)) {
				t.Fatalf("body was not the redacted echo: %q", resp.Body)
			}
			if _, cookie := resp.Headers["Set-Cookie"]; cookie {
				t.Fatal("response disclosed Set-Cookie")
			}
			if resp.Headers["X-Ratelimit-Remaining"] != "9" || resp.Headers["Content-Type"] != "text/plain" {
				t.Fatalf("allowlisted headers lost: %v", resp.Headers)
			}
			if !strings.Contains(resp.Headers["Etag"], redacted) {
				t.Fatalf("allowlisted header echo was not redacted: %q", resp.Headers["Etag"])
			}
			// The injected slot reached the upstream, so the echo was real.
			if e.requests != 1 || e.lookups != 1 {
				t.Fatalf("requests %d lookups %d", e.requests, e.lookups)
			}
			if !injectionReached(e.seen, style.inject, style.name, e.secret) {
				t.Fatal("credential was not injected into the granted slot")
			}
			if e.lastResult(t) != resultCompleted {
				t.Fatal("completed use was not audited")
			}
			e.assertNoLeak(t, string(resp.Body), mustHeaderText(resp.Headers))
		})
	}
}

func injectionReached(req *http.Request, inject, name string, secret []byte) bool {
	if req == nil {
		return false
	}
	switch inject {
	case InjectBearer:
		return req.Header.Get("Authorization") == "Bearer "+string(secret)
	case InjectHeader:
		return req.Header.Get(name) == string(secret)
	case InjectBasic:
		user, pass, ok := req.BasicAuth()
		return ok && user == name && pass == string(secret)
	case InjectQuery:
		return req.URL.Query().Get(name) == string(secret)
	}
	return false
}

func mustHeaderText(h map[string]string) string {
	return encodeHeaderBlock(h)
}

// TestBrokerRedactsSecretSplitAcrossReads proves redaction runs on the whole
// capped buffer, not on one upstream read at a time.
func TestBrokerRedactsSecretSplitAcrossReads(t *testing.T) {
	e := newHTTPBrokerEnv(t, InjectBearer, "")
	// Flush mid-secret so the credential straddles two upstream chunks. Each
	// flush is its own read on the client side.
	half := len(e.secret) / 2
	e.handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(append([]byte(strings.Repeat("a", 9000)), e.secret[:half]...))
		w.(http.Flusher).Flush()
		_, _ = w.Write(append(append([]byte(nil), e.secret[half:]...), []byte(strings.Repeat("b", 9000))...))
	}
	resp, err := e.principal.BrokerRequest(e.request(brokerTestPrefix))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(resp.Body, []byte(redacted)) || len(resp.Body) != 18000+len(redacted) {
		t.Fatalf("split secret was not redacted once: %d bytes", len(resp.Body))
	}
	e.assertNoLeak(t, string(resp.Body))
}

// TestBrokerTruncatesOversizedBody also covers the partial-credential tail: a
// body cut by the cap must not end in a prefix of the credential.
func TestBrokerTruncatesOversizedBody(t *testing.T) {
	e := newHTTPBrokerEnv(t, InjectBearer, "")
	// Place the credential so the cap falls inside it.
	lead := maxAgentBody - len(e.secret)/2
	e.handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("c", lead)))
		_, _ = w.Write(e.secret)
		_, _ = w.Write([]byte(strings.Repeat("d", maxAgentBody)))
	}
	resp, err := e.principal.BrokerRequest(e.request(brokerTestPrefix))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Truncated || len(resp.Body) > maxAgentBody {
		t.Fatalf("oversized body was not truncated: %d bytes truncated %v", len(resp.Body), resp.Truncated)
	}
	if len(resp.Body) != lead {
		t.Fatalf("truncated body kept a partial credential: %d bytes, want %d", len(resp.Body), lead)
	}
	e.assertNoLeak(t, string(resp.Body))
}

// TestBrokerDeniesMalformedPathsBeforeDNS covers traversal, encoded slashes
// and backslashes, percent-encoded dots, double slashes, fragments, userinfo
// and control bytes. None of them may resolve a name or open a connection.
func TestBrokerDeniesMalformedPathsBeforeDNS(t *testing.T) {
	cases := []struct {
		name, path string
	}{
		{"dot-segment", brokerTestPrefix + "/../../etc/passwd"},
		{"single-dot", brokerTestPrefix + "/./issues"},
		{"encoded-slash", brokerTestPrefix + "%2f..%2fadmin"},
		{"encoded-backslash", brokerTestPrefix + "%5c..%5cadmin"},
		{"literal-backslash", brokerTestPrefix + `\..\admin`},
		{"encoded-dot", brokerTestPrefix + "/%2e%2e/admin"},
		{"double-slash", brokerTestPrefix + "//issues"},
		{"fragment", brokerTestPrefix + "/issues#frag"},
		{"userinfo", brokerTestPrefix + "/issues@evil.example"},
		{"control-byte", brokerTestPrefix + "/iss\x00ues"},
		{"newline", brokerTestPrefix + "/iss\nues"},
		{"space", brokerTestPrefix + "/iss ues"},
		{"star", brokerTestPrefix + "/*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "")
			e.s.dial = func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("malformed path opened a connection")
				return nil, errors.New("dial")
			}
			resp, err := e.principal.BrokerRequest(e.request(tc.path))
			if err == nil || resp.StatusCode != 0 || resp.Body != nil {
				t.Fatalf("malformed path produced a response: %d %v", resp.StatusCode, err)
			}
			if e.lookups != 0 || e.requests != 0 {
				t.Fatalf("malformed path resolved or reached the destination: lookups %d requests %d", e.lookups, e.requests)
			}
			e.assertNoLeak(t, err.Error())
		})
	}
}

// TestBrokerRefusesHeaderSmuggling covers every header an agent may not set,
// including the grant's own injection slot.
func TestBrokerRefusesHeaderSmuggling(t *testing.T) {
	cases := []struct {
		name, inject, injectName string
		headers                  map[string]string
		query                    string
	}{
		{name: "authorization", inject: InjectBearer, headers: map[string]string{"Authorization": "Bearer attacker"}},
		{name: "authorization-lowercase", inject: InjectBearer, headers: map[string]string{"authorization": "Bearer attacker"}},
		{name: "proxy-authorization", inject: InjectBearer, headers: map[string]string{"Proxy-Authorization": "Basic x"}},
		{name: "cookie", inject: InjectBearer, headers: map[string]string{"Cookie": "a=b"}},
		{name: "host", inject: InjectBearer, headers: map[string]string{"Host": "attacker.example"}},
		{name: "content-length", inject: InjectBearer, headers: map[string]string{"Content-Length": "0"}},
		{name: "transfer-encoding", inject: InjectBearer, headers: map[string]string{"Transfer-Encoding": "chunked"}},
		{name: "accept-encoding", inject: InjectBearer, headers: map[string]string{"Accept-Encoding": "gzip"}},
		{name: "accept-encoding-folded", inject: InjectBearer, headers: map[string]string{"accept-ENCODING": "br, deflate"}},
		{name: "range", inject: InjectBearer, headers: map[string]string{"Range": "bytes=0-9"}},
		{name: "if-range", inject: InjectBearer, headers: map[string]string{"If-Range": `"etag"`}},
		{name: "expect", inject: InjectBearer, headers: map[string]string{"Expect": "100-continue"}},
		{name: "connection", inject: InjectBearer, headers: map[string]string{"Connection": "close"}},
		{name: "upgrade", inject: InjectBearer, headers: map[string]string{"Upgrade": "websocket"}},
		{name: "te", inject: InjectBearer, headers: map[string]string{"TE": "trailers"}},
		{name: "crlf-in-value", inject: InjectBearer, headers: map[string]string{"X-Note": "a\r\nX-Injected: b"}},
		{name: "crlf-in-name", inject: InjectBearer, headers: map[string]string{"X-Note\r\nX-Injected": "b"}},
		{name: "injected-header-slot", inject: InjectHeader, injectName: "X-Api-Key", headers: map[string]string{"X-Api-Key": "attacker"}},
		{name: "injected-header-slot-folded", inject: InjectHeader, injectName: "X-Api-Key", headers: map[string]string{"x-API-key": "attacker"}},
		{name: "injected-query-slot", inject: InjectQuery, injectName: "access_token", query: "access_token=attacker"},
		{name: "injected-query-slot-folded", inject: InjectQuery, injectName: "access_token", query: "a=1&ACCESS_Token=attacker"},
		{name: "method-override-header", inject: InjectBearer, headers: map[string]string{"X-HTTP-Method-Override": "DELETE"}},
		{name: "method-override-header-folded", inject: InjectBearer, headers: map[string]string{"x-http-METHOD": "PATCH"}},
		{name: "x-method-override", inject: InjectBearer, headers: map[string]string{"X-Method-Override": "POST"}},
		{name: "x-original-url", inject: InjectBearer, headers: map[string]string{"X-Original-URL": "/admin"}},
		{name: "x-rewrite-url", inject: InjectBearer, headers: map[string]string{"X-Rewrite-URL": "/admin"}},
		{name: "x-forwarded-host", inject: InjectBearer, headers: map[string]string{"X-Forwarded-Host": "evil.example"}},
		{name: "forwarded", inject: InjectBearer, headers: map[string]string{"Forwarded": `host=evil.example`}},
		{name: "method-override-query", inject: InjectBearer, query: "_method=DELETE"},
		{name: "method-override-query-folded", inject: InjectBearer, query: "a=1&_METHOD=PATCH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, tc.inject, tc.injectName)
			req := e.request(brokerTestPrefix + "/issues")
			req.Headers, req.Query = tc.headers, tc.query
			resp, err := e.principal.BrokerRequest(req)
			if err == nil || resp.StatusCode != 0 {
				t.Fatalf("header smuggling was accepted: %d %v", resp.StatusCode, err)
			}
			if e.requests != 0 || e.lookups != 0 {
				t.Fatalf("refused request resolved or reached the upstream: lookups %d requests %d", e.lookups, e.requests)
			}
			// A collision with the grant's own slot is a policy refusal and is
			// attributed; a forbidden name is refused before attribution.
			wantResult := resultDenied
			if strings.HasPrefix(tc.name, "injected-") || strings.Contains(tc.name, "method-override-query") {
				wantResult = resultDeniedMalformed
				if !errors.Is(err, ErrDeniedMalformed) {
					t.Fatalf("injection collision error %v", err)
				}
			} else if !errors.Is(err, ErrInvalid) {
				t.Fatalf("forbidden header error %v", err)
			}
			if e.lastResult(t) != wantResult {
				t.Fatalf("audit result %s, want %s", e.lastResult(t), wantResult)
			}
			e.assertNoLeak(t, err.Error())
		})
	}
}

func gzipBytes(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.WriteString(zw, text); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestBrokerTransparentGzipIsRedacted is the case redaction must keep
// handling: the broker never sends Accept-Encoding itself, so the transport
// negotiates gzip and decodes the body before the broker sees it. The echoed
// credential is then an ordinary literal match.
func TestBrokerTransparentGzipIsRedacted(t *testing.T) {
	e := newHTTPBrokerEnv(t, InjectBearer, "")
	e.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzipBytes(t, "token: "+r.Header.Get("Authorization")))
	}
	resp, err := e.principal.BrokerRequest(e.request(brokerTestPrefix))
	if err != nil {
		t.Fatalf("transparently decoded response failed: %v", err)
	}
	if e.seen == nil || e.seen.Header.Get("Accept-Encoding") != "gzip" {
		t.Fatal("the transport did not negotiate gzip, so this is not the transparent case")
	}
	if !strings.HasPrefix(string(resp.Body), "token: Bearer ") || !bytes.Contains(resp.Body, []byte(redacted)) {
		t.Fatalf("decoded body was not redacted: %q", resp.Body)
	}
	e.assertNoLeak(t, string(resp.Body), mustHeaderText(resp.Headers))
}

// TestBrokerWithholdsUndecodedOrPartialBody covers the two ways an upstream
// can hand back bytes the literal redaction scan cannot match: a content
// coding the transport did not decode, and a byte-range fragment carrying a
// slice of the credential shorter than any whole form. Both fail closed on
// the same upstream_error path as a surviving credential form.
func TestBrokerWithholdsUndecodedOrPartialBody(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		headers map[string]string
	}{
		{"unsolicited-gzip", http.StatusOK, map[string]string{"Content-Encoding": "gzip"}},
		{"brotli", http.StatusOK, map[string]string{"Content-Encoding": "BR"}},
		{"partial-content", http.StatusPartialContent, map[string]string{"Content-Range": "bytes 0-15/4096"}},
		{"content-range-without-206", http.StatusOK, map[string]string{"Content-Range": "bytes 0-15/4096"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "")
			// The upstream is written straight onto the wire-level response:
			// a real transport decodes the gzip it asked for, so only this
			// seam can present a coding it did not negotiate.
			e.s.httpDo = func(req *http.Request) (*http.Response, error) {
				e.requests++
				auth := req.Header.Get("Authorization")
				raw := gzipBytes(t, "token: "+auth)
				if tc.headers["Content-Encoding"] == "" {
					raw = []byte(auth[:16])
				}
				header := http.Header{"Content-Type": {"text/plain"}}
				for name, value := range tc.headers {
					header.Set(name, value)
				}
				return &http.Response{
					StatusCode: tc.status,
					Header:     header,
					Body:       io.NopCloser(bytes.NewReader(raw)),
				}, nil
			}
			resp, err := e.principal.BrokerRequest(e.request(brokerTestPrefix))
			if !errors.Is(err, ErrBrokerUpstream) || resp.StatusCode != 0 || resp.Body != nil || resp.Headers != nil {
				t.Fatalf("unreadable body was projected: %+v %v", resp, err)
			}
			if e.requests != 1 || e.lastResult(t) != resultUpstreamError {
				t.Fatalf("requests %d result %s", e.requests, e.lastResult(t))
			}
			e.assertNoLeak(t, err.Error())
		})
	}
}

// TestBrokerWithholdsCompressedBodyWithoutContentEncoding covers upstream
// bodies that are compressed containers with no Content-Encoding: the literal
// scan cannot match them and gunzip would recover the credential.
func TestBrokerWithholdsCompressedBodyWithoutContentEncoding(t *testing.T) {
	const echoLabel = "SENTINEL_ECHO:"
	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "gzip-no-header", raw: nil},
		{name: "zstd-magic", raw: []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00}},
		{name: "xz-magic", raw: []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00}},
		{name: "bzip2-magic", raw: []byte("BZh1\x31\x41\x59\x26\x53\x59\x00")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "")
			e.s.httpDo = func(req *http.Request) (*http.Response, error) {
				e.requests++
				auth := req.Header.Get("Authorization")
				raw := tc.raw
				if raw == nil {
					raw = gzipBytes(t, echoLabel+auth)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {"text/plain"}},
					Body:       io.NopCloser(bytes.NewReader(raw)),
				}, nil
			}
			resp, err := e.principal.BrokerRequest(e.request(brokerTestPrefix))
			if !errors.Is(err, ErrBrokerUpstream) || resp.StatusCode != 0 || resp.Body != nil || resp.Headers != nil {
				t.Fatalf("compressed body without coding was projected: %+v %v", resp, err)
			}
			if e.requests != 1 || e.lastResult(t) != resultUpstreamError {
				t.Fatalf("requests %d result %s", e.requests, e.lastResult(t))
			}
			e.assertNoLeak(t, err.Error())
		})
	}
	t.Run("plaintext-prefix-still-redacted", func(t *testing.T) {
		e := newHTTPBrokerEnv(t, InjectBearer, "")
		e.handler = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, echoLabel+r.Header.Get("Authorization"))
		}
		resp, err := e.principal.BrokerRequest(e.request(brokerTestPrefix))
		if err != nil {
			t.Fatalf("plaintext echo failed: %v", err)
		}
		if !strings.HasPrefix(string(resp.Body), echoLabel) || !bytes.Contains(resp.Body, []byte(redacted)) {
			t.Fatalf("plaintext body was not redacted: %q", resp.Body)
		}
		e.assertNoLeak(t, string(resp.Body), mustHeaderText(resp.Headers))
	})
}

// TestBrokerRefusesRedirect keeps ADR 0006's refusal: the credential is never
// offered to the next hop and the Location header never reaches the agent.
func TestBrokerRefusesRedirect(t *testing.T) {
	e := newHTTPBrokerEnv(t, InjectBearer, "")
	e.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://attacker.example/?t="+r.Header.Get("Authorization"))
		w.Header().Set("ETag", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}
	resp, err := e.principal.BrokerRequest(e.request(brokerTestPrefix))
	if !errors.Is(err, ErrDeniedRedirect) || resp.StatusCode != 0 || resp.Body != nil || resp.Headers != nil {
		t.Fatalf("redirect was followed or projected: %+v %v", resp, err)
	}
	if e.requests != 1 || e.lastResult(t) != resultDeniedRedirect {
		t.Fatalf("requests %d result %s", e.requests, e.lastResult(t))
	}
	e.assertNoLeak(t, err.Error())
}

// TestBrokerGrantMatching is the positive and negative scope table: origin,
// path prefix on segment boundaries, and the explicit method set.
func TestBrokerGrantMatching(t *testing.T) {
	allow := []struct{ method, path string }{
		{http.MethodGet, brokerTestPrefix},
		{http.MethodGet, brokerTestPrefix + "/issues"},
		{http.MethodGet, brokerTestPrefix + "/issues/17/comments"},
		{http.MethodPost, brokerTestPrefix + "/issues"},
	}
	deny := []struct {
		method, path, origin string
		want                 error
	}{
		{http.MethodGet, brokerTestPrefix + "x", brokerTestOrigin, ErrDeniedPath},
		{http.MethodGet, "/v1/repos/o/rx/issues", brokerTestOrigin, ErrDeniedPath},
		{http.MethodGet, "/v1/repos/o", brokerTestOrigin, ErrDeniedPath},
		{http.MethodGet, "/v1/other", brokerTestOrigin, ErrDeniedPath},
		{http.MethodGet, "/", brokerTestOrigin, ErrDeniedPath},
		{http.MethodDelete, brokerTestPrefix + "/issues", brokerTestOrigin, ErrDeniedMethod},
		{http.MethodPut, brokerTestPrefix, brokerTestOrigin, ErrDeniedMethod},
		{http.MethodGet, brokerTestPrefix, "https://other.example", ErrDeniedOrigin},
		{http.MethodGet, brokerTestPrefix, "https://svc.example:8443", ErrDeniedOrigin},
		{http.MethodGet, brokerTestPrefix, "https://sub.svc.example", ErrDeniedOrigin},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.method+tc.path, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "", http.MethodGet, http.MethodPost)
			req := e.request(tc.path)
			req.Method = tc.method
			if tc.method == http.MethodPost {
				req.Body = []byte(`{"ok":true}`)
			}
			resp, err := e.principal.BrokerRequest(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("granted request denied: %d %v", resp.StatusCode, err)
			}
			if e.seen == nil || e.seen.URL.Path != tc.path || e.seen.Method != tc.method {
				t.Fatal("broker changed the granted request")
			}
			if tc.method == http.MethodPost && e.seen.ContentLength != int64(len(req.Body)) {
				t.Fatalf("body framing changed: %d", e.seen.ContentLength)
			}
			e.assertNoLeak(t)
		})
	}
	for _, tc := range deny {
		t.Run("deny/"+tc.method+tc.origin+tc.path, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "", http.MethodGet, http.MethodPost)
			req := e.request(tc.path)
			req.Method, req.Origin = tc.method, tc.origin
			resp, err := e.principal.BrokerRequest(req)
			if !errors.Is(err, tc.want) || resp.StatusCode != 0 {
				t.Fatalf("scope denial %v, want %v", err, tc.want)
			}
			if e.requests != 0 || e.lookups != 0 {
				t.Fatal("scope denial resolved or reached the destination")
			}
			e.assertNoLeak(t, err.Error())
		})
	}
}

// TestBrokerGrantShapeValidation keeps the grant shape closed at issuance.
func TestBrokerGrantShapeValidation(t *testing.T) {
	e := newHTTPBrokerEnv(t, InjectBearer, "")
	base := GrantSpec{
		AgentID: e.agentID, CredentialID: e.credID, Operations: []string{OpHTTPBroker},
		Resource: brokerTestOrigin + brokerTestPrefix, ExpiresAt: time.Now().UTC().Add(time.Hour),
		HTTPMethods: []string{http.MethodGet}, HTTPInject: InjectBearer,
	}
	mutate := map[string]func(*GrantSpec){
		"no-methods":          func(s *GrantSpec) { s.HTTPMethods = nil },
		"unknown-method":      func(s *GrantSpec) { s.HTTPMethods = []string{"TRACE"} },
		"lowercase-method":    func(s *GrantSpec) { s.HTTPMethods = []string{"get"} },
		"duplicate-method":    func(s *GrantSpec) { s.HTTPMethods = []string{"GET", "GET"} },
		"no-injection":        func(s *GrantSpec) { s.HTTPInject = "" },
		"unknown-injection":   func(s *GrantSpec) { s.HTTPInject = "digest" },
		"bearer-with-name":    func(s *GrantSpec) { s.HTTPInjectName = "X-Api-Key" },
		"header-without-name": func(s *GrantSpec) { s.HTTPInject = InjectHeader },
		"header-refused-name": func(s *GrantSpec) { s.HTTPInject, s.HTTPInjectName = InjectHeader, "Cookie" },
		"header-bad-name":     func(s *GrantSpec) { s.HTTPInject, s.HTTPInjectName = InjectHeader, "X Api Key" },
		"basic-user-colon":    func(s *GrantSpec) { s.HTTPInject, s.HTTPInjectName = InjectBasic, "us:er" },
		"query-bad-name":      func(s *GrantSpec) { s.HTTPInject, s.HTTPInjectName = InjectQuery, "a b" },
		"class-not-id":        func(s *GrantSpec) { s.CredentialID, s.CredentialClass = "", "api_key" },
		"http-scheme":         func(s *GrantSpec) { s.Resource = "http://svc.example/v1" },
		"explicit-443":        func(s *GrantSpec) { s.Resource = "https://svc.example:443/v1" },
		"uppercase-host":      func(s *GrantSpec) { s.Resource = "https://SVC.example/v1" },
		"trailing-slash":      func(s *GrantSpec) { s.Resource = brokerTestOrigin + brokerTestPrefix + "/" },
		"dot-segment":         func(s *GrantSpec) { s.Resource = brokerTestOrigin + "/v1/../admin" },
		"percent-escape":      func(s *GrantSpec) { s.Resource = brokerTestOrigin + "/v1%2fadmin" },
		"query-in-resource":   func(s *GrantSpec) { s.Resource = brokerTestOrigin + "/v1?a=b" },
		"loopback-host":       func(s *GrantSpec) { s.Resource = "https://localhost/v1" },
		"internal-host":       func(s *GrantSpec) { s.Resource = "https://svc.internal/v1" },
		"ip-host":             func(s *GrantSpec) { s.Resource = "https://1.1.1.1/v1" },
		"ssh-fields":          func(s *GrantSpec) { s.SSHUsername = "git" },
	}
	for name, apply := range mutate {
		t.Run(name, func(t *testing.T) {
			spec := base
			spec.HTTPMethods = append([]string(nil), base.HTTPMethods...)
			apply(&spec)
			if _, err := e.s.IssueGrant(spec); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid broker grant issued: %v", err)
			}
		})
	}
	// Broker scope fields are forbidden on every other operation.
	for _, op := range []string{OpHTTPRequest, OpSign, OpLocalArtifactAttest} {
		spec := base
		spec.Operations, spec.Resource = []string{op}, "GET https://svc.example/v1/ping"
		if _, err := e.s.IssueGrant(spec); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s grant accepted broker scope: %v", op, err)
		}
	}
}

// TestBrokerRequestShapeLimits keeps the caller-controlled sizes bounded and
// a body off the methods that must not carry one.
func TestBrokerRequestShapeLimits(t *testing.T) {
	cases := map[string]func(*HTTPRequest){
		"oversized-body":   func(r *HTTPRequest) { r.Method, r.Body = http.MethodPost, make([]byte, maxAgentBody+1) },
		"body-on-get":      func(r *HTTPRequest) { r.Body = []byte("x") },
		"oversized-query":  func(r *HTTPRequest) { r.Query = strings.Repeat("a", maxAgentQuery+1) },
		"too-many-headers": func(r *HTTPRequest) { r.Headers = manyHeaders(maxAgentHeaders + 1) },
		"empty-header":     func(r *HTTPRequest) { r.Headers = map[string]string{"X-Note": ""} },
		"origin-with-path": func(r *HTTPRequest) { r.Origin = brokerTestOrigin + "/v1" },
		"origin-plain":     func(r *HTTPRequest) { r.Origin = "http://svc.example" },
		"relative-path":    func(r *HTTPRequest) { r.Path = "v1/repos/o/r" },
		"unknown-method":   func(r *HTTPRequest) { r.Method = "TRACE" },
		"no-credential":    func(r *HTTPRequest) { r.CredentialID = "" },
	}
	for name, apply := range cases {
		t.Run(name, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "", http.MethodGet, http.MethodPost)
			req := e.request(brokerTestPrefix)
			apply(&req)
			resp, err := e.principal.BrokerRequest(req)
			if !errors.Is(err, ErrInvalid) || resp.StatusCode != 0 {
				t.Fatalf("unbounded request shape accepted: %d %v", resp.StatusCode, err)
			}
			if e.requests != 0 || e.lookups != 0 {
				t.Fatal("refused request shape reached the destination")
			}
		})
	}
}

func manyHeaders(n int) map[string]string {
	out := make(map[string]string, n)
	for i := 0; i < n; i++ {
		out["X-Note-"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	return out
}

// TestBrokerHTTPRequestGrantIsNotABrokerGrant keeps the two operations
// separate: an exact http_request grant cannot return a body.
func TestBrokerHTTPRequestGrantIsNotABrokerGrant(t *testing.T) {
	e := newHTTPBrokerEnv(t, InjectBearer, "")
	exact := "GET " + brokerTestOrigin + brokerTestPrefix + "/issues"
	if _, err := e.s.IssueGrant(GrantSpec{
		AgentID: e.agentID, CredentialID: e.credID, Operations: []string{OpHTTPRequest},
		Resource: exact, ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	e.handler = e.echoHandler
	// The exact grant still works on the status-only path.
	status, err := e.principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: e.credID, Method: http.MethodGet, Target: strings.TrimPrefix(exact, "GET ")})
	if err != nil || status.StatusCode != http.StatusOK {
		t.Fatalf("existing exact grant stopped working: %d %v", status.StatusCode, err)
	}
	if _, ok := any(status).(interface{ Body() []byte }); ok {
		t.Fatal("status-only response gained a body")
	}
	e.assertNoLeak(t)
}

// TestBrokerRedactForms is the unit check behind the streaming property: one
// left-to-right pass over the capped buffer, marker bytes never rescanned, and
// a truncated buffer losing any partial credential tail.
func TestBrokerRedactForms(t *testing.T) {
	secret := []byte("s3cr3t-value")
	forms := credentialForms(grantInjection{style: InjectBearer}, secret)
	full := []byte("a" + string(secret) + "b" + base64.StdEncoding.EncodeToString(secret) + "c")
	got := redactForms(append([]byte(nil), full...), forms, false)
	want := "a" + redacted + "b" + redacted + "c"
	if string(got) != want {
		t.Fatalf("redaction %q, want %q", got, want)
	}
	// A truncated buffer must not end in a proper prefix of the credential.
	cut := []byte("abc" + string(secret[:len(secret)-3]))
	if string(redactForms(append([]byte(nil), cut...), forms, true)) != "abc" {
		t.Fatalf("partial tail survived truncation: %q", redactForms(append([]byte(nil), cut...), forms, true))
	}
	// The marker is not itself rescanned into a second match.
	if bytes.Count(redactForms([]byte(string(secret)+string(secret)), forms, false), []byte(redacted)) != 2 {
		t.Fatal("adjacent occurrences were not each replaced exactly once")
	}
	if string(redactForms([]byte("plain"), nil, false)) != "plain" {
		t.Fatal("empty form set rewrote the buffer")
	}
}

func TestBrokerRedactsEquivalentCredentialEncodings(t *testing.T) {
	var secret []byte
	for {
		secret = randBytesT(t, 32)
		std := base64.StdEncoding.EncodeToString(secret)
		url64 := base64.URLEncoding.EncodeToString(secret)
		escaped := url.QueryEscape(string(secret))
		lowerEscaped := lowerPercentHex(escaped)
		mixedEscaped := mixedPercentHex(escaped)
		if std != url64 && escaped != lowerEscaped && mixedEscaped != escaped && mixedEscaped != lowerEscaped {
			break
		}
	}
	forms := credentialForms(grantInjection{style: InjectBearer}, secret)
	defer wipeForms(forms)
	cases := []struct {
		name string
		body []byte
	}{
		{"uppercase-hex", []byte(strings.ToUpper(hex.EncodeToString(secret)))},
		{"lowercase-percent-escapes", []byte(lowerPercentHex(url.QueryEscape(string(secret))))},
		{"mixed-case-percent-escapes", []byte(mixedPercentHex(url.QueryEscape(string(secret))))},
		{"base64-standard-padded", []byte(base64.StdEncoding.EncodeToString(secret))},
		{"base64-standard-raw", []byte(base64.RawStdEncoding.EncodeToString(secret))},
		{"base64-url-padded", []byte(base64.URLEncoding.EncodeToString(secret))},
		{"base64-url-raw", []byte(base64.RawURLEncoding.EncodeToString(secret))},
		{"mixed-case-hex", mixedCaseHexEncoding(secret)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactForms(append([]byte(nil), tc.body...), forms, false); string(got) != redacted {
				t.Fatal("equivalent credential encoding survived redaction")
			}
		})
	}
}

func mixedCaseHexEncoding(secret []byte) []byte {
	lower := hex.EncodeToString(secret)
	out := []byte(lower)
	for i := range out {
		if out[i] >= 'a' && out[i] <= 'f' {
			out[i] -= 'a' - 'A'
			return out
		}
	}
	return out
}

func TestBrokerRedactsJSONSolidusEscape(t *testing.T) {
	secret := []byte("ab/cd+EF9kLm")
	forms := credentialForms(grantInjection{style: InjectBearer}, secret)
	defer wipeForms(forms)
	body := []byte(`ab\/cd+EF9kLm`)
	if got := redactForms(append([]byte(nil), body...), forms, false); string(got) != redacted {
		t.Fatalf("JSON solidus escape survived redaction: %q", got)
	}
}

func TestBrokerWithholdsMCPJSONEncodingLeak(t *testing.T) {
	// Credential bytes are a JSON escape spelling; the upstream echoes the preimage.
	secret := []byte(`Q7m\u003ckL2p9`)
	body := []byte(`Q7m<kL2p9`)
	forms := credentialForms(grantInjection{style: InjectBearer}, secret)
	defer wipeForms(forms)
	for _, form := range forms {
		if bytes.Contains(body, form) {
			t.Fatal("fixture body already held a credential form")
		}
	}
	resp, err := projectResponse(grantInjection{style: InjectBearer}, secret, http.Header{}, body, false)
	if err == nil {
		mcpJSON, _ := json.Marshal(brokerBody(resp))
		if containsCredentialForm(mcpJSON, forms) {
			t.Fatal("fixture did not reproduce the MCP JSON encoding leak")
		}
		t.Fatal("MCP JSON credential form was not withheld")
	}
	if !errors.Is(err, ErrBrokerUpstream) || resp.Body != nil {
		t.Fatal("MCP JSON credential form did not fail closed")
	}
}

func TestBrokerOrdinaryResponseUnchanged(t *testing.T) {
	secret := []byte("Sk" + randHex(t, 20) + `/\"&=`)
	body := []byte("upstream ok: no reflection")
	resp, err := projectResponse(grantInjection{style: InjectBearer}, secret, http.Header{
		"Content-Type": []string{"text/plain"},
	}, body, false)
	if err != nil {
		t.Fatalf("ordinary response withheld: %v", err)
	}
	if string(resp.Body) != string(body) {
		t.Fatalf("body %q, want %q", resp.Body, body)
	}
	mcpJSON, err := json.Marshal(brokerBody(resp))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mcpJSON), "upstream ok") {
		t.Fatalf("MCP projection changed ordinary body: %s", mcpJSON)
	}
}

func TestBrokerWithholdsMCPBase64EncodingLeak(t *testing.T) {
	secret := []byte(base64.RawStdEncoding.EncodeToString(randBytesT(t, 18)))
	encoded := "/" + string(secret)
	encoded += strings.Repeat("A", (4-len(encoded)%4)%4)
	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || utf8.Valid(body) {
		t.Fatal("invalid binary response fixture")
	}
	forms := credentialForms(grantInjection{style: InjectBearer}, secret)
	defer wipeForms(forms)
	for _, form := range forms {
		if bytes.Contains(body, form) {
			t.Fatal("binary fixture already held a credential form")
		}
	}

	resp, err := projectResponse(grantInjection{style: InjectBearer}, secret, http.Header{}, body, false)
	if err == nil {
		projected := brokerBody(resp)
		if projected.BodyBase64 == "" || !strings.Contains(projected.BodyBase64, string(secret)) {
			t.Fatal("fixture did not reproduce the MCP encoding leak")
		}
		t.Fatal("MCP base64 credential form was not withheld")
	}
	if !errors.Is(err, ErrBrokerUpstream) || resp.Body != nil {
		t.Fatal("MCP base64 credential form did not fail closed")
	}
}

func TestBrokerCapsExpandedRedaction(t *testing.T) {
	var secret []byte
	for {
		secret = randBytesT(t, 1)
		forms := credentialForms(grantInjection{style: InjectBearer}, secret)
		// A one-byte secret is short enough for one of its spellings to sit
		// inside the marker or the MCP JSON field names ("ea" in "headers"),
		// which is withheld on purpose. This test is about the cap, so draw
		// a byte whose spellings appear in neither.
		scaffold := []byte(redacted + `{"status_code":0,"headers":{},"body":"","body_base64":"","truncated":true}`)
		safeMarker := true
		for _, form := range forms {
			if containsCredentialForm(scaffold, [][]byte{form}) {
				safeMarker = false
			}
		}
		wipeForms(forms)
		if safeMarker {
			break
		}
	}
	body := bytes.Repeat(secret, maxAgentBody)
	resp, err := projectResponse(grantInjection{style: InjectBearer}, secret, http.Header{}, body, false)
	if err != nil {
		t.Fatal("expanded redaction was unexpectedly withheld")
	}
	if len(resp.Body) > maxAgentBody || !resp.Truncated {
		t.Fatal("expanded redaction exceeded the response cap")
	}
}

func TestBrokerPathUnderPrefix(t *testing.T) {
	cases := []struct {
		prefix, path string
		want         bool
	}{
		{"/repos/o/r", "/repos/o/r", true},
		{"/repos/o/r", "/repos/o/r/issues", true},
		{"/repos/o/r", "/repos/o/rx", false},
		{"/repos/o/r", "/repos/o/rx/issues", false},
		{"/repos/o/r", "/repos/o", false},
		{"/repos/o/r", "/", false},
		{"/", "/anything", true},
		{"/", "/", true},
	}
	for _, tc := range cases {
		if got := pathUnderPrefix(tc.prefix, tc.path); got != tc.want {
			t.Fatalf("pathUnderPrefix(%q, %q) = %v", tc.prefix, tc.path, got)
		}
	}
}

// TestBrokerHeaderNameCannotCarryCredential: header names are not scanned for
// credential forms, so no allowlisted name may be upstream-chosen.
func TestBrokerHeaderNameCannotCarryCredential(t *testing.T) {
	secret := []byte(strings.Repeat("7", 32))
	upstream := http.Header{}
	upstream.Set("X-RateLimit-"+string(secret), "1")
	upstream.Set("X-RateLimit-Remaining", "9")
	resp, err := projectResponse(grantInjection{style: InjectBearer}, secret, upstream, []byte("ok"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Headers) != 1 || resp.Headers["X-Ratelimit-Remaining"] != "9" {
		t.Fatalf("headers %v, want only X-Ratelimit-Remaining", resp.Headers)
	}
}

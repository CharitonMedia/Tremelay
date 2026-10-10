package vault

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestReclassifyScopeDeterministic(t *testing.T) {
	const (
		agent = "agent"
		cred  = "cred"
	)
	base := grantRecord{AgentID: agent, CredentialID: cred, Operations: []string{OpHTTPRequest}}
	get := base
	get.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	get.Resource = "GET https://svc.example/v1/ping"
	post := base
	post.ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	post.Resource = "POST https://svc.example/v1/ping"
	other := base
	other.ID = "cccccccccccccccccccccccccccccccc"
	other.Resource = "GET https://other.example/v1/ping"
	legacy := base
	legacy.ID = "dddddddddddddddddddddddddddddddd"
	legacy.Resource = "svc:legacy"

	class, id, ok := reclassifyScope([]grantRecord{get, post}, agent, cred, "api_key", http.MethodHead, "https://svc.example/v1/ping", OpHTTPRequest)
	if !ok || class != resultDeniedMethod || id != get.ID {
		t.Fatalf("head class %s id %s ok %v", class, id, ok)
	}
	class, id, ok = reclassifyScope([]grantRecord{get, post}, agent, cred, "api_key", http.MethodDelete, "https://svc.example/v1/ping", OpHTTPRequest)
	if !ok || class != resultDeniedMethod || id != post.ID {
		t.Fatalf("delete class %s id %s ok %v", class, id, ok)
	}
	class, id, ok = reclassifyScope([]grantRecord{get}, agent, cred, "api_key", http.MethodDelete, "https://svc.example/v1/ping", OpHTTPRequest)
	if !ok || class != resultDeniedAction || id != get.ID {
		t.Fatalf("delete action class %s id %s ok %v", class, id, ok)
	}
	class, id, ok = reclassifyScope([]grantRecord{post}, agent, cred, "api_key", http.MethodPut, "https://svc.example/v1/ping", OpHTTPRequest)
	if !ok || class != resultDeniedMethod || id != post.ID {
		t.Fatalf("put class %s id %s ok %v", class, id, ok)
	}
	class, id, ok = reclassifyScope([]grantRecord{other, get}, agent, cred, "api_key", http.MethodGet, "https://svc.example/v1/admin", OpHTTPRequest)
	if !ok || class != resultDeniedPath || id != get.ID {
		t.Fatalf("path class %s id %s ok %v", class, id, ok)
	}
	class, id, ok = reclassifyScope([]grantRecord{other, legacy}, agent, cred, "api_key", http.MethodGet, "https://svc.example/v1/ping", OpHTTPRequest)
	if !ok || class != resultDeniedOrigin || id != other.ID {
		t.Fatalf("origin class %s id %s ok %v", class, id, ok)
	}
	if _, _, ok = reclassifyScope([]grantRecord{legacy}, agent, cred, "api_key", http.MethodGet, "https://svc.example/v1/ping", OpHTTPRequest); ok {
		t.Fatal("non-http resource was classified as an HTTP policy")
	}
	far := other
	far.ID = "00000000000000000000000000000000"
	far.Resource = "GET https://zzz.example/v1/ping"
	near := other
	near.ID = "ffffffffffffffffffffffffffffffff"
	near.Resource = "GET https://aaa.example/v1/ping"
	class, id, ok = reclassifyScope([]grantRecord{near, far}, agent, cred, "api_key", http.MethodGet, "https://svc.example/v1/ping", OpHTTPRequest)
	if !ok || class != resultDeniedOrigin || id != far.ID {
		t.Fatalf("tie class %s id %s ok %v", class, id, ok)
	}
	if transmissionAuthorized(resultDeniedMethod) || !transmissionAuthorized(resultAllowed) || transmissionAuthorized(resultDeniedRedirect) {
		t.Fatal("transmission flag drifted")
	}
}

func TestBrokerPolicyMismatchBeforeNetwork(t *testing.T) {
	e := newBrokerEnv(t)
	const target = "https://svc.example/v1/ping"
	cases := []struct {
		method string
		target string
		cred   string
		want   error
	}{
		{http.MethodGet, "https://other.example/v1/ping", e.apiID, ErrDeniedOrigin},
		{http.MethodGet, "https://svc.example:8443/v1/ping", e.apiID, ErrDeniedOrigin},
		{http.MethodGet, "http://svc.example/v1/ping", e.apiID, ErrDeniedOrigin},
		{http.MethodGet, "https://1.1.1.1/v1/ping", e.apiID, ErrDeniedOrigin},
		{http.MethodGet, "https://[2001:4860:4860::8888]/v1/ping", e.apiID, ErrDeniedOrigin},
		{http.MethodGet, "https://svc.example/v1/ping/extra", e.apiID, ErrDeniedPath},
		{http.MethodGet, "https://svc.example/v1", e.apiID, ErrDeniedPath},
		{http.MethodGet, "https://svc.example/v1/ping?x=1", e.apiID, ErrDeniedPath},
		{http.MethodHead, target, e.apiID, ErrDeniedMethod},
		{http.MethodPut, "https://svc.example/v1/submit", e.apiID, ErrDeniedMethod},
		{http.MethodDelete, target, e.apiID, ErrDeniedAction},
		{http.MethodGet, "https://user:secret@svc.example/v1/ping", e.apiID, ErrDeniedMalformed},
		{http.MethodGet, "https://svc.example/v1/../admin", e.apiID, ErrDeniedMalformed},
		{http.MethodGet, "https://127.0.0.1/latest", e.apiID, ErrDeniedSSRF},
		{http.MethodGet, "https://192.88.99.2/latest", e.apiID, ErrDeniedSSRF},
		{http.MethodGet, "https://[fd00::1]/", e.apiID, ErrDeniedSSRF},
		{http.MethodGet, "https://metadata.google.internal/latest", e.apiID, ErrDeniedSSRF},
	}
	for _, tc := range cases {
		e.deny(t, HTTPBrokerRequest{CredentialID: tc.cred, Method: tc.method, Target: tc.target}, tc.want)
	}
	before := len(e.session.audit)
	e.session.clock = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: target}, ErrDeniedExpired)
	e.session.clock = nil
	caps, err := e.principal.Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range caps {
		if c.Resource == "GET "+target {
			if err := e.session.RevokeGrant(c.GrantID); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: target}, ErrDeniedRevoked)
	bare, err := e.session.CreateAgent("bare")
	if err != nil {
		t.Fatal(err)
	}
	barePrincipal, err := e.session.Agent(bare.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := barePrincipal.BrokerHTTP(HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: target}); !errors.Is(err, ErrDeniedAgent) {
		t.Fatal(err)
	}
	if result, _ := decideAccess(nil, true, e.agentID, e.apiID, "api_key", true, OpHTTPRequest, "GET "+target, time.Now()); result != resultDeniedMissing {
		t.Fatalf("missing grant %s", result)
	}
	for _, ev := range e.session.audit[before:] {
		if ev.Action == actionBroker && transmissionAuthorized(ev.Result) {
			t.Fatalf("denial transmitted: %s", ev.Result)
		}
	}
	if _, err := e.session.IssueGrant(GrantSpec{
		AgentID: e.agentID, CredentialID: e.apiID, Operations: []string{OpHTTPRequest},
		Resource: "GET https://svc.example/v1/*", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err == nil {
		t.Fatal("wildcard grant was accepted")
	}
}

func TestBrokerDNSPinAndProxy(t *testing.T) {
	e := newBrokerEnv(t)
	const target = "https://svc.example/v1/ping"
	good := HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: target}
	e.session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("credential-bearing request")
		return nil, errors.New("network")
	}
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		return nil, nil
	}
	e.deny(t, good, ErrDeniedDestination)
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1")}, nil
	}
	e.deny(t, good, ErrDeniedSSRF)
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("192.88.99.2")}, nil
	}
	e.deny(t, good, ErrDeniedSSRF)

	var ip net.IP
	lookups := 0
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		lookups++
		if lookups == 1 {
			ip = append(net.IP(nil), net.ParseIP("1.1.1.1").To4()...)
			return []net.IP{ip}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	var dialed string
	e.session.httpDo = nil
	e.session.dial = func(_ context.Context, network, addr string) (net.Conn, error) {
		dialed = network + " " + addr
		return nil, errors.New("stop " + string(e.secret))
	}
	if err := e.session.SetAbuseGuard(func(d AbuseDecision) error {
		if d.Class == resultAllowed && ip != nil {
			copy(ip, net.ParseIP("10.0.0.1").To4())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	res, err := e.principal.BrokerHTTP(good)
	if !errors.Is(err, ErrBrokerUpstream) || res.StatusCode != 0 || secretIn(err.Error(), e.secret) {
		t.Fatalf("pin status %d err %v", res.StatusCode, err)
	}
	if lookups != 1 || dialed != "tcp 1.1.1.1:443" {
		t.Fatalf("lookups %d dialed %s", lookups, dialed)
	}
	var sawAllowed bool
	for _, ev := range e.session.audit {
		if ev.Action == actionBroker && ev.Result == resultAllowed {
			sawAllowed = true
		}
		if secretIn(ev.Result+ev.Operation, e.secret) {
			t.Fatal("audit secret")
		}
	}
	if !sawAllowed {
		t.Fatal("pin failure lost the pre-send audit")
	}

	e.session.SetAbuseGuard(nil)
	lookups = 0
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		lookups++
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")}, nil
	}
	dialed = ""
	_, err = e.principal.BrokerHTTP(good)
	if !errors.Is(err, ErrBrokerUpstream) || dialed != "tcp 8.8.8.8:443" || lookups != 1 {
		t.Fatalf("first pin lookups %d dialed %s err %v", lookups, dialed, err)
	}

	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:9")
	var got []string
	tr, err := pinnedTransportDial(net.ParseIP("1.1.1.1"), "443", func(_ context.Context, network, addr string) (net.Conn, error) {
		got = append(got, network+" "+addr)
		return nil, errors.New("stop")
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := tr.Proxy(req)
	if err != nil || proxy != nil || tr.TLSClientConfig != nil {
		t.Fatalf("proxy %v tls %v err %v", proxy, tr.TLSClientConfig, err)
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "10.0.0.1:443"); err == nil || len(got) != 1 || got[0] != "tcp 1.1.1.1:443" {
		t.Fatalf("dial %v %v", got, err)
	}
	if _, err := tr.DialContext(context.Background(), "udp", "1.1.1.1:443"); !errors.Is(err, errDestination) {
		t.Fatal(err)
	}
	if _, err := pinnedTransportDial(net.ParseIP("192.88.99.2"), "443", func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialed 6to4")
		return nil, errors.New("dial")
	}); !errors.Is(err, errDestination) {
		t.Fatal(err)
	}
	raw := net.ParseIP("1.1.1.1").To4()
	copied := normalizeIP(raw)
	raw[0] = 10
	if copied[0] != 1 {
		t.Fatal("pin aliased the resolver address")
	}
}

func TestBrokerRedirectsDoNotInherit(t *testing.T) {
	e := newBrokerEnv(t)
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	good := HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://svc.example/v1/ping"}
	locations := []string{
		"https://svc.example/v1/next",
		"https://evil.example/steal",
		"http://svc.example/v1/ping",
		"https://svc.example:8443/v1/ping",
		"/v1/admin",
		"../admin",
		"//evil.example/x",
		"https://127.0.0.1/latest",
		"https://169.254.169.254/latest",
		"https://[::1]/",
		"https://evil.example/" + string(e.secret),
	}
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, loc := range locations {
			calls := 0
			e.session.httpDo = func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Host != "svc.example" || req.Header.Get("Authorization") == "" {
					t.Fatal("redirect left the granted origin")
				}
				return &http.Response{
					StatusCode: code,
					Header:     http.Header{"Location": []string{loc}},
					Body:       io.NopCloser(strings.NewReader(string(e.secret))),
				}, nil
			}
			res, err := e.principal.BrokerHTTP(good)
			if !errors.Is(err, ErrDeniedRedirect) || res.StatusCode != 0 || calls != 1 || secretIn(err.Error(), e.secret) {
				t.Fatalf("code %d loc %s calls %d status %d err %v", code, loc, calls, res.StatusCode, err)
			}
		}
	}
	req, err := http.NewRequest(http.MethodGet, good.Target, nil)
	if err != nil {
		t.Fatal(err)
	}
	via := []*http.Request{req, req, req}
	if err := refuseRedirect(req, via); !errors.Is(err, errRedirectRefused) {
		t.Fatal(err)
	}
	if err := brokerClient(&http.Transport{Proxy: refuseProxy}).CheckRedirect(req, via); !errors.Is(err, errRedirectRefused) {
		t.Fatal(err)
	}
	for _, ev := range e.session.audit {
		fields := ev.Action + ev.Result + ev.Operation + ev.AgentID + ev.GrantID
		if secretIn(fields, e.secret) || strings.Contains(fields, "evil.example") || strings.Contains(fields, "Location") {
			t.Fatal("redirect audit recorded caller text")
		}
	}
	var allowed, redirected bool
	for _, ev := range e.session.audit {
		if ev.Action != actionBroker {
			continue
		}
		if ev.Result == resultAllowed {
			allowed = true
		}
		if ev.Result == resultDeniedRedirect {
			redirected = true
		}
		if ev.Result == resultCompleted {
			t.Fatal("redirect completed")
		}
	}
	if !allowed || !redirected {
		t.Fatal("redirect audit missing allowed or denied_redirect")
	}
}

func TestAbuseGuardVeto(t *testing.T) {
	e := newBrokerEnv(t)
	const (
		get  = "https://svc.example/v1/ping"
		post = "https://svc.example/v1/submit"
	)
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	e.session.httpDo = func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			t.Fatal("write was sent")
		}
		return &http.Response{StatusCode: 204, Body: http.NoBody, Header: make(http.Header)}, nil
	}
	var seen []string
	if err := e.session.SetAbuseGuard(func(d AbuseDecision) error {
		blob := d.AgentID + d.GrantID + d.CredentialID + d.Action + d.Class
		if strings.Contains(blob, "svc.example") || strings.Contains(blob, "http") || secretIn(blob, e.secret) {
			t.Fatal("hook saw a url or secret")
		}
		seen = append(seen, d.Class+"/"+d.Action)
		if d.Class == resultAllowed && d.Action == actionWrite {
			return errors.New("limit " + string(e.secret))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	res, err := e.principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: get})
	if err != nil || res.StatusCode != 204 {
		t.Fatalf("read %d %v", res.StatusCode, err)
	}
	res, err = e.principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodPost, Target: post})
	if !errors.Is(err, ErrDeniedAbuse) || res.StatusCode != 0 || secretIn(err.Error(), e.secret) {
		t.Fatalf("write %d %v", res.StatusCode, err)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	if err := e.session.SetAbuseGuard(func(AbuseDecision) error {
		return errors.New("always")
	}); err != nil {
		t.Fatal(err)
	}
	e.session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("ssrf veto changed the denial into a send")
		return nil, errors.New("network")
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://10.0.0.1/"}, ErrDeniedSSRF)
	locked := e.session
	locked.Lock()
	if err := locked.SetAbuseGuard(nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	joined := strings.Join(seen, ",")
	if !strings.Contains(joined, resultAllowed+"/"+actionRead) || !strings.Contains(joined, resultDeniedSSRF+"/") {
		t.Fatalf("hook observations %s", joined)
	}
	if _, err := VerifyAudit(e.path, e.pass); err != nil {
		t.Fatal(err)
	}
	if secretIn(e.logs.String(), e.secret) || secretIn(string(readAll(t, e.path)), e.secret) {
		t.Fatal("secret in logs or vault")
	}
}

type brokerEnv struct {
	session   *Session
	principal *AgentPrincipal
	agentID   string
	apiID     string
	secret    []byte
	path      string
	pass      []byte
	logs      *bytes.Buffer
}

func newBrokerEnv(t *testing.T) brokerEnv {
	t.Helper()
	logs := &bytes.Buffer{}
	path, pass, session := mustCreate(t, log.New(logs, "", 0))
	secret := []byte(randHex(t, 24))
	api, err := session.Put("api", "api_key", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := session.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().UTC().Add(time.Hour)
	for _, resource := range []string{"GET https://svc.example/v1/ping", "POST https://svc.example/v1/submit"} {
		if _, err := session.IssueGrant(GrantSpec{
			AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest},
			Resource: resource, ExpiresAt: exp,
		}); err != nil {
			t.Fatal(err)
		}
	}
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("dns before policy denial")
		return nil, errors.New("dns")
	}
	session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("network before policy denial")
		return nil, errors.New("network")
	}
	session.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dial before policy denial")
		return nil, errors.New("dial")
	}
	return brokerEnv{session: session, principal: principal, agentID: agent.ID, apiID: api.ID, secret: secret, path: path, pass: pass, logs: logs}
}

func (e brokerEnv) deny(t *testing.T, req HTTPBrokerRequest, want error) {
	t.Helper()
	res, err := e.principal.BrokerHTTP(req)
	if !errors.Is(err, want) || res.StatusCode != 0 {
		t.Fatalf("%s %s: status %d err %v", req.Method, req.Target, res.StatusCode, err)
	}
	if secretIn(err.Error(), e.secret) {
		t.Fatal("secret in error")
	}
}

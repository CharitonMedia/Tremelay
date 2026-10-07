package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClassifyAndPublicDestination(t *testing.T) {
	const okURL = "https://svc.example/v1/ping"
	resource, host, port, class := classifyTarget(http.MethodGet, okURL)
	if class != targetOK || resource != "GET "+okURL || host != "svc.example" || port != "443" {
		t.Fatalf("class %d resource %s host %s port %s", class, resource, host, port)
	}
	classified := []struct {
		target string
		class  int
	}{
		{"https://127.0.0.1/latest", targetSSRF},
		{"https://user@127.0.0.1/latest", targetSSRF},
		{"https://127.0.0.1/", targetSSRF},
		{"https://localhost/latest", targetSSRF},
		{"https://LOCALHOST/latest", targetSSRF},
		{"https://db.localhost/latest", targetSSRF},
		{"https://printer.local/latest", targetSSRF},
		{"https://metadata.google.internal/latest", targetSSRF},
		{"https://name.invalid/latest", targetSSRF},
		{"https://name.test/latest", targetSSRF},
		{"https://[::1]/", targetSSRF},
		{"https://[fe80::1]/", targetSSRF},
		{"https://[fd00::1]/", targetSSRF},
		{"https://169.254.169.254/latest", targetSSRF},
		{"https://10.0.0.1/", targetSSRF},
		{"https://192.168.1.20/", targetSSRF},
		{"https://172.16.0.1/", targetSSRF},
		{"https://0.0.0.0/", targetSSRF},
		{"https://2130706433/", targetSSRF},
		{"https://0177.0.0.1/", targetSSRF},
		{"https://0x7f.0.0.1/", targetSSRF},
		{"https://127.1/", targetSSRF},
		{"https://192.88.99.2/", targetSSRF},
		{"http://svc.example/v1/ping", targetOrigin},
		{"https://1.1.1.1/v1/ping", targetOrigin},
		{"https://user:secret@svc.example/v1/ping", targetMalformed},
		{"https://svc.example/v1/../admin", targetMalformed},
		{"https://svc.example/v1/./ping", targetMalformed},
		{"https://svc.example/v1/ping%2fadmin", targetMalformed},
		{"https://svc.example\\@evil.example/v1/ping", targetMalformed},
		{"https://svc.example/v1/ping#frag", targetMalformed},
		{"https://SVC.example/v1/ping", targetMalformed},
		{"https://svc.example./v1/ping", targetMalformed},
		{"https://svc.example:443/v1/ping", targetMalformed},
		{"https://svc.example", targetMalformed},
		{"HTTPS://svc.example/v1/ping", targetMalformed},
	}
	for _, tc := range classified {
		if _, _, _, got := classifyTarget(http.MethodGet, tc.target); got != tc.class {
			t.Fatalf("%s class %d want %d", tc.target, got, tc.class)
		}
	}
	invalid := []string{"", "not-a-url", "https://svc.example/*", "https://svc.example/v1/ping\n"}
	for _, target := range invalid {
		if _, _, _, got := classifyTarget(http.MethodGet, target); got != targetInvalid {
			t.Fatalf("%s class %d", target, got)
		}
	}
	if _, _, _, got := classifyTarget("TRACE", okURL); got != targetInvalid {
		t.Fatalf("TRACE class %d", got)
	}
	if _, _, _, got := classifyTarget(http.MethodPost, "https://evil.example/v1/ping"); got != targetOK {
		t.Fatal("alternate origin should stay syntactically brokerable")
	}
	if _, host, _, got := classifyTarget(http.MethodGet, "https://rebind.nip.io/latest"); got != targetOK || host != "rebind.nip.io" {
		t.Fatal("rebinding name was rejected before DNS")
	}
	public := []string{"1.1.1.1", "8.8.8.8", "192.88.98.1", "192.88.98.255", "192.88.100.0", "192.88.100.1", "192.0.1.1", "100.63.255.255", "100.128.0.0", "198.17.255.255", "198.20.0.0", "192.31.195.255", "192.31.197.0", "2001:4860:4860::8888", "2606:4700:4700::1111", "3ff1::1", "3ff0::1", "3fff:1000::1", "2620:4f:8001::1"}
	for _, raw := range public {
		if !isPublicIP(net.ParseIP(raw)) {
			t.Fatal(raw)
		}
	}
	private := []string{
		"127.0.0.1", "127.0.0.2", "::1", "10.1.2.3", "192.168.0.1", "172.16.0.1",
		"169.254.169.254", "0.0.0.0", "100.64.0.1", "255.255.255.255", "224.0.0.1",
		"::ffff:127.0.0.1", "fe80::1", "fc00::1", "fd00::1", "2001:db8::1", "2002::1",
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "192.88.99.0", "192.88.99.1", "192.88.99.2", "192.88.99.255", "::ffff:192.88.99.1", "::ffff:192.88.99.2",
		"192.31.196.1", "192.52.193.1", "192.175.48.1", "198.18.0.1", "198.19.255.255", "100.64.0.1", "100.127.255.255", "240.0.0.1", "192.0.0.8",
		"fec0::1", "64:ff9b::1", "64:ff9b:1::1", "100::1", "100:0:0:1::1",
		"2001::1", "2001:2::1", "3fff::1", "3fff:fff::1", "5f00::1", "2620:4f:8000::1", "4000::1",
	}
	for _, raw := range private {
		if isPublicIP(net.ParseIP(raw)) {
			t.Fatal(raw)
		}
	}
	if isPublicIP(nil) || publicIPs(nil) || publicIPs([]net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1")}) {
		t.Fatal("mixed or empty addresses were accepted")
	}
	got, err := pinTarget(net.ParseIP("1.1.1.1"), "443")
	if err != nil || got != "1.1.1.1:443" {
		t.Fatalf("pin %s %v", got, err)
	}
	if _, err := pinTarget(net.ParseIP("10.0.0.1"), "443"); !errors.Is(err, errDestination) {
		t.Fatal(err)
	}
	if _, err := pinTarget(net.ParseIP("192.88.99.1"), "443"); !errors.Is(err, errDestination) {
		t.Fatal(err)
	}
	if _, err := pinTarget(net.ParseIP("192.88.99.2"), "443"); !errors.Is(err, errDestination) {
		t.Fatal(err)
	}
	if _, err := pinTarget(net.ParseIP("::ffff:1.1.1.1"), "443"); err != nil {
		t.Fatal(err)
	}
	if err := refuseRedirect(nil, nil); !errors.Is(err, errRedirectRefused) {
		t.Fatal(err)
	}
}

func TestBrokerAuditShape(t *testing.T) {
	vaultID := strings.Repeat("ab", 16)
	agentID := strings.Repeat("cd", 16)
	grantID := strings.Repeat("ef", 16)
	credID := strings.Repeat("12", 16)
	create, err := nextEvent(nil, actionCreate, vaultID, "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	base := auditEvent{
		Action: actionBroker, AgentID: agentID, GrantID: grantID, CredID: credID,
		CredType: "api_key", Operation: OpHTTPRequest,
	}
	var chain []auditEvent
	chain = append(chain, create)
	for _, result := range []string{
		resultAllowed, resultCompleted, resultUpstreamError, resultDeniedDestination, resultDeniedScope,
		resultDeniedOrigin, resultDeniedSSRF, resultDeniedRedirect, resultDeniedMethod, resultDeniedPath,
		resultDeniedAction, resultDeniedMalformed, resultDeniedAbuse,
	} {
		ev := base
		ev.Result = result
		if result == resultDeniedDestination || result == resultDeniedScope {
			ev.GrantID = ""
		}
		next, err := nextAudit(chain, vaultID, ev)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, next)
		if err := verifyChain(chain); err != nil {
			t.Fatalf("%s: %v", result, err)
		}
	}
	bad := base
	bad.Result = resultCompleted
	bad.Operation = "https://evil.example/secret"
	next, err := nextAudit(chain, vaultID, bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(append(chain, next)); !errors.Is(err, ErrAudit) {
		t.Fatalf("free-form operation: %v", err)
	}
	bad.Operation = OpHTTPRequest
	bad.Result = "https://evil.example/secret"
	next, err = nextAudit(chain, vaultID, bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(append(chain, next)); !errors.Is(err, ErrAudit) {
		t.Fatalf("free-form result: %v", err)
	}
	bad = base
	bad.Result = resultDeniedAbuse
	bad.GrantID = ""
	next, err = nextAudit(chain, vaultID, bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(append(chain, next)); !errors.Is(err, ErrAudit) {
		t.Fatalf("abuse row without grant: %v", err)
	}
}

func TestBrokerHTTP(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	secret := []byte(randHex(t, 24))
	otherSecret := []byte(randHex(t, 24))
	api, err := session.Put("api", "api_key", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := session.Put("other", "api_key", otherSecret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unsafeSecret := append([]byte("nope\r\nX-Injected: "), secret...)
	unsafe, err := session.Put("unsafe", "generic", unsafeSecret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pwSecret := []byte(randHex(t, 24))
	pw, err := session.Put("pw", "password", pwSecret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := session.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	otherAgent, err := session.CreateAgent("other")
	if err != nil {
		t.Fatal(err)
	}
	bare, err := session.CreateAgent("bare")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherPrincipal, err := session.Agent(otherAgent.ID)
	if err != nil {
		t.Fatal(err)
	}
	barePrincipal, err := session.Agent(bare.ID)
	if err != nil {
		t.Fatal(err)
	}
	const target = "https://svc.example/v1/ping"
	const resource = "GET " + target
	exp := time.Now().UTC().Add(time.Hour)
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("dns ran before a grant existed")
		return nil, errors.New("dns")
	}
	session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("network ran before a grant existed")
		return nil, errors.New("network")
	}
	if _, err := barePrincipal.BrokerHTTP(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: target}); !errors.Is(err, ErrDeniedMissing) {
		t.Fatal(err)
	}
	grant, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest},
		Resource: resource, ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: otherAgent.ID, CredentialID: api.ID, Operations: []string{OpSign},
		Resource: resource, ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialClass: "password", Operations: []string{OpHTTPRequest},
		Resource: "POST https://svc.example/v1/submit", ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}
	once, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest},
		Resource: "GET https://127.0.0.1/latest", ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = once
	nip, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest},
		Resource: "GET https://rebind.nip.io/latest", ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = nip
	revoked, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest},
		Resource: "GET https://svc.example/v1/once", ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}

	var calls int
	var sawAllowedBeforeSend bool
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	session.httpDo = func(req *http.Request) (*http.Response, error) {
		calls++
		for _, ev := range session.audit {
			if ev.Action == actionBroker && ev.Result == resultAllowed {
				sawAllowedBeforeSend = true
			}
		}
		if !sawAllowedBeforeSend {
			t.Fatal("credential-bearing request preceded the allowed audit")
		}
		if req.Header.Get("Authorization") != "Bearer "+string(secret) {
			t.Fatal("upstream authorization mismatch")
		}
		if strings.Contains(req.URL.String(), string(secret)) || req.URL.User != nil {
			t.Fatal("credential in outbound URL")
		}
		if len(req.Header) != 1 {
			t.Fatal("agent-controlled headers were forwarded")
		}
		return &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    req,
		}, nil
	}
	res, err := principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || calls != 1 {
		t.Fatalf("status %d calls %d", res.StatusCode, calls)
	}
	encoded, err := json.Marshal(res)
	if err != nil || string(encoded) != `{"StatusCode":200}` || bytes.Contains(encoded, secret) || bytes.Contains(encoded, []byte(`{"ok":true}`)) {
		t.Fatalf("broker result %s", encoded)
	}
	res, err = principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: target})
	if err != nil || res.StatusCode != 200 || calls != 2 {
		t.Fatalf("replay status %d calls %d err %v", res.StatusCode, calls, err)
	}

	session.httpDo = func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPost || req.Header.Get("Authorization") != "Bearer "+string(pwSecret) {
			t.Fatal("class grant used the wrong credential")
		}
		if strings.Contains(req.Header.Get("Authorization"), string(secret)) {
			t.Fatal("class grant forwarded the other credential")
		}
		return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader("saved")), Header: make(http.Header)}, nil
	}
	res, err = principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: pw.ID, Method: http.MethodPost, Target: "https://svc.example/v1/submit"})
	if err != nil || res.StatusCode != 201 {
		t.Fatalf("class broker %d %v", res.StatusCode, err)
	}
	if encoded, err := json.Marshal(res); err != nil || bytes.Contains(encoded, []byte("saved")) {
		t.Fatal("class broker returned the upstream body")
	}

	denyNet := func() {
		t.Helper()
		session.httpDo = func(*http.Request) (*http.Response, error) {
			t.Fatal("credential-bearing network use")
			return nil, errors.New("network")
		}
	}
	denyDNS := func() {
		t.Helper()
		session.resolve = func(context.Context, string) ([]net.IP, error) {
			t.Fatal("dns before authorization")
			return nil, errors.New("dns")
		}
	}
	expect := func(req HTTPBrokerRequest, who *AgentPrincipal, want error) {
		t.Helper()
		before := calls
		res, err := who.BrokerHTTP(req)
		if !errors.Is(err, want) || res.StatusCode != 0 || calls != before {
			t.Fatalf("res %d calls %d err %v", res.StatusCode, calls, err)
		}
		if secretIn(err.Error(), secret, otherSecret, pwSecret, unsafeSecret) {
			t.Fatal("credential in broker error")
		}
	}
	good := HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: target}
	denyNet()
	denyDNS()
	expect(HTTPBrokerRequest{CredentialID: other.ID, Method: http.MethodGet, Target: target}, principal, ErrDeniedCredential)
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: other.ID, Operations: []string{OpHTTPRequest},
		Resource: "svc:legacy", ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}
	expect(HTTPBrokerRequest{CredentialID: other.ID, Method: http.MethodGet, Target: target}, principal, ErrDeniedScope)
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodHead, Target: target}, principal, ErrDeniedMethod)
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodDelete, Target: target}, principal, ErrDeniedAction)
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodPost, Target: target}, principal, ErrDeniedAction)
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: "https://evil.example/v1/ping"}, principal, ErrDeniedOrigin)
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: "https://svc.example/v1/admin"}, principal, ErrDeniedPath)
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: "https://svc.example/v1/ping?x=" + string(secret)}, principal, ErrDeniedPath)
	expect(good, otherPrincipal, ErrDeniedOperation)
	expect(good, barePrincipal, ErrDeniedAgent)
	expect(HTTPBrokerRequest{CredentialID: string(secret), Method: http.MethodGet, Target: target}, principal, ErrInvalid)
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: "TRACE", Target: target}, principal, ErrInvalid)
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: ""}, principal, ErrInvalid)
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: "https://svc.example/*"}, principal, ErrInvalid)
	ssrf := []string{
		"https://127.0.0.1/latest",
		"https://127.0.0.1/",
		"https://localhost/latest",
		"https://[::1]/",
		"https://169.254.169.254/latest",
		"https://10.0.0.1/",
		"https://192.168.1.20/",
		"https://172.16.0.1/",
		"https://0.0.0.0/",
		"https://[fe80::1]/",
		"https://[fd00::1]/",
		"https://2130706433/",
		"https://0177.0.0.1/",
		"https://0x7f.0.0.1/",
		"https://metadata.google.internal/latest",
		"https://192.88.99.2/latest",
	}
	for _, raw := range ssrf {
		expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: raw}, principal, ErrDeniedSSRF)
	}
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: "http://svc.example/v1/ping"}, principal, ErrDeniedOrigin)
	for _, raw := range []string{
		"https://user:" + string(secret) + "@svc.example/v1/ping",
		"https://svc.example/v1/../admin",
		"https://svc.example/v1/ping%2fadmin",
		`https://svc.example\@evil.example/v1/ping`,
		"https://svc.example/v1/ping#x",
		"https://SVC.example/v1/ping",
		"https://svc.example:443/v1/ping",
	} {
		expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: raw}, principal, ErrDeniedMalformed)
	}

	var lookups int
	session.resolve = func(_ context.Context, host string) ([]net.IP, error) {
		lookups++
		if host != "rebind.nip.io" {
			t.Fatalf("resolved %s", host)
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: "https://rebind.nip.io/latest"}, principal, ErrDeniedSSRF)
	if lookups != 1 {
		t.Fatalf("rebind lookups %d", lookups)
	}
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1")}, nil
	}
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: target}, principal, ErrDeniedSSRF)
	for _, raw := range []string{"fec0::1", "64:ff9b::c000:201", "64:ff9b:1::1", "100::1", "2001:2::1", "3fff::1", "3fff:fff::1", "192.88.99.0", "192.88.99.1", "192.88.99.2", "192.88.99.255"} {
		session.resolve = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP(raw)}, nil
		}
		session.httpDo = func(*http.Request) (*http.Response, error) {
			t.Fatal("non-public address was dialed")
			return nil, errors.New("network")
		}
		expect(good, principal, ErrDeniedSSRF)
	}
	for _, raw := range []string{"3ff1::1", "3fff:1000::1", "192.88.98.1", "192.88.100.1"} {
		session.resolve = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP(raw)}, nil
		}
		session.httpDo = func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("public")), Header: make(http.Header)}, nil
		}
		res, err = principal.BrokerHTTP(good)
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("%s was refused: %v", raw, err)
		}
	}
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return nil, errors.New("lookup " + string(secret))
	}
	expect(good, principal, ErrDeniedDestination)
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}

	redirects := 0
	session.httpDo = func(req *http.Request) (*http.Response, error) {
		redirects++
		if req.URL.Host != "svc.example" {
			t.Fatal("redirect forwarded the credential")
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://evil.example/steal"}},
			Body:       io.NopCloser(strings.NewReader(string(secret))),
		}, nil
	}
	expect(good, principal, ErrDeniedRedirect)
	if redirects != 1 {
		t.Fatalf("redirect calls %d", redirects)
	}
	for _, code := range []int{http.StatusMovedPermanently, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		redirects = 0
		session.httpDo = func(*http.Request) (*http.Response, error) {
			redirects++
			return &http.Response{
				StatusCode: code,
				Header:     http.Header{"Location": []string{"https://svc.example/v1/next"}},
				Body:       io.NopCloser(strings.NewReader("next")),
			}, nil
		}
		expect(good, principal, ErrDeniedRedirect)
		if redirects != 1 {
			t.Fatalf("chain status %d calls %d", code, redirects)
		}
	}
	session.httpDo = func(*http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Get", URL: "https://evil.example/" + string(secret), Err: errRedirectRefused}
	}
	expect(good, principal, ErrDeniedRedirect)
	session.httpDo = func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial " + string(secret))
	}
	expect(good, principal, ErrBrokerUpstream)
	for _, body := range []string{
		"echo " + string(secret),
		"Bearer " + string(secret),
		base64.StdEncoding.EncodeToString(secret),
		base64.URLEncoding.EncodeToString(append([]byte("Bearer "), secret...)),
	} {
		session.httpDo = func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		res, err = principal.BrokerHTTP(good)
		encoded, mErr := json.Marshal(res)
		if err != nil || mErr != nil || string(encoded) != `{"StatusCode":200}` || bytes.Contains(encoded, secret) || strings.Contains(string(encoded), body) {
			t.Fatalf("reflected body returned %s err %v", encoded, err)
		}
	}

	denyNet()
	expect(HTTPBrokerRequest{CredentialID: unsafe.ID, Method: http.MethodGet, Target: target}, principal, ErrDeniedCredential)
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: unsafe.ID, Operations: []string{OpHTTPRequest},
		Resource: resource, ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe credential was sent")
		return nil, errors.New("network")
	}
	expect(HTTPBrokerRequest{CredentialID: unsafe.ID, Method: http.MethodGet, Target: target}, principal, ErrBrokerUpstream)

	session.clock = func() time.Time { return exp }
	session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("expired grant was used")
		return nil, errors.New("network")
	}
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("dns after expiry")
		return nil, errors.New("dns")
	}
	expect(good, principal, ErrDeniedExpired)
	session.clock = nil

	if err := session.RevokeGrant(revoked.ID); err != nil {
		t.Fatal(err)
	}
	expect(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: "https://svc.example/v1/once"}, principal, ErrDeniedRevoked)

	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	session.httpDo = func(*http.Request) (*http.Response, error) {
		session.commitFault = func() error { return errors.New("induced") }
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("hidden")), Header: make(http.Header)}, nil
	}
	res, err = principal.BrokerHTTP(good)
	session.commitFault = nil
	if !errors.Is(err, ErrAudit) || res.StatusCode != 0 || secretIn(err.Error(), secret) {
		t.Fatalf("withheld %d %v", res.StatusCode, err)
	}

	want := map[string]bool{
		resultAllowed: true, resultCompleted: true, resultDeniedDestination: true,
		resultDeniedScope: true, resultDeniedExpired: true, resultDeniedRevoked: true,
		resultDeniedMissing: true, resultDeniedOperation: true, resultUpstreamError: true,
		resultDenied: true, resultDeniedAgent: true, resultDeniedCredential: true,
		resultDeniedOrigin: true, resultDeniedSSRF: true, resultDeniedRedirect: true,
		resultDeniedMethod: true, resultDeniedPath: true, resultDeniedAction: true,
		resultDeniedMalformed: true,
	}
	got := map[string]bool{}
	for _, ev := range session.audit {
		if ev.Action == actionBroker {
			got[ev.Result] = true
		}
		fields := strings.Join([]string{ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation, ev.Class, ev.Time, ev.Prev, ev.Hash}, "\n")
		if secretIn(fields, secret, otherSecret, pwSecret, unsafeSecret) {
			t.Fatal("audit recorded credential material")
		}
	}
	for result := range want {
		if !got[result] {
			t.Fatalf("missing broker audit %s", result)
		}
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
	raw := readAll(t, path)
	for _, blob := range [][]byte{raw, logs.Bytes()} {
		if secretIn(string(blob), secret, otherSecret, pwSecret, unsafeSecret) {
			t.Fatal("credential in plaintext persistence or logs")
		}
	}
	for _, env := range os.Environ() {
		if secretIn(env, secret, otherSecret, pwSecret, unsafeSecret) {
			t.Fatal("credential in environment")
		}
	}
	if grant.ID == "" {
		t.Fatal("grant id")
	}
}

func TestBrokerReturnsStatusOnly(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	secret := []byte(`tok"en\x<a/b`)
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
	const target = "https://svc.example/v1/ping"
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest},
		Resource: "GET " + target, ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	quoted, err := json.Marshal(string(secret))
	if err != nil || len(quoted) < 2 {
		t.Fatal(err)
	}
	inner := quoted[1 : len(quoted)-1]
	bearer := append([]byte("Bearer "), secret...)
	wrapped := base64.StdEncoding.EncodeToString(secret)
	var folded strings.Builder
	for i := 0; i < len(wrapped); i += 8 {
		if i > 0 {
			folded.WriteByte('\n')
		}
		end := i + 8
		if end > len(wrapped) {
			end = len(wrapped)
		}
		folded.WriteString(wrapped[i:end])
	}
	twice, err := json.Marshal(string(quoted))
	if err != nil {
		t.Fatal(err)
	}
	percent := url.QueryEscape(string(secret))
	nested := string(secret)
	for range 7 {
		nested = base64.StdEncoding.EncodeToString([]byte(nested))
	}
	tabbed := []byte(`tok\ten"x`)
	bodies := []string{
		`{"ok":true,"path":"C:\\temp","next":"https://cdn.example/a%2Fb","blob":"` + base64.StdEncoding.EncodeToString([]byte("hello-not-the-credential")) + `"}`,
		string(secret),
		string(inner),
		`tok\"en\\x<a\/b`,
		`tok\u0022en\u005cx<a/b`,
		percent,
		strings.ToLower(percent),
		"pre " + percent + " post",
		wrapped,
		base64.RawURLEncoding.EncodeToString(bearer),
		folded.String(),
		url.QueryEscape(percent),
		strings.ToLower(url.QueryEscape(percent)),
		"pre " + url.QueryEscape(percent) + " post",
		url.QueryEscape(string(inner)),
		string(twice),
		url.QueryEscape(base64.StdEncoding.EncodeToString(secret)),
		base64.StdEncoding.EncodeToString([]byte(percent)),
		base64.URLEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString(secret))),
		base64.StdEncoding.EncodeToString(inner),
		nested,
		hex.EncodeToString(secret),
		hex.EncodeToString(bearer),
		url.QueryEscape(string(tabbed)),
		url.QueryEscape(url.QueryEscape(string(tabbed))),
		base64.StdEncoding.EncodeToString([]byte(strings.ToLower(url.QueryEscape(string(tabbed))))),
	}
	for i, body := range bodies {
		session.httpDo = func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		res, err := principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: target})
		encoded, mErr := json.Marshal(res)
		if err != nil || mErr != nil || string(encoded) != `{"StatusCode":200}` {
			t.Fatalf("body %d result %s err %v", i, encoded, err)
		}
	}
	for _, ev := range session.audit {
		fields := strings.Join([]string{ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation, ev.Class, ev.Time, ev.Prev, ev.Hash}, "\n")
		if secretIn(fields, secret, tabbed) {
			t.Fatal("audit recorded credential material")
		}
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
	if secretIn(string(readAll(t, path)), secret, tabbed) || secretIn(logs.String(), secret, tabbed) {
		t.Fatal("credential in plaintext persistence or logs")
	}
}

func secretIn(s string, secrets ...[]byte) bool {
	for _, secret := range secrets {
		if len(secret) > 0 && strings.Contains(s, string(secret)) {
			return true
		}
	}
	return false
}

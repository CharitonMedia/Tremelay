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

func TestCanonicalGitHubIssue(t *testing.T) {
	got, err := GitHubIssueResource("octocat", "Hello-World", "17")
	if err != nil || got != "GET https://api.github.com/repos/octocat/Hello-World/issues/17" {
		t.Fatalf("resource %s %v", got, err)
	}
	rejected := [][3]string{
		{"", "Hello-World", "17"},
		{"-octo", "Hello-World", "17"},
		{"octo-", "Hello-World", "17"},
		{"octo.cat", "Hello-World", "17"},
		{"octo/cat", "Hello-World", "17"},
		{"octo%63at", "Hello-World", "17"},
		{"octo\r\nX-Evil: 1", "Hello-World", "17"},
		{"\u043ectocat", "Hello-World", "17"},
		{strings.Repeat("a", 40), "Hello-World", "17"},
		{"octocat", "", "17"},
		{"octocat", ".", "17"},
		{"octocat", "..", "17"},
		{"octocat", ".git", "17"},
		{"octocat", "Hello.git", "17"},
		{"octocat", "Hello.GIT", "17"},
		{"octocat", "Hello World", "17"},
		{"octocat", "Hello/World", "17"},
		{"octocat", "a/../../etc", "17"},
		{"octocat", strings.Repeat("a", 101), "17"},
		{"octocat", "Hello-World", ""},
		{"octocat", "Hello-World", "0"},
		{"octocat", "Hello-World", "01"},
		{"octocat", "Hello-World", "-1"},
		{"octocat", "Hello-World", "+1"},
		{"octocat", "Hello-World", "1e2"},
		{"octocat", "Hello-World", "1?x=1"},
		{"octocat", "Hello-World", "1#x"},
		{"octocat", "Hello-World", "1000000000"},
		{"octocat", "Hello-World", "17 "},
	}
	for _, in := range rejected {
		if _, err := GitHubIssueResource(in[0], in[1], in[2]); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q %q %q", in[0], in[1], in[2])
		}
	}
}

func TestParseGitHubIssueState(t *testing.T) {
	const (
		owner = "octocat"
		repo  = "Hello-World"
	)
	ok := githubIssueDoc(owner, repo, "17", "open", false, 3, `"title":"ignored"`)
	got, err := parseGitHubIssueState([]byte(ok), owner, repo, 17)
	if err != nil || got != (GitHubIssueState{Number: 17, State: "open", Locked: false, Comments: 3}) {
		t.Fatalf("parse %+v %v", got, err)
	}
	closed := githubIssueDoc(owner, repo, "17", "closed", true, 0, "")
	got, err = parseGitHubIssueState([]byte(closed), owner, repo, 17)
	if err != nil || got != (GitHubIssueState{Number: 17, State: "closed", Locked: true}) {
		t.Fatalf("closed %+v %v", got, err)
	}
	bad := []string{
		"",
		"[]",
		"null",
		"{",
		githubIssueDoc(owner, repo, "17", "open", false, 3, "") + "{}",
		githubIssueDoc(owner, repo, "18", "open", false, 3, ""),
		githubIssueDoc("Octocat", repo, "17", "open", false, 3, ""),
		githubIssueDoc(owner, repo, "17", "OPEN", false, 3, ""),
		githubIssueDoc(owner, repo, "17", "open", false, -1, ""),
		strings.Replace(ok, `"locked":false`, `"locked":"false"`, 1),
		strings.Replace(ok, `"comments":3`, `"comments":1.5`, 1),
		strings.Replace(ok, `"comments":3`, `"comments":1000001`, 1),
		strings.Replace(ok, `"number":17`, `"number":"17"`, 1),
		`{"url":"https://api.github.com/repos/octocat/Hello-World/issues/17","url":"https://api.github.com/repos/octocat/Hello-World/issues/17","repository_url":"https://api.github.com/repos/octocat/Hello-World","number":17,"state":"open","locked":false,"comments":3}`,
		githubIssueDoc(owner, repo, "17", "open", false, 3, `"pull_request":{"url":"https://api.github.com/repos/octocat/Hello-World/pulls/17"}`),
		githubIssueDoc(owner, repo, "17", "open", false, 3, `"pull_request":null`),
		strings.Replace(githubIssueDoc(owner, repo, "17", "open", false, 3, ""), `"repository_url":"https://api.github.com/repos/octocat/Hello-World",`, "", 1),
		`{"url":"https:\/\/api.github.com\/repos\/octocat\/Hello-World\/issues\/17","repository_url":"https://api.github.com/repos/octocat/Hello-World","number":17,"state":"open","locked":false,"comments":3}`,
		strings.Repeat("[", githubJSONDepth+1) + strings.Repeat("]", githubJSONDepth+1),
	}
	for i, body := range bad {
		got, err := parseGitHubIssueState([]byte(body), owner, repo, 17)
		if err == nil || got != (GitHubIssueState{}) {
			t.Fatalf("body %d accepted %+v", i, got)
		}
	}
}

func TestGitHubIssueState(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	secret := []byte("Gh" + randHex(t, 16) + `/\"`)
	otherSecret := []byte("Ot" + randHex(t, 16) + `/\"`)
	forms := secretForms(secret)
	api, err := session.Put("api", "api_key", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := session.Put("other", "api_key", otherSecret, PutOptions{})
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
	var nilPrincipal *AgentPrincipal
	if _, err := nilPrincipal.GitHubIssueState(GitHubIssueRequest{}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	const owner, repo, number = "octocat", "Hello-World", "17"
	resource, err := GitHubIssueResource(owner, repo, number)
	if err != nil {
		t.Fatal(err)
	}
	target := strings.TrimPrefix(resource, "GET ")
	good := GitHubIssueRequest{CredentialID: api.ID, Owner: owner, Repository: repo, Number: number}
	exp := time.Now().UTC().Add(time.Hour)
	calls := 0
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("dns before authorization")
		return nil, errors.New("dns")
	}
	session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("network before authorization")
		return nil, errors.New("network")
	}
	if _, err := principal.GitHubIssueState(good); !errors.Is(err, ErrDeniedMissing) {
		t.Fatal(err)
	}
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest},
		Resource: resource, ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := principal.GitHubIssueState(good); !errors.Is(err, ErrDeniedOperation) || got != (GitHubIssueState{}) {
		t.Fatalf("old grant gained the projection: %+v %v", got, err)
	}
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	session.httpDo = func(req *http.Request) (*http.Response, error) {
		calls++
		if len(req.Header) != 1 || req.Header.Get("Authorization") == "" {
			t.Fatal("status-only call gained github headers or dropped authorization")
		}
		body := githubIssueDoc(owner, repo, number, "open", false, 3, `"title":"`+string(secret)+`"`)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	}
	res, err := principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: target})
	encoded, mErr := json.Marshal(res)
	if err != nil || mErr != nil || string(encoded) != `{"StatusCode":200}` || calls != 1 {
		t.Fatalf("status-only %s calls %d err %v", encoded, calls, err)
	}
	grant, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpGitHubIssueState},
		Resource: resource, ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: otherAgent.ID, CredentialID: api.ID, Operations: []string{OpGitHubIssueState},
		Resource: "GET https://evil.example/repos/octocat/Hello-World/issues/17", ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}
	headResource := "HEAD https://api.github.com/repos/octocat/Hello-World/issues/19"
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpGitHubIssueState},
		Resource: headResource, ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}
	commentsResource := "GET https://api.github.com/repos/octocat/Hello-World/issues/19/comments"
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: api.ID, Operations: []string{OpGitHubIssueState},
		Resource: commentsResource, ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}

	session.resolve = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("dns before authorization")
		return nil, errors.New("dns")
	}
	session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("network before authorization")
		return nil, errors.New("network")
	}
	deny := func(req GitHubIssueRequest, who *AgentPrincipal, want error) {
		t.Helper()
		before := calls
		got, err := who.GitHubIssueState(req)
		if !errors.Is(err, want) || got != (GitHubIssueState{}) || calls != before {
			t.Fatalf("got %+v calls %d err %v want %v", got, calls, err, want)
		}
		if containsForm(err.Error(), forms) || containsForm(err.Error(), secretForms(otherSecret)) {
			t.Fatal("secret in error")
		}
	}
	deny(GitHubIssueRequest{CredentialID: other.ID, Owner: owner, Repository: repo, Number: number}, principal, ErrDeniedCredential)
	deny(GitHubIssueRequest{CredentialID: api.ID, Owner: "other", Repository: repo, Number: number}, principal, ErrDeniedPath)
	deny(GitHubIssueRequest{CredentialID: api.ID, Owner: owner, Repository: "Other", Number: number}, principal, ErrDeniedPath)
	deny(GitHubIssueRequest{CredentialID: api.ID, Owner: owner, Repository: repo, Number: "18"}, principal, ErrDeniedPath)
	deny(GitHubIssueRequest{CredentialID: api.ID, Owner: owner, Repository: repo, Number: "19"}, principal, ErrDeniedMethod)
	deny(good, otherPrincipal, ErrDeniedOrigin)
	deny(good, barePrincipal, ErrDeniedAgent)
	deny(GitHubIssueRequest{CredentialID: string(secret), Owner: owner, Repository: repo, Number: number}, principal, ErrInvalid)
	for _, req := range []GitHubIssueRequest{
		{api.ID, "", repo, number},
		{api.ID, "octo/cat", repo, number},
		{api.ID, "octo%63at", repo, number},
		{api.ID, "octo\r\nX-Evil: 1", repo, number},
		{api.ID, string(secret), repo, number},
		{api.ID, owner, "..", number},
		{api.ID, owner, "Hello.git", number},
		{api.ID, owner, repo, "01"},
		{api.ID, owner, repo, "1?x=1"},
		{api.ID, owner, repo, "0"},
	} {
		deny(req, principal, ErrInvalid)
	}
	if res, err := otherPrincipal.BrokerHTTP(HTTPBrokerRequest{CredentialID: api.ID, Method: http.MethodGet, Target: target}); !errors.Is(err, ErrDeniedOperation) || res.StatusCode != 0 {
		t.Fatalf("github grant authorized BrokerHTTP: %d %v", res.StatusCode, err)
	}

	var sawAllowed bool
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	session.httpDo = func(req *http.Request) (*http.Response, error) {
		calls++
		for _, ev := range session.audit {
			if ev.Action == actionBroker && ev.Result == resultAllowed && ev.Operation == OpGitHubIssueState && ev.GrantID == grant.ID {
				sawAllowed = true
			}
		}
		if !sawAllowed {
			t.Fatal("credential-bearing request preceded the allowed audit")
		}
		if req.Method != http.MethodGet || req.URL.String() != target || req.Body != nil || req.URL.RawQuery != "" {
			t.Fatalf("outbound request %s %s", req.Method, req.URL)
		}
		deadline, ok := req.Context().Deadline()
		if !ok || time.Until(deadline) > brokerTimeout || time.Until(deadline) < brokerTimeout-time.Second {
			t.Fatal("timeout was not the broker limit")
		}
		if req.Header.Get("Authorization") != "Bearer "+string(secret) ||
			req.Header.Get("Accept") != githubAccept ||
			req.Header.Get("X-GitHub-Api-Version") != githubAPIVersion ||
			req.Header.Get("User-Agent") != githubUserAgent ||
			len(req.Header) != 4 {
			t.Fatalf("headers %v", req.Header)
		}
		extra := `"title":"` + jsonEscape(string(secret)) + `","body":"` + url.QueryEscape(string(secret)) + `","node":"` + hex.EncodeToString(secret) + `","blob":"` + base64.StdEncoding.EncodeToString(secret) + `"`
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Link": []string{"<https://api.github.com/repos/octocat/Hello-World/issues?page=2>; rel=\"next\""}},
			Body:       io.NopCloser(strings.NewReader(githubIssueDoc(owner, repo, number, "open", false, 3, extra))),
		}, nil
	}
	got, err := principal.GitHubIssueState(good)
	encoded, mErr = json.Marshal(got)
	if err != nil || mErr != nil || string(encoded) != `{"number":17,"state":"open","locked":false,"comments":3}` || calls != 2 {
		t.Fatalf("summary %s calls %d err %v", encoded, calls, err)
	}
	if containsForm(string(encoded), forms) {
		t.Fatal("summary contained the credential")
	}
	session.httpDo = func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(githubIssueDoc(owner, repo, number, "closed", true, 0, `"title":"closed"`))),
		}, nil
	}
	got, err = principal.GitHubIssueState(good)
	encoded, mErr = json.Marshal(got)
	if err != nil || mErr != nil || string(encoded) != `{"number":17,"state":"closed","locked":true,"comments":0}` || calls != 3 {
		t.Fatalf("closed %s calls %d err %v", encoded, calls, err)
	}

	failUpstream := func(status int, body string, header http.Header, transport error) {
		t.Helper()
		before := calls
		session.httpDo = func(*http.Request) (*http.Response, error) {
			calls++
			if transport != nil {
				return nil, transport
			}
			return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
		got, err := principal.GitHubIssueState(good)
		if !errors.Is(err, ErrBrokerUpstream) || got != (GitHubIssueState{}) || calls != before+1 {
			t.Fatalf("status %d got %+v calls %d err %v", status, got, calls, err)
		}
		if containsForm(err.Error(), forms) {
			t.Fatal("upstream error contained the credential")
		}
	}
	reflected := strings.Join(forms, " ")
	failUpstream(500, reflected, http.Header{"Retry-After": []string{"https://evil.example/retry?t=" + string(secret)}}, nil)
	failUpstream(404, `{"message":"`+jsonEscape(string(secret))+`","documentation_url":"https://docs.github.com/rest"}`, nil, nil)
	failUpstream(403, reflected, nil, nil)
	failUpstream(429, reflected, http.Header{"Retry-After": []string{"60"}}, nil)
	failUpstream(200, githubIssueDoc(owner, repo, "18", "open", false, 1, ""), nil, nil)
	failUpstream(200, githubIssueDoc("Octocat", repo, number, "open", false, 1, ""), nil, nil)
	failUpstream(200, githubIssueDoc(owner, "hello-world", number, "open", false, 1, ""), nil, nil)
	failUpstream(200, `{`, nil, nil)
	failUpstream(200, githubIssueDoc(owner, repo, number, "open", false, 3, `"pull_request":{}`), nil, nil)
	failUpstream(200, strings.Repeat("x", githubIssueMaxBody+1), nil, nil)
	dup := `{"state":"open","state":"closed","url":"https://api.github.com/repos/octocat/Hello-World/issues/17","repository_url":"https://api.github.com/repos/octocat/Hello-World","number":17,"locked":false,"comments":1}`
	failUpstream(200, dup, nil, nil)
	failUpstream(200, strings.Replace(githubIssueDoc(owner, repo, number, "open", false, 3, ""), `"locked":false`, `"locked":1`, 1), nil, nil)
	failUpstream(0, "", nil, errors.New("dial "+string(secret)))

	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect} {
		before := calls
		session.httpDo = func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: code,
				Header:     http.Header{"Location": []string{"https://evil.example/repos/other/repo/issues/1?t=" + string(secret)}},
				Body:       io.NopCloser(strings.NewReader(string(secret))),
			}, nil
		}
		got, err := principal.GitHubIssueState(good)
		if !errors.Is(err, ErrDeniedRedirect) || got != (GitHubIssueState{}) || calls != before+1 || containsForm(err.Error(), forms) {
			t.Fatalf("redirect %d %+v calls %d err %v", code, got, calls, err)
		}
	}

	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("credential sent to a private address")
		return nil, errors.New("network")
	}
	deny(good, principal, ErrDeniedSSRF)
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}

	session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("allowed audit failure still sent the credential")
		return nil, errors.New("network")
	}
	session.commitFault = func() error { return errors.New("induced") }
	if got, err := principal.GitHubIssueState(good); !errors.Is(err, ErrAudit) || got != (GitHubIssueState{}) {
		t.Fatalf("pre-send audit %+v %v", got, err)
	}
	session.commitFault = nil
	session.httpDo = func(*http.Request) (*http.Response, error) {
		calls++
		session.commitFault = func() error { return errors.New("induced") }
		return &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(githubIssueDoc(owner, repo, number, "open", false, 4, `"title":"withheld"`))),
		}, nil
	}
	if got, err := principal.GitHubIssueState(good); !errors.Is(err, ErrAudit) || got != (GitHubIssueState{}) {
		t.Fatalf("completion audit withheld %+v %v", got, err)
	}
	session.commitFault = nil

	session.clock = func() time.Time { return exp }
	session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("expired grant was used")
		return nil, errors.New("network")
	}
	session.resolve = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("dns after expiry")
		return nil, errors.New("dns")
	}
	deny(good, principal, ErrDeniedExpired)
	session.clock = nil
	if err := session.RevokeGrant(grant.ID); err != nil {
		t.Fatal(err)
	}
	deny(good, principal, ErrDeniedRevoked)

	for i := range session.agents {
		if session.agents[i].ID == agent.ID {
			session.agents[i].State = agentStateSuspended
		}
	}
	deny(good, principal, ErrDeniedAgent)
	deny(GitHubIssueRequest{CredentialID: string(secret), Owner: "../" + string(secret), Repository: repo, Number: "1?x=1"}, principal, ErrDeniedAgent)

	want := map[string]bool{
		resultAllowed: true, resultCompleted: true, resultUpstreamError: true,
		resultDenied: true, resultDeniedAgent: true, resultDeniedCredential: true,
		resultDeniedOperation: true, resultDeniedPath: true, resultDeniedMethod: true,
		resultDeniedOrigin: true, resultDeniedMissing: true, resultDeniedExpired: true,
		resultDeniedRevoked: true, resultDeniedSSRF: true, resultDeniedRedirect: true,
	}
	gotResults := map[string]bool{}
	sawGitHubComplete := false
	for _, ev := range session.audit {
		if ev.Action == actionBroker {
			gotResults[ev.Result] = true
			if ev.Operation == OpGitHubIssueState && ev.Result == resultCompleted {
				sawGitHubComplete = true
			}
		}
		fields := strings.Join([]string{ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation, ev.Class, ev.Time, ev.Prev, ev.Hash, ev.Reasons}, "\n")
		if containsForm(fields, forms) || containsForm(fields, secretForms(otherSecret)) || strings.Contains(fields, "evil.example") || strings.Contains(fields, "Retry-After") {
			t.Fatal("audit recorded caller or credential material")
		}
	}
	for result := range want {
		if !gotResults[result] {
			t.Fatalf("missing github audit %s", result)
		}
	}
	if !sawGitHubComplete {
		t.Fatal("completed issue read was not audited as github_issue_state")
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
	for _, blob := range []string{string(readAll(t, path)), logs.String()} {
		if containsForm(blob, forms) || containsForm(blob, secretForms(otherSecret)) {
			t.Fatal("credential in plaintext persistence or logs")
		}
	}
	for _, env := range os.Environ() {
		if containsForm(env, forms) || containsForm(env, secretForms(otherSecret)) {
			t.Fatal("credential in environment")
		}
	}
}

func githubIssueDoc(owner, repo, number, state string, locked bool, comments int, extra string) string {
	flag := "false"
	if locked {
		flag = "true"
	}
	body := `{"url":"https://api.github.com/repos/` + owner + `/` + repo + `/issues/` + number + `","repository_url":"https://api.github.com/repos/` + owner + `/` + repo + `","number":` + number + `,"state":"` + state + `","locked":` + flag + `,"comments":` + itoa(comments)
	if extra != "" {
		body += "," + extra
	}
	return body + "}"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func jsonEscape(s string) string {
	quoted, err := json.Marshal(s)
	if err != nil || len(quoted) < 2 {
		return ""
	}
	return string(quoted[1 : len(quoted)-1])
}

func secretForms(secret []byte) []string {
	raw := string(secret)
	return []string{
		raw,
		jsonEscape(raw),
		url.QueryEscape(raw),
		hex.EncodeToString(secret),
		base64.StdEncoding.EncodeToString(secret),
	}
}

func containsForm(s string, forms []string) bool {
	for _, form := range forms {
		if form != "" && strings.Contains(s, form) {
			return true
		}
	}
	return false
}

package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// These tests use private pipes, random disposable credentials, and a synthetic
// upstream. No DNS resolver, network listener, or external account is used.
type mcpNetworkEnv struct {
	s        *Session
	path     string
	pass     []byte
	logs     bytes.Buffer
	secret   []byte
	cred     Credential
	agent    Agent
	resource string
	grants   map[string]Grant
	calls    int
	lookups  int
}

func newMCPNetworkEnv(t *testing.T) *mcpNetworkEnv {
	t.Helper()
	e := &mcpNetworkEnv{grants: make(map[string]Grant)}
	e.path, e.pass, e.s = mustCreate(t, log.New(&e.logs, "", 0))
	e.secret = []byte("Mcp" + randHex(t, 24) + `/\"`)
	var err error
	e.cred, err = e.s.Put("private-label-"+randHex(t, 12), "api_key", e.secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e.agent, err = e.s.CreateAgent("private-agent-" + randHex(t, 12))
	if err != nil {
		t.Fatal(err)
	}
	e.resource, err = GitHubIssueResource("octocat", "Hello-World", "17")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{OpHTTPRequest, OpGitHubIssueState} {
		e.grants[op] = e.grant(t, e.agent.ID, op, e.resource, time.Now().Add(time.Hour))
	}
	e.s.resolve = func(_ context.Context, host string) ([]net.IP, error) {
		e.lookups++
		if host != "api.github.com" {
			t.Error("broker changed the bound destination")
			return nil, errors.New("unexpected destination")
		}
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	e.s.httpDo = e.upstream(t)
	return e
}

func (e *mcpNetworkEnv) grant(t *testing.T, agentID, op, resource string, expiry time.Time) Grant {
	t.Helper()
	g, err := e.s.IssueGrant(GrantSpec{
		AgentID: agentID, CredentialID: e.cred.ID, Operations: []string{op},
		Resource: resource, ExpiresAt: expiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (e *mcpNetworkEnv) upstream(t *testing.T) func(*http.Request) (*http.Response, error) {
	t.Helper()
	return func(req *http.Request) (*http.Response, error) {
		e.calls++
		if req.Header.Get("Authorization") != "Bearer "+string(e.secret) {
			t.Error("synthetic upstream did not receive the protected credential")
			return nil, errors.New("unauthorized")
		}
		if req.Method != http.MethodGet || req.URL.String() != strings.TrimPrefix(e.resource, "GET ") || req.Body != nil {
			t.Error("broker changed the bound request")
			return nil, errors.New("unexpected request")
		}
		op := OpHTTPRequest
		if req.Header.Get("Accept") != "" {
			op = OpGitHubIssueState
			if req.Header.Get("Accept") != githubAccept || req.Header.Get("X-GitHub-Api-Version") != githubAPIVersion || req.Header.Get("User-Agent") != githubUserAgent || len(req.Header) != 4 {
				t.Error("GitHub request did not retain its fixed headers")
				return nil, errors.New("unexpected headers")
			}
		} else if len(req.Header) != 1 {
			t.Error("HTTP request gained a caller-controlled header")
			return nil, errors.New("unexpected headers")
		}
		if len(e.s.audit) == 0 {
			t.Error("credential use was not audited before transmission")
			return nil, errors.New("missing audit")
		}
		last := e.s.audit[len(e.s.audit)-1]
		if last.Action != actionBroker || last.Result != resultAllowed || last.Operation != op || last.AgentID != e.agent.ID || last.CredID != e.cred.ID || last.GrantID == "" {
			t.Error("credential use preceded its exact allowed audit row")
			return nil, errors.New("missing audit")
		}
		reflection, _ := json.Marshal(strings.Join(secretForms(e.secret), " "))
		body := githubIssueDoc("octocat", "Hello-World", "17", "open", false, 3, `"title":`+string(reflection)+`,"body":`+string(reflection))
		return &http.Response{
			StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)),
			Header: http.Header{"X-Reflection": []string{string(e.secret)}},
		}, nil
	}
}

func mcpNetworkClient(t *testing.T, cap *AgentCapability, revision string) *mcpSession {
	t.Helper()
	if revision == mcpProtocolRevision {
		return startMCP(t, cap)
	}
	return startStdioSDK(t, cap, revision)
}

func mcpNetworkHandles(t *testing.T, client *mcpSession) map[string]string {
	t.Helper()
	entries := entriesOf(t, mustCall(t, client, toolList, map[string]any{}))
	if len(entries) != 2 {
		t.Fatalf("network catalogue has %d entries, want 2", len(entries))
	}
	handles := make(map[string]string)
	for _, entry := range entries {
		op, ok := entry["operation"].(string)
		if !ok || (op != OpHTTPRequest && op != OpGitHubIssueState) {
			t.Fatal("network catalogue contains an unexpected operation")
		}
		handle, ok := entry["handle"].(string)
		if !ok || len(mustB64(t, handle)) != 32 || len(entry) != 5 || entry["status"] != GrantActive {
			t.Fatal("network catalogue violated its exact public projection")
		}
		if _, hasKeyID := entry["key_id"]; hasKeyID {
			t.Fatal("network catalogue exposed a key identity")
		}
		if _, duplicate := handles[op]; duplicate {
			t.Fatal("network catalogue duplicated an operation")
		}
		handles[op] = handle
	}
	return handles
}

func assertMCPNetworkProjection(t *testing.T, result *mcp.CallToolResult, op string) {
	t.Helper()
	if result.IsError || result.StructuredContent == nil {
		t.Fatal("authorized network invocation did not produce a structured result")
	}
	want := map[string]any{"status_code": float64(200)}
	if op == OpGitHubIssueState {
		want = map[string]any{"number": float64(17), "state": "open", "locked": false, "comments": float64(3)}
	}
	if !reflect.DeepEqual(toolObject(t, result), want) {
		t.Fatal("network invocation violated its operation-specific result projection")
	}
	// Check the text mirror too; a safe structured projection cannot cover a
	// second disclosure in an MCP content block.
	if len(result.Content) != 1 {
		t.Fatal("network invocation returned unexpected content blocks")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("network invocation returned non-text content")
	}
	var mirrored map[string]any
	if json.Unmarshal([]byte(text.Text), &mirrored) != nil || !reflect.DeepEqual(mirrored, want) {
		t.Fatal("network invocation's text and structured projections differ")
	}
}

func (e *mcpNetworkEnv) assertSurfaces(t *testing.T, client *mcpSession, outputs ...any) {
	t.Helper()
	rows := mcpAuditSnapshot(e.s)
	if err := verifyChain(rows); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(e.path, e.pass); err != nil {
		t.Fatal(err)
	}
	surfaces := [][]byte{readAll(t, e.path), e.logs.Bytes(), mustJSON(t, rows), []byte(strings.Join(os.Environ(), "\n"))}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		data, err := os.ReadFile(e.path + suffix)
		if err == nil {
			surfaces = append(surfaces, data)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	if client != nil {
		surfaces = append(surfaces, []byte(client.ep.logs.text()), []byte(client.clientLog.text()))
	}
	for _, output := range outputs {
		surfaces = append(surfaces, mustJSON(t, output))
	}
	for _, surface := range surfaces {
		if containsForm(string(surface), secretForms(e.secret)) {
			t.Fatal("credential-derived bytes escaped to a public or plaintext surface")
		}
	}
}

// Risk responses are separate required audit rows. Count credential operations
// exactly while also checking every accompanying response/notification binding.
func mcpNetworkBrokerRows(t *testing.T, s *Session, before int) []auditEvent {
	t.Helper()
	all := mcpAuditSnapshot(s)[before:]
	var brokers []auditEvent
	bySeq := make(map[uint64]auditEvent)
	responses := make(map[uint64]int)
	for _, row := range all {
		if row.Action == actionBroker {
			brokers = append(brokers, row)
			bySeq[row.Seq] = row
			continue
		}
		source, found := bySeq[row.RefSeq]
		if !noticeAction(row.Action) || !found || validNoticeAudit(row) != nil || row.AgentID != source.AgentID || row.GrantID != source.GrantID || row.CredID != source.CredID || row.CredType != source.CredType || row.Class != baseClass(source).Class {
			t.Fatal("broker denial appended an invalid or misattributed risk response")
		}
		if row.Action == actionRespond {
			responses[row.RefSeq]++
		}
	}
	for _, row := range brokers {
		want := 0
		if baseClass(row).alert() {
			want = 1
		}
		if responses[row.Seq] != want {
			t.Fatal("broker attempt lost or duplicated its required risk response")
		}
	}
	return brokers
}

func TestMCPNetworkBrokerProtectedUse(t *testing.T) {
	for _, revision := range []string{mcpProtocolRevision, mcpStdio20250618, mcpStdio20251125} {
		t.Run(revision, func(t *testing.T) {
			e := newMCPNetworkEnv(t)
			client := mcpNetworkClient(t, bindCap(t, e.s, e.agent.ID), revision)
			if client.cs.InitializeResult().ProtocolVersion != revision {
				t.Fatal("client negotiated the wrong protocol profile")
			}
			tools, err := client.cs.ListTools(t.Context(), nil)
			if err != nil || len(tools.Tools) != 3 {
				t.Fatal("network brokers changed the fixed tool catalogue")
			}
			names := make(map[string]bool)
			for _, tool := range tools.Tools {
				names[tool.Name] = true
				var schema map[string]any
				if json.Unmarshal(mustJSON(t, tool.InputSchema), &schema) != nil || schema["type"] != "object" || schema["additionalProperties"] != false {
					t.Fatal("tool input schema is not a closed object")
				}
			}
			if !names[toolList] || !names[toolDescribe] || !names[toolInvoke] || names[toolRequest] {
				t.Fatal("network brokers added an authority-creating tool")
			}
			handles := mcpNetworkHandles(t, client)
			var outputs []any
			outputs = append(outputs, tools, handles)
			for _, op := range []string{OpHTTPRequest, OpGitHubIssueState} {
				described := mustCall(t, client, toolDescribe, map[string]any{"handle": handles[op]})
				desc := toolObject(t, described)
				if len(desc) != 5 || desc["operation"] != op || desc["handle"] != handles[op] || desc["resource"] != e.resource || desc["status"] != GrantActive {
					t.Fatal("describe changed the handle's operation or resource")
				}
				before := len(mcpAuditSnapshot(e.s))
				result := mustCall(t, client, toolInvoke, map[string]any{"handle": handles[op]})
				assertMCPNetworkProjection(t, result, op)
				rows := mcpNetworkBrokerRows(t, e.s, before)
				if len(rows) != 2 || rows[0].Result != resultAllowed || rows[1].Result != resultCompleted {
					t.Fatal("credential use did not record exactly allowed then completed")
				}
				for _, row := range rows {
					if row.Action != actionBroker || row.Operation != op || row.GrantID != e.grants[op].ID || row.CredID != e.cred.ID || row.AgentID != e.agent.ID {
						t.Fatal("credential use audit lost its operation-specific authority")
					}
				}
				outputs = append(outputs, described, result)
			}
			if e.calls != 2 || e.lookups != 2 {
				t.Fatal("discovery caused network access or invocation retried")
			}
			for _, output := range outputs {
				encoded := mustJSON(t, output)
				for _, hidden := range []string{e.cred.ID, e.cred.Label, e.agent.ID, e.agent.Label, e.grants[OpHTTPRequest].ID, e.grants[OpGitHubIssueState].ID} {
					if bytes.Contains(encoded, []byte(hidden)) {
						t.Fatal("MCP disclosed non-public authority metadata")
					}
				}
			}
			e.assertSurfaces(t, client, outputs...)
		})
	}
}

func TestMCPNetworkBrokerCatalogScope(t *testing.T) {
	e := newMCPNetworkEnv(t)
	other, err := e.s.CreateAgent("other-agent")
	if err != nil {
		t.Fatal(err)
	}
	foreignResource := "GET https://foreign.example/private"
	e.grant(t, other.ID, OpHTTPRequest, foreignResource, time.Now().Add(time.Hour))
	for _, spec := range []GrantSpec{
		{AgentID: e.agent.ID, CredentialClass: "api_key", Operations: []string{OpHTTPRequest}, Resource: "GET https://class.example/private", ExpiresAt: time.Now().Add(time.Hour)},
		{AgentID: e.agent.ID, CredentialID: e.cred.ID, Operations: []string{OpHTTPRequest, OpGitHubIssueState}, Resource: e.resource, ExpiresAt: time.Now().Add(time.Hour)},
		{AgentID: e.agent.ID, CredentialID: e.cred.ID, Operations: []string{OpSign}, Resource: "hidden-signing", ExpiresAt: time.Now().Add(time.Hour)},
		{AgentID: e.agent.ID, CredentialID: e.cred.ID, Operations: []string{OpHTTPRequest}, Resource: "GET https://API.github.com/repos/octocat/Hello-World/issues/17", ExpiresAt: time.Now().Add(time.Hour)},
		{AgentID: e.agent.ID, CredentialID: e.cred.ID, Operations: []string{OpGitHubIssueState}, Resource: "GET https://api.github.com/repos/octocat/Hello-World/issues/017", ExpiresAt: time.Now().Add(time.Hour)},
	} {
		if _, err := e.s.IssueGrant(spec); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := e.s.Put("ssh-key", CredTypeEd25519, der, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.IssueGrant(GrantSpec{
		AgentID: e.agent.ID, CredentialID: key.ID, Operations: []string{OpSSHUserAuth}, Resource: "hidden-ssh", ExpiresAt: time.Now().Add(time.Hour),
		SSHUsername: "hidden-account", SSHHostKey: marshalEd25519Pub(pub),
	}); err != nil {
		t.Fatal(err)
	}
	client := startMCP(t, bindCap(t, e.s, e.agent.ID))
	handles := mcpNetworkHandles(t, client)
	if len(handles) != 2 || e.calls != 0 || e.lookups != 0 {
		t.Fatal("catalogue included unbound authority or performed credential use")
	}
	list := mustCall(t, client, toolList, map[string]any{})
	for _, hidden := range []string{foreignResource, "class.example", "hidden-signing", "hidden-ssh", "hidden-account", "API.github.com", "/017"} {
		if bytes.Contains(mustJSON(t, list), []byte(hidden)) {
			t.Fatal("catalogue disclosed an excluded grant")
		}
	}
	e.assertSurfaces(t, client, list)
}

func TestMCPNetworkBrokerRejectsRetargeting(t *testing.T) {
	for _, revision := range []string{mcpProtocolRevision, mcpStdio20251125} {
		t.Run(revision, func(t *testing.T) {
			e := newMCPNetworkEnv(t)
			client := mcpNetworkClient(t, bindCap(t, e.s, e.agent.ID), revision)
			handles := mcpNetworkHandles(t, client)
			var outputs []any
			for _, op := range []string{OpHTTPRequest, OpGitHubIssueState} {
				for _, extra := range []struct {
					name  string
					value any
				}{
					{"payload", base64.StdEncoding.EncodeToString(e.secret)},
					{"payload", ""}, {"payload", nil},
					{"target", "https://attacker.example/" + string(e.secret)},
					{"credential_id", e.cred.ID}, {"credential", e.cred.ID},
					{"operation", OpLocalArtifactAttest}, {"agent_id", e.agent.ID},
					{"resource", e.resource}, {"method", "DELETE"}, {"headers", map[string]any{"Authorization": string(e.secret)}},
				} {
					waitMCPIdle(t, client.ep)
					before := len(mcpAuditSnapshot(e.s))
					result, err := client.cs.CallTool(t.Context(), &mcp.CallToolParams{Name: toolInvoke, Arguments: map[string]any{"handle": handles[op], extra.name: extra.value}})
					waitMCPIdle(t, client.ep)
					if err == nil && (result == nil || !result.IsError) {
						t.Fatalf("%s accepted a network %s argument", op, extra.name)
					}
					if result != nil && result.StructuredContent != nil {
						t.Fatal("rejected retargeting returned structured success content")
					}
					rows := mcpAuditSnapshot(e.s)[before:]
					if len(rows) != 1 || rows[0].Result != resultDenied || rows[0].AgentID != e.agent.ID {
						t.Fatal("retargeting did not produce exactly one denial for the bound agent")
					}
					outputs = append(outputs, result)
					if err != nil {
						outputs = append(outputs, err.Error())
					}
				}
			}
			if e.calls != 0 || e.lookups != 0 {
				t.Fatal("rejected retargeting reached a destination")
			}
			e.assertSurfaces(t, client, outputs...)
		})
	}
}

func TestMCPNetworkBrokerForeignHandles(t *testing.T) {
	e := newMCPNetworkEnv(t)
	other, err := e.s.CreateAgent("foreign")
	if err != nil {
		t.Fatal(err)
	}
	foreignGrant := e.grant(t, other.ID, OpHTTPRequest, "GET https://foreign.example/private", time.Now().Add(time.Hour))
	foreignCap := bindCap(t, e.s, other.ID)
	foreignList := capCall(t, foreignCap, okBytes(t)(encodeCapList()))
	if len(foreignList.entries) != 1 {
		t.Fatal("foreign fixture grant was not discoverable by its own principal")
	}
	secondCap := bindCap(t, e.s, e.agent.ID)
	secondList := capCall(t, secondCap, okBytes(t)(encodeCapList()))
	if len(secondList.entries) != 2 {
		t.Fatal("second adapter did not discover its own handles")
	}
	client := startMCP(t, bindCap(t, e.s, e.agent.ID))
	mcpNetworkHandles(t, client)
	var outputs []any
	for _, handle := range []string{
		base64.StdEncoding.EncodeToString(make([]byte, 32)),
		base64.StdEncoding.EncodeToString(foreignList.entries[0].handle[:]),
		base64.StdEncoding.EncodeToString(secondList.entries[0].handle[:]),
	} {
		for _, tool := range []string{toolDescribe, toolInvoke} {
			before := len(mcpAuditSnapshot(e.s))
			result := mustCall(t, client, tool, map[string]any{"handle": handle})
			if !result.IsError || result.StructuredContent != nil || toolObject(t, result)["code"] != capUnknownHandle {
				t.Fatal("foreign or unknown handle did not fail identically")
			}
			rows := mcpAuditSnapshot(e.s)[before:]
			if len(rows) != 1 || rows[0].Result != resultDenied || rows[0].AgentID != e.agent.ID || rows[0].GrantID != "" || rows[0].CredID != "" || rows[0].Operation != "" {
				t.Fatal("foreign handle denial leaked or adopted another binding")
			}
			raw := mustJSON(t, result)
			for _, hidden := range []string{handle, foreignGrant.ID, foreignGrant.Resource, other.ID} {
				if bytes.Contains(raw, []byte(hidden)) {
					t.Fatal("foreign handle denial reflected hidden authority")
				}
			}
			outputs = append(outputs, result)
		}
	}
	if e.calls != 0 || e.lookups != 0 {
		t.Fatal("foreign handle reached the broker")
	}
	e.assertSurfaces(t, client, outputs...)
}

func TestMCPNetworkBrokerLifecycle(t *testing.T) {
	for _, op := range []string{OpHTTPRequest, OpGitHubIssueState} {
		for _, state := range []string{"revoked", "expired", "suspended"} {
			t.Run(op+"/"+state, func(t *testing.T) {
				e := newMCPNetworkEnv(t)
				client := startMCP(t, bindCap(t, e.s, e.agent.ID))
				handle := mcpNetworkHandles(t, client)[op]
				want := capDeniedRevoked
				switch state {
				case "revoked":
					if err := e.s.RevokeGrant(e.grants[op].ID); err != nil {
						t.Fatal(err)
					}
				case "expired":
					e.s.clock = func() time.Time { return e.grants[op].ExpiresAt }
					want = capDeniedExpired
				case "suspended":
					for i := range e.s.agents {
						if e.s.agents[i].ID == e.agent.ID {
							e.s.agents[i].State = agentStateSuspended
						}
					}
					want = capDeniedAgent
				}
				before := len(mcpAuditSnapshot(e.s))
				result := mustCall(t, client, toolInvoke, map[string]any{"handle": handle})
				if !result.IsError || result.StructuredContent != nil || toolObject(t, result)["code"] != want {
					t.Fatal("stale authority produced a result or the wrong fixed denial")
				}
				rows := mcpNetworkBrokerRows(t, e.s, before)
				if len(rows) != 1 || rows[0].Action != actionBroker || rows[0].Result != want || rows[0].AgentID != e.agent.ID || rows[0].Operation != op {
					t.Fatal("lifecycle denial did not retain its operation-specific audit")
				}
				if state != "suspended" && rows[0].GrantID != e.grants[op].ID {
					t.Fatal("lifecycle denial selected another grant")
				}
				if e.calls != 0 || e.lookups != 0 {
					t.Fatal("inactive authority reached the destination")
				}
				e.assertSurfaces(t, client, result)
			})
		}
	}
}

func TestMCPNetworkBrokerExactGrantNoFallback(t *testing.T) {
	for _, op := range []string{OpHTTPRequest, OpGitHubIssueState} {
		for _, state := range []string{"revoked", "expired"} {
			t.Run(op+"/"+state, func(t *testing.T) {
				e := newMCPNetworkEnv(t)
				keep := e.grant(t, e.agent.ID, op, e.resource, time.Now().Add(2*time.Hour))
				cap := bindCap(t, e.s, e.agent.ID)
				client := startMCP(t, cap)
				if len(entriesOf(t, mustCall(t, client, toolList, map[string]any{}))) != 3 {
					t.Fatal("duplicate fixture did not retain both grants")
				}
				oldH, keepH := handlesFor(t, cap, e.grants[op].ID, keep.ID)
				want := capDeniedRevoked
				if state == "expired" {
					e.s.clock = func() time.Time { return e.grants[op].ExpiresAt }
					want = capDeniedExpired
				} else if err := e.s.RevokeGrant(e.grants[op].ID); err != nil {
					t.Fatal(err)
				}
				before := len(mcpAuditSnapshot(e.s))
				denied := mustCall(t, client, toolInvoke, map[string]any{"handle": base64.StdEncoding.EncodeToString(oldH[:])})
				rows := mcpNetworkBrokerRows(t, e.s, before)
				if !denied.IsError || toolObject(t, denied)["code"] != want || e.calls != 0 || e.lookups != 0 || len(rows) != 1 || rows[0].GrantID != e.grants[op].ID || rows[0].Result != want {
					t.Fatal("inactive handle fell back to a different matching grant")
				}
				result := mustCall(t, client, toolInvoke, map[string]any{"handle": base64.StdEncoding.EncodeToString(keepH[:])})
				assertMCPNetworkProjection(t, result, op)
				rows = mcpNetworkBrokerRows(t, e.s, before)
				if e.calls != 1 || rows[len(rows)-1].GrantID != keep.ID || rows[len(rows)-1].Result != resultCompleted {
					t.Fatal("remaining exact grant was not usable on its own handle")
				}
				e.assertSurfaces(t, client, denied, result)
			})
		}
	}
}

func TestMCPNetworkBrokerCredentialReplacement(t *testing.T) {
	for _, op := range []string{OpHTTPRequest, OpGitHubIssueState} {
		t.Run(op, func(t *testing.T) {
			e := newMCPNetworkEnv(t)
			client := startMCP(t, bindCap(t, e.s, e.agent.ID))
			handle := mcpNetworkHandles(t, client)[op]
			oldSecret := append([]byte(nil), e.secret...)
			e.secret = []byte("Replaced" + randHex(t, 24) + `/\"`)
			if _, err := e.s.Replace(e.cred.ID, e.secret, LifecycleOptions{}); err != nil {
				t.Fatal(err)
			}
			// Re-listing on the old adapter cannot silently rebind its existing handle.
			relisted := entriesOf(t, mustCall(t, client, toolList, map[string]any{}))
			found := false
			for _, entry := range relisted {
				if entry["handle"] == handle {
					found = entry["operation"] == op && entry["resource"] == e.resource && entry["status"] == GrantRevoked
				}
			}
			if !found {
				t.Fatal("re-listing moved or revived an old credential-generation handle")
			}
			description := toolObject(t, mustCall(t, client, toolDescribe, map[string]any{"handle": handle}))
			if description["status"] != GrantRevoked {
				t.Fatal("describe hid a replaced credential generation")
			}
			before := len(mcpAuditSnapshot(e.s))
			denied := mustCall(t, client, toolInvoke, map[string]any{"handle": handle})
			rows := mcpNetworkBrokerRows(t, e.s, before)
			if !denied.IsError || denied.StructuredContent != nil || e.calls != 0 || e.lookups != 0 || len(rows) != 1 || rows[0].Result != resultDeniedCredential || rows[0].Operation != op || rows[0].GrantID != e.grants[op].ID {
				t.Fatal("old handle moved to the replacement credential generation")
			}
			fresh := startMCP(t, bindCap(t, e.s, e.agent.ID))
			newHandle := mcpNetworkHandles(t, fresh)[op]
			if newHandle == handle {
				t.Fatal("new adapter reused another adapter's handle")
			}
			result := mustCall(t, fresh, toolInvoke, map[string]any{"handle": newHandle})
			assertMCPNetworkProjection(t, result, op)
			if e.calls != 1 {
				t.Fatal("new adapter did not use the replacement exactly once")
			}
			e.assertSurfaces(t, client, denied, result)
			e.assertSurfaces(t, fresh, denied, result)
			e.secret = oldSecret
			e.assertSurfaces(t, client, denied, result)
		})
	}
}

func TestMCPNetworkBrokerDestinationDenials(t *testing.T) {
	for _, op := range []string{OpHTTPRequest, OpGitHubIssueState} {
		for _, mode := range []string{"private-dns", "mixed-dns", "redirect", "reflected-error"} {
			t.Run(op+"/"+mode, func(t *testing.T) {
				e := newMCPNetworkEnv(t)
				client := startMCP(t, bindCap(t, e.s, e.agent.ID))
				handle := mcpNetworkHandles(t, client)[op]
				want, calls := resultDeniedSSRF, 0
				switch mode {
				case "private-dns", "mixed-dns":
					e.s.resolve = func(context.Context, string) ([]net.IP, error) {
						ips := []net.IP{net.ParseIP("127.0.0.1")}
						if mode == "mixed-dns" {
							ips = append(ips, net.ParseIP("1.1.1.1"))
						}
						return ips, nil
					}
				case "redirect", "reflected-error":
					want, calls = resultDeniedRedirect, 1
					if mode == "reflected-error" {
						want = resultUpstreamError
					}
					checked := e.upstream(t)
					e.s.httpDo = func(req *http.Request) (*http.Response, error) {
						response, err := checked(req)
						if err != nil {
							return nil, err
						}
						_ = response.Body.Close()
						if mode == "reflected-error" {
							return nil, errors.New("upstream " + strings.Join(secretForms(e.secret), " "))
						}
						return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://attacker.example/" + string(e.secret)}}, Body: io.NopCloser(strings.NewReader(string(e.secret)))}, nil
					}
				}
				before := len(mcpAuditSnapshot(e.s))
				result := mustCall(t, client, toolInvoke, map[string]any{"handle": handle})
				if !result.IsError || result.StructuredContent != nil || e.calls != calls {
					t.Fatal("destination denial released a result or followed a redirect")
				}
				rows := mcpNetworkBrokerRows(t, e.s, before)
				if len(rows) != calls+1 || rows[len(rows)-1].Result != want || rows[len(rows)-1].Operation != op || rows[len(rows)-1].GrantID != e.grants[op].ID {
					t.Fatal("destination failure did not preserve exact-grant audit attribution")
				}
				e.assertSurfaces(t, client, result)
			})
		}
	}
}

func TestMCPNetworkBrokerAuditFailClosed(t *testing.T) {
	for _, op := range []string{OpHTTPRequest, OpGitHubIssueState} {
		for _, stage := range []string{"allowed", "completed", "denied"} {
			t.Run(op+"/"+stage, func(t *testing.T) {
				e := newMCPNetworkEnv(t)
				cap := bindCap(t, e.s, e.agent.ID)
				client := startMCP(t, cap)
				handle := mcpNetworkHandles(t, client)[op]
				fault := func() error { return errors.New("induced audit failure") }
				wantCalls, wantRows := 0, 0
				if stage == "completed" {
					checked := e.upstream(t)
					e.s.httpDo = func(req *http.Request) (*http.Response, error) {
						response, err := checked(req)
						e.s.commitFault = fault
						return response, err
					}
					wantCalls, wantRows = 1, 1
				} else {
					if stage == "denied" {
						if err := e.s.RevokeGrant(e.grants[op].ID); err != nil {
							t.Fatal(err)
						}
					}
					e.s.commitFault = fault
				}
				before := len(mcpAuditSnapshot(e.s))
				result, err := client.cs.CallTool(t.Context(), &mcp.CallToolParams{Name: toolInvoke, Arguments: map[string]any{"handle": handle}})
				if err == nil || (result != nil && !result.IsError) || e.calls != wantCalls {
					t.Fatal("failed required audit still released a network result")
				}
				if result != nil && result.StructuredContent != nil {
					t.Fatal("audit failure returned a structured network projection")
				}
				rows := mcpNetworkBrokerRows(t, e.s, before)
				if len(rows) != wantRows || (wantRows == 1 && rows[0].Result != resultAllowed) {
					t.Fatal("audit failure claimed an undurable completion or denial")
				}
				e.s.commitFault = nil
				e.assertSurfaces(t, client, result, err.Error())
			})
		}
	}
}

func TestMCPNetworkBrokerPreservesAttestationPayload(t *testing.T) {
	for _, revision := range []string{mcpProtocolRevision, mcpStdio20251125} {
		t.Run(revision, func(t *testing.T) {
			s, cap, grant, pub, resource := newSingleAttestCap(t)
			client := mcpNetworkClient(t, cap, revision)
			entries := entriesOf(t, mustCall(t, client, toolList, map[string]any{}))
			if len(entries) != 1 || entries[0]["key_id"] != grant.KeyID {
				t.Fatal("attestation lost its key-bound catalogue entry")
			}
			handle := entries[0]["handle"]
			before := len(mcpAuditSnapshot(s))
			denied := mustCall(t, client, toolInvoke, map[string]any{"handle": handle})
			if !denied.IsError || denied.StructuredContent != nil {
				t.Fatal("attestation accepted network-style arguments without a payload")
			}
			rows := mcpAuditSnapshot(s)[before:]
			if len(rows) != 1 || rows[0].Result != resultDenied {
				t.Fatal("missing attestation payload was not denied exactly once")
			}
			payload := []byte("network-coexistence-artifact-" + randHex(t, 12))
			result := mustCall(t, client, toolInvoke, invokeArgs(handle, payload))
			out := toolObject(t, result)
			if result.IsError || len(out) != 5 || out["domain"] != AttestDomain || out["purpose"] != AttestPurpose || out["resource"] != resource || !VerifyLocalAttestation(pub, resource, payload, mustB64(t, out["signature"].(string))) {
				t.Fatal("existing payload-bound attestation no longer verifies")
			}
		})
	}
}

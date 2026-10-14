package vault

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"log"
	"os"
	"testing"
)

// TestAgentTokenAuthentication is the ADR 0024 authentication contract: the
// principal comes only from the token, the vault keeps only its digest, and
// every attempt leaves exactly one secret-free daemon_auth row.
func TestAgentTokenAuthentication(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	agent, err := session.CreateAgent("token-worker")
	if err != nil {
		t.Fatal(err)
	}
	if len(agent.Token) != AgentTokenLen {
		t.Fatalf("minted token length %d", len(agent.Token))
	}
	token := append([]byte(nil), agent.Token...)
	Wipe(agent.Token)

	// Only the digest is sealed. The token itself is not recoverable.
	sum := sha256.Sum256(token)
	stored := false
	for _, rec := range session.agents {
		if rec.ID == agent.ID {
			stored = bytes.Equal(rec.TokenHash, sum[:])
		}
	}
	if !stored {
		t.Fatal("agent record does not bind this token digest")
	}

	principal, err := session.AuthenticateAgentToken(token)
	if err != nil || principal == nil {
		t.Fatalf("accepted token did not authenticate: %v", err)
	}
	if principal.id != agent.ID {
		t.Fatal("authenticated principal is not the token's agent")
	}
	// The principal is the ordinary agent surface, not a wider authority.
	if _, err := principal.Capabilities(); err != nil {
		t.Fatalf("token principal cannot use its own capability surface: %v", err)
	}

	for name, wrong := range map[string][]byte{
		"wrong token":   randBytesT(t, AgentTokenLen),
		"empty token":   {},
		"short token":   token[:AgentTokenLen-1],
		"long token":    append(append([]byte(nil), token...), 0),
		"digest replay": sum[:],
	} {
		if _, err := session.AuthenticateAgentToken(wrong); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("%s authenticated: %v", name, err)
		}
	}

	// A principal whose agent is no longer active is refused by the
	// authentication step itself, not only by a later capability check.
	for i := range session.agents {
		if session.agents[i].ID == agent.ID {
			session.agents[i].State = agentStateSuspended
		}
	}
	if _, err := session.AuthenticateAgentToken(token); !errors.Is(err, ErrDeniedAgent) {
		t.Fatalf("suspended agent authenticated: %v", err)
	}

	rows, err := session.AuditHistory(AuditFilter{Action: "daemon_auth", Limit: auditPageMax})
	if err != nil {
		t.Fatal(err)
	}
	var results []string
	for _, row := range rows {
		results = append(results, row.Result+"/"+row.AgentID)
		if row.GrantID != "" || row.Operation != "" || row.CredentialID != "" {
			t.Fatal("daemon_auth row carries capability metadata")
		}
	}
	// One row per attempt: the accepted token, five unattributed refusals,
	// then the refusal that names the verified but inactive agent.
	want := []string{
		"allowed/" + agent.ID,
		"denied/", "denied/", "denied/", "denied/", "denied/",
		"denied_agent/" + agent.ID,
	}
	if len(results) != len(want) {
		t.Fatalf("daemon_auth rows %v", results)
	}
	for i := range want {
		if results[i] != want[i] {
			t.Fatalf("daemon_auth row %d is %q, want %q", i, results[i], want[i])
		}
	}

	// A locked session cannot authenticate at all, and cannot audit either.
	session.Lock()
	if _, err := session.AuthenticateAgentToken(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("locked session authenticated a token: %v", err)
	}

	// The token is never written to the vault file, the audit chain, or logs.
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, token) || bytes.Contains(sealed, pass) {
		t.Fatal("vault file contains a raw token or passphrase")
	}
	if bytes.Contains(logs.Bytes(), token) || bytes.Contains(logs.Bytes(), pass) {
		t.Fatal("logs contain a raw token or passphrase")
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatalf("audit chain invalid after token authentication: %v", err)
	}
}

// TestAgentTokenRequiresMintedAgent covers the pre-ADR-0024 record shape: an
// agent sealed without a digest cannot authenticate, and a digest of the wrong
// length is corruption rather than a usable credential.
func TestAgentTokenRequiresMintedAgent(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	agent, err := session.CreateAgent("legacy-shape")
	if err != nil {
		t.Fatal(err)
	}
	token := append([]byte(nil), agent.Token...)
	for i := range session.agents {
		session.agents[i].TokenHash = nil
	}
	if _, err := session.AuthenticateAgentToken(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("agent without a token digest authenticated: %v", err)
	}
	sum := sha256.Sum256(token)
	for i := range session.agents {
		session.agents[i].TokenHash = sum[:sha256.Size-1]
	}
	if _, err := session.AuthenticateAgentToken(token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("short token digest authenticated: %v", err)
	}
	doc := document{Agents: []agentRecord{{
		ID: agent.ID, Label: "legacy-shape", Kind: principalAgent,
		CreatedAt: agent.CreatedAt, State: agentStateActive, TokenHash: sum[:sha256.Size-1],
	}}}
	if err := validateAgentsAndGrants(doc); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short stored digest accepted: %v", err)
	}
	doc.Agents[0].TokenHash = sum[:]
	if err := validateAgentsAndGrants(doc); err != nil {
		t.Fatalf("valid stored digest rejected: %v", err)
	}
}

package vault

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"
)

// These are the vault half of V1.md item 3c and assume no socket and no
// platform, so Windows runs them too.

// TestAgentTokenCustody is the acceptance path: an agent with no token can be
// given one, a live token can be replaced at will, and a token can be taken
// away and later restored — all without recreating the agent, so its id and
// its grants, which is what a client's configuration names, never move.
func TestAgentTokenCustody(t *testing.T) {
	var logs bytes.Buffer
	env := newAttestEnvLog(t, &logs)
	grant := env.grant(t, time.Hour)
	session := env.s

	// An agent sealed before ADR 0024 holds grants and no digest. It is the
	// case `agent token issue` exists for.
	legacy := session.agents[session.agentIndex(env.agent.ID)]
	legacy.TokenHash, legacy.TokenGen = nil, 0
	session.agents = []agentRecord{legacy}

	issued, err := session.IssueAgentToken(env.agent.ID)
	if err != nil {
		t.Fatalf("an agent without a token could not be given one: %v", err)
	}
	first := append([]byte(nil), issued.Token...)
	Wipe(issued.Token)
	if issued.ID != env.agent.ID {
		t.Fatal("issuing a token moved the agent id")
	}
	assertAuthenticates(t, session, first, env.agent.ID, grant.ID)
	if gen := session.agents[0].tokenGen(); gen != 1 {
		t.Fatalf("first issued token is generation %d", gen)
	}

	// Issue refuses a live token rather than silently retiring it.
	if _, err := session.IssueAgentToken(env.agent.ID); !errors.Is(err, ErrAgentTokenPresent) {
		t.Fatalf("issue replaced a live token: %v", err)
	}
	assertAuthenticates(t, session, first, env.agent.ID, grant.ID)

	rotated, err := session.RotateAgentToken(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	second := append([]byte(nil), rotated.Token...)
	Wipe(rotated.Token)
	if bytes.Equal(first, second) {
		t.Fatal("rotation minted the same token")
	}
	if _, err := session.AuthenticateAgentToken(first); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("the rotated-away token still authenticated: %v", err)
	}
	assertAuthenticates(t, session, second, env.agent.ID, grant.ID)
	if gen := session.agents[0].tokenGen(); gen != 2 {
		t.Fatalf("rotated token is generation %d", gen)
	}

	if err := session.RevokeAgentToken(env.agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AuthenticateAgentToken(second); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a revoked token still authenticated: %v", err)
	}
	if session.agents[0].TokenHash != nil {
		t.Fatal("revoke left a digest behind")
	}
	// The agent keeps its identity and its authority across the revocation.
	if len(session.grants) != 1 || session.grants[0].ID != grant.ID || session.grants[0].RevokedAt != nil {
		t.Fatalf("revoking a token touched the agent's grants: %+v", session.grants)
	}

	restored, err := session.IssueAgentToken(env.agent.ID)
	if err != nil {
		t.Fatalf("a revoked agent could not be given a new token: %v", err)
	}
	third := append([]byte(nil), restored.Token...)
	Wipe(restored.Token)
	assertAuthenticates(t, session, third, env.agent.ID, grant.ID)
	// A generation is never reused, so a token from an earlier custody
	// period cannot be mistaken for the current one.
	if gen := session.agents[0].tokenGen(); gen != 3 {
		t.Fatalf("reissued token is generation %d", gen)
	}
	for _, old := range [][]byte{first, second} {
		if _, err := session.AuthenticateAgentToken(old); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("a superseded token authenticated after reissue: %v", err)
		}
	}

	// No token material reaches the file, the chain or the logs.
	sealed, err := os.ReadFile(env.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range [][]byte{first, second, third} {
		sum := sha256.Sum256(token)
		if bytes.Contains(sealed, token) || bytes.Contains(logs.Bytes(), token) {
			t.Fatal("a raw token reached the vault file or the logs")
		}
		if bytes.Contains(logs.Bytes(), sum[:]) {
			t.Fatal("a token digest reached the logs")
		}
	}
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatalf("audit chain invalid after token custody: %v", err)
	}
}

func assertAuthenticates(t *testing.T, s *Session, token []byte, agentID, grantID string) {
	t.Helper()
	principal, err := s.AuthenticateAgentToken(token)
	if err != nil || principal == nil || principal.id != agentID {
		t.Fatalf("token did not resolve its agent: %v", err)
	}
	caps, err := principal.Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != 1 || caps[0].GrantID != grantID || caps[0].Status != GrantActive {
		t.Fatalf("token principal holds %+v, want the agent's own grant", caps)
	}
}

// TestAgentTokenCustodyRefusals covers what each verb must refuse, and the
// audit shape of those refusals.
func TestAgentTokenCustodyRefusals(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	agent, err := session.CreateAgent("custody")
	if err != nil {
		t.Fatal(err)
	}
	Wipe(agent.Token)
	unknown := randHex(t, 16)
	cases := []struct {
		name   string
		call   func() error
		want   error
		action string
		result string
		agent  string
	}{
		{"issue over a live token", func() error {
			_, err := session.IssueAgentToken(agent.ID)
			return err
		}, ErrAgentTokenPresent, actionAgentTokenIssue, resultDeniedAgent, agent.ID},
		{"issue for an unknown agent", func() error {
			_, err := session.IssueAgentToken(unknown)
			return err
		}, ErrAgentNotFound, actionAgentTokenIssue, resultDenied, ""},
		{"issue for a malformed id", func() error {
			_, err := session.IssueAgentToken("../../etc/passwd")
			return err
		}, ErrAgentNotFound, actionAgentTokenIssue, resultDenied, ""},
		{"rotate an unknown agent", func() error {
			_, err := session.RotateAgentToken(unknown)
			return err
		}, ErrAgentNotFound, actionAgentTokenRotate, resultDenied, ""},
		{"revoke an unknown agent", func() error {
			return session.RevokeAgentToken(unknown)
		}, ErrAgentNotFound, actionAgentTokenRevoke, resultDenied, ""},
		{"revoke a token", func() error {
			return session.RevokeAgentToken(agent.ID)
		}, nil, actionAgentTokenRevoke, resultAllowed, agent.ID},
		{"revoke again", func() error {
			return session.RevokeAgentToken(agent.ID)
		}, ErrAgentTokenAbsent, actionAgentTokenRevoke, resultDeniedAgent, agent.ID},
		{"rotate what is not there", func() error {
			_, err := session.RotateAgentToken(agent.ID)
			return err
		}, ErrAgentTokenAbsent, actionAgentTokenRotate, resultDeniedAgent, agent.ID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(session.audit)
			if err := tc.call(); !errors.Is(err, tc.want) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
			// Every attempt is one row, and it names the agent only when the
			// caller actually identified one.
			if len(session.audit) != before+1 {
				t.Fatalf("wrote %d rows", len(session.audit)-before)
			}
			row := session.audit[len(session.audit)-1]
			if row.Action != tc.action || row.Result != tc.result || row.AgentID != tc.agent {
				t.Fatalf("row %s/%s/%q", row.Action, row.Result, row.AgentID)
			}
			if row.GrantID != "" || row.Operation != "" || row.CredID != "" || row.CredType != "" || row.CredGen != 0 {
				t.Fatalf("token row carries unrelated metadata: %+v", row)
			}
			if err := validAuditShape(row); err != nil {
				t.Fatalf("token row shape: %v", err)
			}
		})
	}
	// A locked session mints nothing.
	session.Lock()
	if _, err := session.IssueAgentToken(agent.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("locked session issued a token: %v", err)
	}
}

// TestAgentTokenAuditShapeRejections pins the shapes a token row must never
// take, so a forged row cannot smuggle attribution or token material past the
// validator by reusing these actions.
func TestAgentTokenAuditShapeRejections(t *testing.T) {
	for _, action := range []string{actionAgentTokenIssue, actionAgentTokenRotate, actionAgentTokenRevoke} {
		base := auditEvent{V: auditCapabilityVersion, Action: action, Result: resultAllowed, AgentID: randHex(t, 16)}
		if err := validAuditShape(base); err != nil {
			t.Fatalf("%s allowed row rejected: %v", action, err)
		}
		bad := map[string]func(auditEvent) auditEvent{
			"no agent on an allowed row": func(ev auditEvent) auditEvent { ev.AgentID = ""; return ev },
			"agent on an unattributed refusal": func(ev auditEvent) auditEvent {
				ev.Result = resultDenied
				return ev
			},
			"grant":      func(ev auditEvent) auditEvent { ev.GrantID = randHex(t, 16); return ev },
			"operation":  func(ev auditEvent) auditEvent { ev.Operation = OpLocalArtifactAttest; return ev },
			"credential": func(ev auditEvent) auditEvent { ev.CredID = randHex(t, 16); return ev },
			"generation": func(ev auditEvent) auditEvent { ev.CredGen = 2; return ev },
			"result":     func(ev auditEvent) auditEvent { ev.Result = resultCompleted; return ev },
		}
		for name, mutate := range bad {
			if err := validAuditShape(mutate(base)); !errors.Is(err, ErrAudit) {
				t.Fatalf("%s accepted a %s row: %v", action, name, err)
			}
		}
	}
}

// TestAgentTokenGenerationShape covers the stored generation: the shape
// sealed before generations existed still reads as a usable token, and the
// shapes custody produces survive a seal and unlock.
func TestAgentTokenGenerationShape(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	agent, err := session.CreateAgent("generations")
	if err != nil {
		t.Fatal(err)
	}
	token := append([]byte(nil), agent.Token...)
	Wipe(agent.Token)
	sum := sha256.Sum256(token)

	// Pre-generation shape: a digest with no count reads as the first token.
	legacy := agentRecord{ID: agent.ID, Label: "generations", Kind: principalAgent,
		CreatedAt: agent.CreatedAt, State: agentStateActive, TokenHash: sum[:]}
	if gen := legacy.tokenGen(); gen != 1 {
		t.Fatalf("a digest with no stored generation reads as %d", gen)
	}
	// Revoked shape: a count with no digest keeps the count and cannot
	// authenticate, which is what makes the next issue strictly newer.
	revoked := legacy
	revoked.TokenHash, revoked.TokenGen = nil, 4
	if gen := revoked.tokenGen(); gen != 4 {
		t.Fatalf("a revoked token lost its generation: %d", gen)
	}
	for _, rec := range []agentRecord{legacy, revoked} {
		if err := validateAgentsAndGrants(document{Agents: []agentRecord{rec}}); err != nil {
			t.Fatalf("stored custody shape rejected: %v", err)
		}
	}

	// The generation survives the seal, so custody is durable rather than a
	// property of one unlocked session.
	if _, err := session.RotateAgentToken(agent.ID); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opened.Lock)
	if gen := opened.agents[0].tokenGen(); gen != 2 {
		t.Fatalf("reopened vault reports generation %d", gen)
	}
}

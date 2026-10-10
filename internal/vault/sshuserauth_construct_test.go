package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSSHUserAuthConstructorDenials(t *testing.T) {
	var logs bytes.Buffer
	env := newSSHEnvLog(t, &logs)
	other, err := env.session.CreateAgent("other-ssh-worker")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := env.session.IssueGrant(GrantSpec{
		AgentID: other.ID, CredentialID: env.cred.ID, Operations: []string{OpSSHUserAuth},
		Resource: env.resource, ExpiresAt: env.grant.ExpiresAt,
		SSHUsername: env.user, SSHHostKey: env.hostBlob,
	})
	if err != nil {
		t.Fatal(err)
	}
	ops := map[string]string{}
	for _, op := range []string{OpSign, OpHTTPRequest, OpGitHubIssueState, OpLocalArtifactAttest} {
		spec := GrantSpec{
			AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{op},
			Resource: env.resource, ExpiresAt: env.grant.ExpiresAt,
		}
		if op == OpLocalArtifactAttest {
			spec.Resource = "artifact:" + env.resource
		}
		g, err := env.session.IssueGrant(spec)
		if err != nil {
			t.Fatal(op, err)
		}
		ops[op] = g.ID
	}
	unknownAgent := randHex(t, 16)
	unknownGrant := randHex(t, 16)
	malformedAgent := "SSH-PRINCIPAL-SENTINEL-" + randHex(t, 16)
	malformedGrant := "SSH-GRANT-SENTINEL-" + randHex(t, 16)
	issued := map[string]bool{foreign.ID: true, env.grant.ID: true}
	for _, id := range ops {
		issued[id] = true
	}
	for _, tc := range []struct {
		name, agentID, grantID, wantActor string
		wantErr                           error
	}{
		{"missing", env.agent.ID, unknownGrant, env.agent.ID, ErrGrantNotFound},
		{"foreign", env.agent.ID, foreign.ID, env.agent.ID, ErrDeniedAgent},
		{"sign", env.agent.ID, ops[OpSign], env.agent.ID, ErrDeniedOperation},
		{"http_request", env.agent.ID, ops[OpHTTPRequest], env.agent.ID, ErrDeniedOperation},
		{"github_issue_state", env.agent.ID, ops[OpGitHubIssueState], env.agent.ID, ErrDeniedOperation},
		{"local_artifact_attest", env.agent.ID, ops[OpLocalArtifactAttest], env.agent.ID, ErrDeniedOperation},
		{"unknown_principal", unknownAgent, env.grant.ID, "", ErrDeniedAgent},
		{"malformed_principal", malformedAgent, env.grant.ID, "", ErrInvalid},
		{"malformed_grant", env.agent.ID, malformedGrant, env.agent.ID, ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			principal, err := env.session.Agent(tc.agentID)
			if err != nil {
				t.Fatal(err)
			}
			before, logBefore := len(mustAudit(t, env.path)), logs.Len()
			stream, err := principal.SSHUserAuth(tc.grantID)
			if stream != nil || !errors.Is(err, tc.wantErr) {
				t.Fatalf("constructor stream %v error %v", stream != nil, err)
			}
			rows := mustAudit(t, env.path)[before:]
			if len(rows) != 1 {
				t.Fatalf("constructor added %d rows, want one denial", len(rows))
			}
			row := rows[0]
			if row.V != auditCapabilityVersion || row.Action != actionSSHUserAuth || row.Operation != "" || row.Result != resultDenied || row.AgentID != tc.wantActor || row.GrantID != "" || row.CredID != "" || row.CredType != "" {
				t.Fatalf("unsafe constructor attribution: %+v", row)
			}
			encoded, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			forbidden := [][]byte{[]byte(tc.grantID), []byte(env.cred.ID), env.der}
			if tc.wantActor == "" {
				forbidden = append(forbidden, []byte(tc.agentID))
			} else if tc.grantID == tc.wantActor {
				t.Fatal("grant id collided with the actor")
			}
			assertNoSecrets(t, encoded, forbidden)
			assertNoSecrets(t, logs.Bytes()[logBefore:], forbidden)
			if !issued[tc.grantID] {
				assertNoSecrets(t, readAll(t, env.path), [][]byte{[]byte(tc.grantID)})
				assertNoSecrets(t, auditPlain(mustAudit(t, env.path)), [][]byte{[]byte(tc.grantID)})
			}
		})
	}
	env.assertClean(t, []byte(malformedAgent), nil, nil)
	env.assertClean(t, []byte(malformedGrant), nil, nil)
	env.assertClean(t, []byte(unknownAgent), nil, nil)
	saved := append([]credential(nil), env.session.creds...)
	restore := func() {
		t.Helper()
		env.session.creds = append([]credential(nil), saved...)
	}
	for _, tc := range []struct {
		name   string
		mutate func()
	}{
		{name: "missing_credential", mutate: func() {
			var rest []credential
			for _, c := range env.session.creds {
				if c.ID != env.cred.ID {
					rest = append(rest, c)
				}
			}
			env.session.creds = rest
		}},
		{name: "non_ed25519", mutate: func() {
			env.session.creds[credIndex(env.session.creds, env.cred.ID)].Type = "api_key"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer restore()
			tc.mutate()
			before, logBefore := len(mustAudit(t, env.path)), logs.Len()
			stream, err := env.principal.SSHUserAuth(env.grant.ID)
			rows := mustAudit(t, env.path)
			if stream != nil || !errors.Is(err, ErrInvalid) || len(rows) != before+1 {
				t.Fatalf("stream %v rows %d err %v", stream != nil, len(rows)-before, err)
			}
			row := rows[len(rows)-1]
			if row.Operation != "" || row.GrantID != "" || row.CredID != "" || row.CredType != "" || row.Result != resultDenied || row.AgentID != env.agent.ID {
				t.Fatalf("credential denial %+v", row)
			}
			encoded, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			assertNoSecrets(t, encoded, [][]byte{[]byte(env.grant.ID), []byte(env.cred.ID)})
			assertNoSecrets(t, logs.Bytes()[logBefore:], [][]byte{[]byte(env.grant.ID), []byte(env.cred.ID)})
		})
	}
	restore()
	if err := env.session.RejectAuthorize(ErrInvalid); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	chain := mustAudit(t, env.path)
	if err := verifyChain(chain); err != nil {
		t.Fatal(err)
	}
	for _, forged := range []auditEvent{
		{Action: actionSSHUserAuth, Result: resultDenied, GrantID: env.grant.ID},
		{Action: actionSSHUserAuth, Result: resultDenied, AgentID: malformedAgent},
		{Action: actionSSHUserAuth, Result: resultDenied, Operation: OpSSHUserAuth, AgentID: env.agent.ID},
	} {
		next, err := nextAudit(chain, chain[0].VaultID, forged)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyChain(append(append([]auditEvent{}, chain...), next)); !errors.Is(err, ErrAudit) {
			t.Fatalf("forged constructor row verified: %+v", forged)
		}
	}
	before := len(chain)
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatal(err)
	}
	env.session.Lock()
	reopened, err := Unlock(env.path, env.pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	if len(reopened.audit) != before+1 {
		t.Fatal("constructor denials did not survive reopening")
	}
}

func TestSSHUserAuthConstructorAuditFailure(t *testing.T) {
	for _, fault := range []string{"audit", "storage", "corrupt"} {
		t.Run(fault, func(t *testing.T) {
			env := newSSHEnv(t)
			before := len(mustAudit(t, env.path))
			unknownGrant := randHex(t, 16)
			wantErr := ErrAudit
			switch fault {
			case "audit":
				env.session.commitFault = func() error { return errors.New("constructor-fault-" + env.user) }
			case "storage":
				wantErr = ErrIO
				if err := env.session.db.Close(); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				wantErr = ErrCorrupt
				if _, err := env.session.db.Exec(`CREATE TRIGGER ssh_no_constructor_update BEFORE UPDATE ON vault BEGIN SELECT RAISE(IGNORE); END;`); err != nil {
					t.Fatal(err)
				}
			}
			stream, err := env.principal.SSHUserAuth(unknownGrant)
			if stream != nil || !errors.Is(err, wantErr) || strings.Contains(err.Error(), env.user) {
				t.Fatalf("audit failure stream %v error %v, want %v", stream != nil, err, wantErr)
			}
			if len(mustAudit(t, env.path)) != before || len(env.session.audit) != before {
				t.Fatal("failed constructor audit published a row")
			}
			if _, err := VerifyAudit(env.path, env.pass); err != nil {
				t.Fatal(err)
			}
			env.session.commitFault = nil
			if fault == "corrupt" {
				if _, err := env.session.db.Exec(`DROP TRIGGER ssh_no_constructor_update`); err != nil {
					t.Fatal(err)
				}
			}
			env.session.Lock()
			reopened, err := Unlock(env.path, env.pass, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Lock()
			principal, err := reopened.Agent(env.agent.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stream, err := principal.SSHUserAuth(unknownGrant); stream != nil || !errors.Is(err, ErrGrantNotFound) {
				t.Fatalf("retry stream %v error %v", stream != nil, err)
			}
			if len(mustAudit(t, env.path)) != before+2 {
				t.Fatal("retry after unlock did not persist its denial")
			}
			if _, err := VerifyAudit(env.path, env.pass); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSSHUserAuthConstructorAuditShape(t *testing.T) {
	if !validAuditOperation("") {
		t.Fatal("empty operation rejected")
	}
	if err := validAuditShape(auditEvent{Action: actionAuthorize, Result: resultDenied}); err != nil {
		t.Fatal(err)
	}
	if err := validAuditShape(auditEvent{Action: actionUnlock, Result: resultDenied}); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []string{"", strings.Repeat("ab", 16)} {
		row := auditEvent{V: auditCapabilityVersion, Action: actionSSHUserAuth, Result: resultDenied, AgentID: actor}
		if err := validAuditShape(row); err != nil {
			t.Fatalf("valid constructor denial rejected: %v", err)
		}
		for _, mutate := range []func(*auditEvent){
			func(ev *auditEvent) { ev.V = auditVersion },
			func(ev *auditEvent) { ev.V = auditNoticeVersion },
			func(ev *auditEvent) { ev.V = auditHealthVersion },
			func(ev *auditEvent) { ev.Action = actionLocalAttest; ev.Operation = OpSSHUserAuth },
			func(ev *auditEvent) { ev.Operation = OpSSHUserAuth },
			func(ev *auditEvent) { ev.Operation = OpSign },
			func(ev *auditEvent) { ev.Result = resultAllowed },
			func(ev *auditEvent) { ev.Result = resultCompleted },
			func(ev *auditEvent) { ev.Result = resultFailed },
			func(ev *auditEvent) { ev.Result = resultDeniedAgent },
			func(ev *auditEvent) { ev.Result = resultDeniedExpired },
			func(ev *auditEvent) { ev.Result = resultDeniedRevoked },
			func(ev *auditEvent) { ev.GrantID = strings.Repeat("cd", 16) },
			func(ev *auditEvent) { ev.CredID = strings.Repeat("ef", 16) },
			func(ev *auditEvent) { ev.CredType = CredTypeEd25519 },
			func(ev *auditEvent) { ev.AgentID = "malformed-principal" },
			func(ev *auditEvent) { ev.Class = ClassRoutine },
			func(ev *auditEvent) { ev.RefSeq = 1 },
			func(ev *auditEvent) { ev.Reasons = "untrusted" },
			func(ev *auditEvent) { ev.CredGen = 1 },
		} {
			bad := row
			mutate(&bad)
			if !errors.Is(validAuditShape(bad), ErrAudit) {
				t.Fatalf("malformed constructor row accepted: %+v", bad)
			}
		}
	}
}

func TestSSHUserAuthConstructorBrokerWindow(t *testing.T) {
	env := newSSHEnv(t)
	for i := 0; i < detectionThreshold; i++ {
		probe := randHex(t, 16)
		stream, err := env.principal.SSHUserAuth(probe)
		if stream != nil || !errors.Is(err, ErrGrantNotFound) {
			t.Fatal(err)
		}
		if bytes.Contains(readAll(t, env.path), []byte(probe)) {
			t.Fatal("probe id stored")
		}
	}
	rows := mustAudit(t, env.path)
	last := rows[len(rows)-1]
	if last.Action != actionSSHUserAuth || last.Result != resultDenied || last.Operation != "" || classify(rows, last).Class != ClassExpectedDenial {
		t.Fatalf("probe class %+v", classify(rows, last))
	}
	if brokerDenialCount(rows, env.agent.ID, last.Seq) != 0 {
		t.Fatal("construction probes entered the broker window")
	}
	var chain []auditEvent
	for i := 0; i < detectionThreshold-1; i++ {
		chain = append(chain, auditEvent{Seq: uint64(len(chain) + 1), Action: actionBroker, Result: resultDeniedMissing, AgentID: env.agent.ID})
	}
	for i := 0; i < 8; i++ {
		chain = append(chain, auditEvent{Seq: uint64(len(chain) + 1), Action: actionSSHUserAuth, Result: resultDenied})
	}
	if got := classify(chain, chain[len(chain)-1]); got.Class != ClassExpectedDenial {
		t.Fatalf("ssh denials promoted %+v", got)
	}
	chain = append(chain, auditEvent{Seq: uint64(len(chain) + 1), Action: actionBroker, Result: resultDeniedMissing, AgentID: env.agent.ID})
	if got := classify(chain, chain[len(chain)-1]); got.Class != ClassRepeatedDenial {
		t.Fatalf("broker threshold moved %+v", got)
	}
}

func auditPlain(events []auditEvent) []byte {
	var buf bytes.Buffer
	for _, ev := range events {
		raw, _ := json.Marshal(ev)
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func TestSSHUserAuthConstructorPreservesLifecycle(t *testing.T) {
	for _, state := range []string{GrantActive, GrantExpired, GrantRevoked} {
		t.Run(state, func(t *testing.T) {
			env := newSSHEnv(t)
			wantDenial := ""
			switch state {
			case GrantExpired:
				env.session.clock = func() time.Time { return env.grant.ExpiresAt }
				wantDenial = resultDeniedExpired
			case GrantRevoked:
				if err := env.session.RevokeGrant(env.grant.ID); err != nil {
					t.Fatal(err)
				}
				wantDenial = resultDeniedRevoked
			}
			before := len(mustAudit(t, env.path))
			stream, err := env.principal.SSHUserAuth(env.grant.ID)
			if err != nil || stream == nil || stream.bound || len(mustAudit(t, env.path)) != before {
				t.Fatalf("construction changed authority or wrote a row: %v", err)
			}
			defer stream.Close()
			if wantDenial != "" {
				before := sshCount(t, env.path, wantDenial)
				response, err := stream.roundTrip([]byte{sshAgentRequestIdentities})
				if err != nil || !bytes.Equal(response, sshEmptyIdentities()) || sshCount(t, env.path, wantDenial) != before+1 {
					t.Fatalf("actual use did not enforce %s: %v", state, err)
				}
			}
			before = len(mustAudit(t, env.path))
			env.session.Lock()
			if stream, err := env.principal.SSHUserAuth(env.grant.ID); stream != nil || !errors.Is(err, ErrUnauthenticated) || len(mustAudit(t, env.path)) != before {
				t.Fatalf("locked construction stream %v error %v", stream != nil, err)
			}
		})
	}
}

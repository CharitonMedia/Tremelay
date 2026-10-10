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
	wrongOp, err := env.session.IssueGrant(GrantSpec{
		AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSign},
		Resource: env.resource, ExpiresAt: env.grant.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	unknownAgent := randHex(t, 16)
	malformedAgent := "SSH-PRINCIPAL-SENTINEL-" + randHex(t, 16)
	malformedGrant := "SSH-GRANT-SENTINEL-" + randHex(t, 16)
	for _, tc := range []struct {
		name, agentID, grantID, wantActor string
		wantErr                           error
	}{
		{"missing", env.agent.ID, randHex(t, 16), env.agent.ID, ErrGrantNotFound},
		{"foreign", env.agent.ID, foreign.ID, env.agent.ID, ErrDeniedAgent},
		{"wrong_operation", env.agent.ID, wrongOp.ID, env.agent.ID, ErrDeniedOperation},
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
			if row.V != auditCapabilityVersion || row.Action != actionSSHUserAuth || row.Operation != OpSSHUserAuth || row.Result != resultDenied || row.AgentID != tc.wantActor || row.GrantID != "" || row.CredID != "" || row.CredType != "" {
				t.Fatalf("unsafe constructor attribution: %+v", row)
			}
			encoded, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			forbidden := [][]byte{[]byte(tc.grantID), env.der}
			if tc.wantActor == "" {
				forbidden = append(forbidden, []byte(tc.agentID))
			}
			assertNoSecrets(t, encoded, forbidden)
			assertNoSecrets(t, logs.Bytes()[logBefore:], forbidden)
		})
	}
	env.assertClean(t, []byte(malformedAgent), nil, nil)
	env.assertClean(t, []byte(malformedGrant), nil, nil)
	before := len(mustAudit(t, env.path))
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
	for _, actor := range []string{"", strings.Repeat("ab", 16)} {
		row := auditEvent{V: auditCapabilityVersion, Action: actionSSHUserAuth, Operation: OpSSHUserAuth, Result: resultDenied, AgentID: actor}
		if err := validAuditShape(row); err != nil {
			t.Fatalf("valid constructor denial rejected: %v", err)
		}
		for _, mutate := range []func(*auditEvent){
			func(ev *auditEvent) { ev.V = auditVersion },
			func(ev *auditEvent) { ev.V = auditNoticeVersion },
			func(ev *auditEvent) { ev.V = auditHealthVersion },
			func(ev *auditEvent) { ev.Action = actionLocalAttest },
			func(ev *auditEvent) { ev.Operation = "" },
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

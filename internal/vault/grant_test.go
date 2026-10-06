package vault

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecideAccess(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	exp := now.Add(time.Hour)
	agent := "agent-a"
	other := "agent-b"
	cred := "cred-1"
	otherCred := "cred-2"
	base := grantRecord{
		ID: "g2", AgentID: agent, CredentialID: cred,
		Operations: []string{OpHTTPRequest}, Resource: "svc:one", ExpiresAt: exp,
	}
	classed := grantRecord{
		ID: "g1", AgentID: agent, CredentialClass: "password",
		Operations: []string{OpSign}, Resource: "svc:pass", ExpiresAt: exp,
	}
	revokedAt := now.Add(-time.Minute)
	revoked := base
	revoked.ID = "g3"
	revoked.RevokedAt = &revokedAt
	expired := base
	expired.ID = "g4"
	expired.ExpiresAt = now

	cases := []struct {
		name      string
		grants    []grantRecord
		agentOK   bool
		agentID   string
		credID    string
		credType  string
		credOK    bool
		op        string
		resource  string
		at        time.Time
		want      string
		wantGrant string
	}{
		{name: "missing", agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultDeniedMissing},
		{name: "unknown agent", grants: []grantRecord{base}, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultDeniedAgent},
		{name: "wrong agent", grants: []grantRecord{base}, agentOK: true, agentID: other, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultDeniedAgent},
		{name: "missing credential", grants: []grantRecord{base}, agentOK: true, agentID: agent, credOK: false, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultDeniedCredential},
		{name: "wrong credential", grants: []grantRecord{base}, agentOK: true, agentID: agent, credID: otherCred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultDeniedCredential, wantGrant: base.ID},
		{name: "wrong operation", grants: []grantRecord{base}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpSign, resource: "svc:one", at: now, want: resultDeniedOperation, wantGrant: base.ID},
		{name: "wrong scope", grants: []grantRecord{base}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:other", at: now, want: resultDeniedScope, wantGrant: base.ID},
		{name: "expired", grants: []grantRecord{expired}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultDeniedExpired, wantGrant: expired.ID},
		{name: "revoked", grants: []grantRecord{revoked}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultDeniedRevoked, wantGrant: revoked.ID},
		{name: "revoked beats expired", grants: []grantRecord{revoked}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: exp, want: resultDeniedRevoked, wantGrant: revoked.ID},
		{name: "allowed", grants: []grantRecord{base}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultAllowed, wantGrant: base.ID},
		{name: "allowed just before expiry", grants: []grantRecord{base}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: exp.Add(-time.Nanosecond), want: resultAllowed, wantGrant: base.ID},
		{name: "class match", grants: []grantRecord{classed}, agentOK: true, agentID: agent, credID: otherCred, credType: "password", credOK: true, op: OpSign, resource: "svc:pass", at: now, want: resultAllowed, wantGrant: classed.ID},
		{name: "class mismatch", grants: []grantRecord{classed}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpSign, resource: "svc:pass", at: now, want: resultDeniedCredential, wantGrant: classed.ID},
		{name: "smallest active id", grants: []grantRecord{base, classedGrant(base, "g0")}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultAllowed, wantGrant: "g0"},
		{name: "active beats revoked", grants: []grantRecord{revoked, base}, agentOK: true, agentID: agent, credID: cred, credType: "api_key", credOK: true, op: OpHTTPRequest, resource: "svc:one", at: now, want: resultAllowed, wantGrant: base.ID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, grantID := decideAccess(tc.grants, tc.agentOK, tc.agentID, tc.credID, tc.credType, tc.credOK, tc.op, tc.resource, tc.at)
			if got != tc.want || grantID != tc.wantGrant {
				t.Fatalf("got %s %s", got, grantID)
			}
		})
	}
}

func classedGrant(g grantRecord, id string) grantRecord {
	g.ID = id
	return g
}

func TestGrantLifecycleAuditAndPersistence(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	sentinel := []byte(randHex(t, 24))
	other := randBytesT(t, 32)
	api, err := session.Put("api", "api_key", sentinel, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pw, err := session.Put("pw", "password", other, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.Put("api-2", "api_key", randBytesT(t, 24), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agentA, err := session.CreateAgent("alpha")
	if err != nil {
		t.Fatal(err)
	}
	agentB, err := session.CreateAgent("beta")
	if err != nil {
		t.Fatal(err)
	}
	if agentA.ID == agentB.ID || safeID(agentA.ID) == "" || safeID(agentB.ID) == "" {
		t.Fatalf("ids %s %s", agentA.ID, agentB.ID)
	}
	if _, err := session.CreateAgent("bad\n" + string(sentinel)); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	principalA, err := session.Agent(agentA.ID)
	if err != nil {
		t.Fatal(err)
	}
	principalB, err := session.Agent(agentB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := principalA.Authorize(api.ID, OpHTTPRequest, "svc:one", time.Now().UTC()); !errors.Is(err, ErrDeniedMissing) {
		t.Fatal(err)
	}

	scope := "scope-" + randHex(t, 16)
	exp := time.Now().UTC().Add(time.Hour)
	rejects := []GrantSpec{
		{AgentID: agentA.ID, CredentialID: api.ID, Operations: []string{"get_secret"}, Resource: scope, ExpiresAt: exp},
		{AgentID: agentA.ID, CredentialID: api.ID, CredentialClass: "api_key", Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
		{AgentID: agentA.ID, Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
		{AgentID: agentA.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest, OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
		{AgentID: agentA.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest}, Resource: "svc*", ExpiresAt: exp},
		{AgentID: agentA.ID, CredentialID: api.ID, Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: time.Now().UTC().Add(-time.Hour)},
		{AgentID: strings.Repeat("ab", 16), CredentialID: api.ID, Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
	}
	for _, spec := range rejects {
		if _, err := session.IssueGrant(spec); err == nil {
			t.Fatal("invalid grant accepted")
		}
	}
	if _, err := principalA.Authorize(api.ID, "get_secret", scope, time.Now().UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}

	grant, err := session.IssueGrant(GrantSpec{
		AgentID:      agentA.ID,
		CredentialID: api.ID,
		Operations:   []string{OpHTTPRequest},
		Resource:     scope,
		ExpiresAt:    exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if grant.CredentialID != api.ID || grant.CredentialClass != "" || bytes.Contains(encoded, sentinel) {
		t.Fatal("grant echoed a secret or the wrong binding")
	}
	classGrant, err := session.IssueGrant(GrantSpec{
		AgentID:         agentA.ID,
		CredentialClass: "password",
		Operations:      []string{OpSign, OpHTTPRequest},
		Resource:        scope + "-pass",
		ExpiresAt:       exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(classGrant.Operations, ",") != OpHTTPRequest+","+OpSign {
		t.Fatalf("ops %v", classGrant.Operations)
	}
	twin, err := session.IssueGrant(GrantSpec{
		AgentID:      agentA.ID,
		CredentialID: api.ID,
		Operations:   []string{OpHTTPRequest},
		Resource:     scope,
		ExpiresAt:    exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantID := grant.ID
	if twin.ID < wantID {
		wantID = twin.ID
	}

	if _, err := principalB.Authorize(api.ID, OpHTTPRequest, scope, time.Now().UTC()); !errors.Is(err, ErrDeniedAgent) {
		t.Fatal(err)
	}
	if _, err := principalA.Authorize(second.ID, OpHTTPRequest, scope, time.Now().UTC()); !errors.Is(err, ErrDeniedCredential) {
		t.Fatal(err)
	}
	if _, err := principalA.Authorize(api.ID, OpSign, scope, time.Now().UTC()); !errors.Is(err, ErrDeniedOperation) {
		t.Fatal(err)
	}
	if _, err := principalA.Authorize(api.ID, OpHTTPRequest, scope+"-other", time.Now().UTC()); !errors.Is(err, ErrDeniedScope) {
		t.Fatal(err)
	}
	gotGrant, err := principalA.Authorize(pw.ID, OpSign, scope+"-pass", time.Now().UTC())
	if err != nil || gotGrant != classGrant.ID {
		t.Fatalf("class authorize %s %v", gotGrant, err)
	}
	gotGrant, err = principalA.Authorize(api.ID, OpHTTPRequest, scope, time.Now().UTC())
	if err != nil || gotGrant != wantID {
		t.Fatalf("authorize %s want %s err %v", gotGrant, wantID, err)
	}
	if _, err := principalA.Authorize(api.ID, OpHTTPRequest, scope, grant.ExpiresAt); !errors.Is(err, ErrDeniedExpired) {
		t.Fatal(err)
	}
	if _, err := principalA.Authorize(api.ID, OpHTTPRequest, scope, grant.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := session.RevokeGrant(grant.ID); err != nil {
		t.Fatal(err)
	}
	if err := session.RevokeGrant(twin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := principalA.Authorize(api.ID, OpHTTPRequest, scope, time.Now().UTC()); !errors.Is(err, ErrDeniedRevoked) {
		t.Fatal(err)
	}
	if err := session.RevokeGrant(grant.ID); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	_, err = principalA.Authorize(pw.ID, OpSign, string(sentinel), time.Now().UTC())
	if !errors.Is(err, ErrDeniedScope) || strings.Contains(err.Error(), string(sentinel)) {
		t.Fatal(err)
	}

	bGrant, err := session.IssueGrant(GrantSpec{
		AgentID:      agentB.ID,
		CredentialID: second.ID,
		Operations:   []string{OpHTTPRequest},
		Resource:     scope + "-b",
		ExpiresAt:    exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	caps, err := principalA.Capabilities(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]Capability{}
	rawCaps, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawCaps, sentinel) || bytes.Contains(rawCaps, other) || bytes.Contains(rawCaps, []byte(`"secret"`)) {
		t.Fatal("capability list exposed secret material")
	}
	for _, cap := range caps {
		if cap.AgentID != agentA.ID || cap.GrantID == bGrant.ID {
			t.Fatalf("principal A saw %s for %s", cap.GrantID, cap.AgentID)
		}
		seen[cap.GrantID] = cap
	}
	if seen[grant.ID].Status != GrantRevoked || seen[classGrant.ID].Status != GrantActive {
		t.Fatalf("statuses %#v", seen)
	}
	if seen[classGrant.ID].CredentialClass != "password" || seen[classGrant.ID].CredentialID != "" {
		t.Fatal("class capability binding")
	}
	bCaps, err := principalB.Capabilities(time.Now().UTC())
	if err != nil || len(bCaps) != 1 || bCaps[0].GrantID != bGrant.ID {
		t.Fatalf("principal B caps %#v %v", bCaps, err)
	}
	unknown, err := session.Agent(strings.Repeat("ab", 16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unknown.Capabilities(time.Now().UTC()); !errors.Is(err, ErrAgentNotFound) {
		t.Fatal(err)
	}
	malformed, err := session.Agent("not-an-id-" + string(sentinel))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := malformed.Capabilities(time.Now().UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}

	got, err := session.Get(api.ID)
	if err != nil || !bytes.Equal(got.Secret, sentinel) {
		t.Fatal("human get failed after grants")
	}
	if _, err := session.Put("later", "generic", randBytesT(t, 16), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(session.audit); err != nil {
		t.Fatal(err)
	}
	assertAuditReasons(t, session.audit, map[string]int{
		resultDeniedMissing:    1,
		resultDeniedAgent:      1,
		resultDeniedCredential: 1,
		resultDeniedOperation:  1,
		resultDeniedScope:      1,
		resultDeniedExpired:    1,
		resultDeniedRevoked:    1,
		resultAllowed:          1,
	})

	session.Lock()
	raw := readAll(t, path)
	assertAbsent(t, raw, sentinel)
	assertAbsent(t, raw, other)
	assertAbsent(t, raw, pass)
	assertAbsent(t, raw, []byte(scope))
	assertAbsent(t, logs.Bytes(), sentinel)
	assertAbsent(t, logs.Bytes(), other)
	assertAbsent(t, logs.Bytes(), pass)
	assertAbsent(t, logs.Bytes(), []byte(scope))
	for _, ev := range mustAudit(t, path) {
		fields := strings.Join([]string{ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation, ev.Time}, "\n")
		if strings.Contains(fields, string(sentinel)) || strings.Contains(fields, string(pass)) || strings.Contains(fields, scope) || strings.Contains(fields, "get_secret") || strings.Contains(fields, "not-an-id") {
			t.Fatal("audit recorded secret material or caller scope")
		}
	}

	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	again, err := opened.Agent(agentA.ID)
	if err != nil {
		t.Fatal(err)
	}
	caps, err = again.Capabilities(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cap := range caps {
		if cap.GrantID == classGrant.ID && cap.Status == GrantActive && cap.Resource == scope+"-pass" {
			found = true
		}
		if cap.GrantID == bGrant.ID {
			t.Fatal("reopened principal listed another agent")
		}
	}
	if !found {
		t.Fatal("class grant did not survive reopen")
	}
	if _, err := again.Authorize(pw.ID, OpSign, scope+"-pass", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	round, err := opened.Get(api.ID)
	if err != nil || !bytes.Equal(round.Secret, sentinel) {
		t.Fatal("secret mismatch after reopen")
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
}

func assertAuditReasons(t *testing.T, events []auditEvent, want map[string]int) {
	t.Helper()
	got := map[string]int{}
	var allowedAuth int
	for _, ev := range events {
		if ev.Action != actionAuthorize {
			continue
		}
		got[ev.Result]++
		if ev.Result == resultAllowed {
			allowedAuth++
			if ev.AgentID == "" || ev.GrantID == "" || ev.CredID == "" || ev.Operation == "" {
				t.Fatalf("allowed authorize missing identifiers %+v", ev)
			}
		}
	}
	for result, n := range want {
		if result == resultAllowed {
			if allowedAuth < n {
				t.Fatalf("allowed authorizes %d", allowedAuth)
			}
			continue
		}
		if got[result] < n {
			t.Fatalf("result %s count %d", result, got[result])
		}
	}
}

func TestGrantCommitFailureRollsBack(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 32)
	cred, err := session.Put("label", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	before := len(session.audit)
	beforeHead := session.header.AuditHead
	session.commitFault = func() error { return errors.New("induced") }
	if _, err := session.CreateAgent("alpha"); !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	if len(session.agents) != 0 || len(session.audit) != before || session.header.AuditHead != beforeHead {
		t.Fatal("failed agent create changed the session")
	}
	session.commitFault = nil
	agent, err := session.CreateAgent("alpha")
	if err != nil {
		t.Fatal(err)
	}
	session.commitFault = func() error { return errors.New("induced") }
	_, err = session.IssueGrant(GrantSpec{
		AgentID:      agent.ID,
		CredentialID: cred.ID,
		Operations:   []string{OpHTTPRequest},
		Resource:     "svc:one",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	})
	if !errors.Is(err, ErrAudit) || len(session.grants) != 0 {
		t.Fatal(err)
	}
	session.commitFault = nil
	grant, err := session.IssueGrant(GrantSpec{
		AgentID:      agent.ID,
		CredentialID: cred.ID,
		Operations:   []string{OpHTTPRequest},
		Resource:     "svc:one",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	session.commitFault = func() error { return errors.New("induced") }
	id, err := principal.Authorize(cred.ID, OpHTTPRequest, "svc:one", time.Now().UTC())
	if !errors.Is(err, ErrAudit) || id != "" || bytes.Contains([]byte(err.Error()), secret) {
		t.Fatalf("id %q err %v", id, err)
	}
	authz := 0
	for _, ev := range session.audit {
		if ev.Action == actionAuthorize {
			authz++
		}
	}
	if authz != 0 {
		t.Fatal("rolled-back authorize stayed in the session")
	}
	session.commitFault = nil
	if _, err := principal.Authorize(cred.ID, OpHTTPRequest, "svc:one", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	assertAbsent(t, readAll(t, path), secret)
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Lock()
	if len(opened.agents) != 1 || opened.agents[0].ID != agent.ID || len(opened.grants) != 1 || opened.grants[0].ID != grant.ID {
		t.Fatal("agent or grant missing after rollback recovery")
	}
	var allowed int
	for _, ev := range opened.audit {
		if ev.Action == actionAuthorize && ev.Result == resultAllowed {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("durable authorizes %d", allowed)
	}
}

func TestCorruptGrantFailsClosed(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	secret := randBytesT(t, 32)
	cred, err := session.Put("label", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := session.CreateAgent("alpha")
	if err != nil {
		t.Fatal(err)
	}
	head := session.header.AuditHead
	seq := session.header.AuditSeq
	aad := dataAAD(session.id, head, seq)
	now := time.Now().UTC()
	humanAgents := append([]agentRecord{}, session.agents...)
	humanAgents[0].Kind = "human"
	badGrant := grantRecord{
		ID:           strings.Repeat("cd", 16),
		AgentID:      agent.ID,
		CredentialID: cred.ID,
		Operations:   []string{"get_secret"},
		Resource:     "svc",
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Hour),
	}
	both := grantRecord{
		ID:              strings.Repeat("ef", 16),
		AgentID:         agent.ID,
		CredentialID:    cred.ID,
		CredentialClass: "generic",
		Operations:      []string{OpHTTPRequest},
		Resource:        "svc",
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Hour),
	}
	cases := []document{
		{Credentials: session.creds, Agents: humanAgents},
		{Credentials: session.creds, Agents: session.agents, Grants: []grantRecord{badGrant}},
		{Credentials: session.creds, Agents: session.agents, Grants: []grantRecord{both}},
	}
	var sealed []struct {
		nonce []byte
		data  []byte
	}
	for _, doc := range cases {
		plain, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		nonce, data, err := seal(session.dek, plain, aad)
		wipe(plain)
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, struct {
			nonce []byte
			data  []byte
		}{nonce, data})
	}
	session.Lock()

	tagged := filepath.Join(t.TempDir(), "tagged.db")
	copyFile(t, path, tagged)
	mutateDB(t, tagged, func(db *sql.DB) {
		if _, err := db.Exec(`UPDATE audit SET agent_id=? WHERE seq=1`, strings.Repeat("ab", 16)); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := Unlock(tagged, pass, nil); !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}

	for i, blob := range sealed {
		copyPath := filepath.Join(t.TempDir(), "vault.db")
		copyFile(t, path, copyPath)
		mutateDB(t, copyPath, func(db *sql.DB) {
			if _, err := db.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=?`, blob.nonce, blob.data); err != nil {
				t.Fatal(err)
			}
		})
		_, err := Unlock(copyPath, pass, log.New(&logs, "", 0))
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("case %d: %v", i, err)
		}
		if bytes.Contains([]byte(err.Error()), secret) || strings.Contains(err.Error(), string(pass)) || strings.Contains(err.Error(), "get_secret") {
			t.Fatal("rejection error contains secret material")
		}
		db, header, events, err := loadVault(copyPath)
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
		if header.AuditHead != head || header.AuditSeq != seq {
			t.Fatal("corrupt document advanced the audit head")
		}
		last := events[len(events)-1]
		if last.Action != actionUnlock || last.Result != resultDenied || last.AgentID != "" || last.CredID != "" {
			t.Fatalf("denial %+v", last)
		}
		assertAbsent(t, readAll(t, copyPath), secret)
	}
	assertAbsent(t, logs.Bytes(), secret)
	assertAbsent(t, logs.Bytes(), pass)
}

package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSharedSyntheticDemo(t *testing.T) {
	env := newSharedEnv(t)
	spec := env.requestSpec(time.Hour, 30*time.Minute)
	req, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.bob.Approve(req.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("member approve %v", err)
	}
	grant, err := env.alice.Approve(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Resource != spec.Resource || grant.CredentialID != env.cred.ID || grant.AgentID != env.agent.ID || grant.KeyID == "" {
		t.Fatalf("grant drifted %#v", grant)
	}
	if _, err := env.alice.Approve(req.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("second approve %v", err)
	}
	payload := []byte("demo-artifact")
	att := env.attest(t, payload)
	if !VerifyLocalAttestation(att.PublicKey[:], spec.Resource, payload, att.Signature[:]) {
		t.Fatal("signature did not verify")
	}
	env.reopen(t)
	att = env.attest(t, payload)
	if !VerifyLocalAttestation(att.PublicKey[:], spec.Resource, payload, att.Signature[:]) {
		t.Fatal("signature did not verify after reopen")
	}
	if err := env.alice.RevokeGrant(grant.ID); err != nil {
		t.Fatal(err)
	}
	principal, err := env.s.Agent(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: spec.Resource, Payload: payload}); !errors.Is(err, ErrDeniedRevoked) {
		t.Fatalf("revoked use %v", err)
	}
	if grants := sharedGrantCount(env.s); grants != 1 {
		t.Fatalf("grants %d", grants)
	}
}

func TestSharedDeniesBypassAndPreservesSingleUser(t *testing.T) {
	env := newSharedEnv(t)
	if _, err := env.s.IssueGrant(GrantSpec{
		AgentID: env.agent.ID, CredentialID: env.cred.ID,
		Operations: []string{OpLocalArtifactAttest}, Resource: "artifact:direct",
		ExpiresAt: time.Now().Add(time.Hour),
	}); !errors.Is(err, ErrDenied) {
		t.Fatalf("direct issue %v", err)
	}
	if _, err := env.s.Get(env.cred.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("shared get %v", err)
	}
	if _, err := env.bob.Put("nope", "generic", []byte("not-the-secret-value"), PutOptions{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("member put %v", err)
	}
	if _, err := env.alice.CreateAgent("worker-2"); err != nil {
		t.Fatal(err)
	}
	self := env.requestSpec(time.Hour, 20*time.Minute)
	own, err := env.alice.RequestAccess(self)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Approve(own.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("self approve %v", err)
	}
	forged := strings.Repeat("ab", 16)
	ghost, err := env.s.BindHuman(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ghost.Approve(own.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("forged approve %v", err)
	}
	agentHuman, err := env.s.BindHuman(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentHuman.Approve(own.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("agent as human %v", err)
	}
	if err := env.alice.Remove(env.aliceID); !errors.Is(err, ErrDenied) {
		t.Fatalf("last owner remove %v", err)
	}
	if err := env.alice.AssignRole(env.aliceID, RoleMember); !errors.Is(err, ErrDenied) {
		t.Fatalf("last owner demote %v", err)
	}
	if _, err := env.s.BindHuman("not-a-human"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad id %v", err)
	}
	blob := readAll(t, env.path)
	if bytes.Contains(blob, []byte(forged)) || bytes.Contains(blob, []byte("not-a-human")) {
		t.Fatal("unknown caller was stored")
	}
	for _, ev := range env.s.audit {
		if ev.ActorID == forged || strings.Contains(ev.TargetID, "not-a-human") {
			t.Fatal("unknown caller became an audit id")
		}
	}
	humanType := reflect.TypeOf(&HumanPrincipal{})
	for i := 0; i < humanType.NumMethod(); i++ {
		m := humanType.Method(i)
		if m.Name == "Get" || strings.Contains(strings.ToLower(m.Name), "session") || m.Name == "BindHuman" || m.Name == "BootstrapShared" || m.Name == "SetNotifier" {
			t.Fatal(m.Name)
		}
		for j := 0; j < m.Type.NumOut(); j++ {
			if m.Type.Out(j) == reflect.TypeOf(&Session{}) {
				t.Fatal("human method returns the session")
			}
		}
	}
	if reflect.TypeOf(&AgentPrincipal{}).NumMethod() != 6 {
		t.Fatal("agent method set changed")
	}

	path, pass, session := mustCreate(t, nil)
	secret := randBytesT(t, 24)
	cred, err := session.Put("solo", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := session.Get(cred.ID)
	if err != nil || !bytes.Equal(got.Secret, secret) {
		t.Fatal("single-user retrieval")
	}
	if session.shared() {
		t.Fatal("legacy vault became shared")
	}
	session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil || opened.shared() {
		t.Fatal(err)
	}
	opened.Lock()
}

func TestSharedIsolatesOrganizations(t *testing.T) {
	a := newSharedEnv(t)
	b := newSharedEnv(t)
	req, err := a.bob.RequestAccess(a.requestSpec(time.Hour, 15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.alice.Approve(req.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign approve %v", err)
	}
	listed, err := b.alice.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range listed {
		if c.ID == a.cred.ID {
			t.Fatal("other vault credential was listed")
		}
	}
	if a.s.org.ID == b.s.org.ID || a.s.id == b.s.id {
		t.Fatal("organizations were not distinct")
	}
}

func TestSharedRequestSubstitutionAndSingleApproval(t *testing.T) {
	env := newSharedEnv(t)
	spec := env.requestSpec(time.Hour, 20*time.Minute)
	req, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.bob.RequestAccess(AccessRequestSpec{
		AgentID: env.agent.ID, CredentialID: env.cred.ID, Resource: "artifact:*",
		ExpiresAt: spec.ExpiresAt, Deadline: spec.Deadline,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatal("wildcard resource")
	}
	other, err := env.alice.Put("other", "generic", randBytesT(t, 16), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.bob.RequestAccess(AccessRequestSpec{
		AgentID: env.agent.ID, CredentialID: other.ID, Resource: "artifact:other",
		ExpiresAt: spec.ExpiresAt, Deadline: spec.Deadline,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatal("non-attestation credential")
	}
	if err := env.bob.Cancel(req.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Approve(req.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("cancelled approve %v", err)
	}
	req, err = env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.alice.Reject(req.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Approve(req.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("rejected approve %v", err)
	}
	req, err = env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	env.s.clock = func() time.Time { return time.Now().Add(21 * time.Minute) }
	if _, err := env.alice.Approve(req.ID); !errors.Is(err, ErrDeniedExpired) {
		t.Fatalf("expired approve %v", err)
	}
	env.s.clock = nil
	req, err = env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, 2)
	grants := make([]Grant, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			grants[i], errs[i] = env.alice.Approve(req.ID)
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for i := range errs {
		if errs[i] == nil {
			ok++
			if grants[i].Resource != spec.Resource {
				t.Fatal("approved scope changed")
			}
		}
	}
	if ok != 1 || sharedGrantCount(env.s) != 1 {
		t.Fatalf("approvals %d grants %d errs %v", ok, sharedGrantCount(env.s), errs)
	}
	foreign := strings.Repeat("cd", 16)
	if _, err := env.alice.Approve(foreign); !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign %v", err)
	}
	for _, ev := range env.s.audit {
		if ev.RequestID == foreign {
			t.Fatal("foreign request id was stored")
		}
	}
}

func TestSharedRemovalExpiryAndStaleSession(t *testing.T) {
	env := newSharedEnv(t)
	spec := env.requestSpec(2*time.Hour, 30*time.Minute)
	req, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Approve(req.ID); err != nil {
		t.Fatal(err)
	}
	payload := []byte("still-valid")
	env.attest(t, payload)
	if err := env.alice.Remove(env.bobID); err != nil {
		t.Fatal(err)
	}
	principal, err := env.s.Agent(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: spec.Resource, Payload: payload}); !errors.Is(err, ErrDeniedRevoked) {
		t.Fatalf("removed requester %v", err)
	}
	if err := env.alice.Attach(env.bobID, RoleMember); err != nil {
		t.Fatal(err)
	}
	env.reopen(t)
	principal, err = env.s.Agent(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: spec.Resource, Payload: payload}); !errors.Is(err, ErrDeniedRevoked) {
		t.Fatalf("reenrollment revived %v", err)
	}
	again, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Approve(again.ID); err != nil {
		t.Fatal(err)
	}
	env.attest(t, payload)
	carol, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.alice.Attach(carol, RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := env.alice.AssignRole(env.aliceID, RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: spec.Resource, Payload: payload}); !errors.Is(err, ErrDeniedRevoked) {
		t.Fatalf("demotion revived %v", err)
	}
	env.s.clock = func() time.Time { return time.Now().Add(3 * time.Hour) }
	fresh := newSharedEnv(t)
	freq, err := fresh.bob.RequestAccess(fresh.requestSpec(4*time.Hour, 30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.alice.Approve(freq.ID); err != nil {
		t.Fatal(err)
	}
	fresh.s.clock = func() time.Time { return time.Now().Add(5 * time.Hour) }
	fp, err := fresh.s.Agent(fresh.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fp.LocalAttest(LocalAttestRequest{CredentialID: fresh.cred.ID, Resource: freq.Resource, Payload: payload}); !errors.Is(err, ErrDeniedExpired) {
		t.Fatalf("expiry %v", err)
	}

	stale := newSharedEnv(t)
	sreq, err := stale.bob.RequestAccess(stale.requestSpec(time.Hour, 20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	other, err := Unlock(stale.path, stale.pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Lock)
	bob2, err := other.BindHuman(stale.bobID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob2.RequestAccess(stale.requestSpec(time.Hour, 10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The second session committed, so the first session's cache is stale.
	if _, err := stale.alice.Approve(sreq.ID); !errors.Is(err, ErrStale) && !errors.Is(err, ErrCorrupt) {
		t.Fatalf("stale approve %v", err)
	}
	if _, err := stale.s.Agent(stale.agent.ID); !errors.Is(err, ErrStale) {
		t.Fatalf("stale session still usable %v", err)
	}
}

func TestSharedFaultsLeaveNoPartialAuthority(t *testing.T) {
	env := newSharedEnv(t)
	env.s.commitFault = func() error { return errors.New("disk") }
	dave, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.alice.Attach(dave, RoleMember); !errors.Is(err, ErrAudit) {
		t.Fatalf("fault attach %v", err)
	}
	env.s.commitFault = nil
	env.reopen(t)
	if _, ok := env.s.member(dave); ok {
		t.Fatal("failed attach persisted")
	}
	env.s.commitFault = func() error { return errors.New("disk") }
	if _, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 15*time.Minute)); !errors.Is(err, ErrAudit) {
		t.Fatalf("fault request %v", err)
	}
	env.s.commitFault = nil
	env.reopen(t)
	if len(env.s.requests) != 0 {
		t.Fatal("failed request persisted")
	}
	req, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	env.s.commitFault = func() error { return errors.New("disk") }
	if _, err := env.alice.Approve(req.ID); !errors.Is(err, ErrAudit) {
		t.Fatalf("fault approve %v", err)
	}
	env.s.commitFault = nil
	env.reopen(t)
	if sharedGrantCount(env.s) != 0 {
		t.Fatal("failed approval left a grant")
	}
	pending := false
	for _, r := range env.s.requests {
		if r.ID == req.ID && r.Status == requestPending {
			pending = true
		}
	}
	if !pending {
		t.Fatal("request was consumed by a failed approval")
	}
	grant, err := env.alice.Approve(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	env.s.commitFault = func() error { return errors.New("disk") }
	if err := env.alice.RevokeGrant(grant.ID); !errors.Is(err, ErrAudit) {
		t.Fatalf("fault revoke %v", err)
	}
	env.s.commitFault = nil
	env.reopen(t)
	g, ok := env.s.grantByID(grant.ID)
	if !ok || g.RevokedAt != nil {
		t.Fatal("failed revoke changed the grant")
	}
	principal, err := env.s.Agent(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	env.s.attestFault = func() error { return errors.New("sign") }
	if _, err := principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: req.Resource, Payload: []byte("x")}); !errors.Is(err, ErrSignFailed) {
		t.Fatalf("fault sign %v", err)
	}
}

func TestSharedTamperLegacyAndOldReader(t *testing.T) {
	env := newSharedEnv(t)
	req, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Approve(req.ID); err != nil {
		t.Fatal(err)
	}
	plain := env.plaintext(t)
	var old struct {
		Credentials  []credential   `json:"credentials"`
		Agents       []agentRecord  `json:"agents,omitempty"`
		Grants       []grantRecord  `json:"grants,omitempty"`
		Detection    detectionState `json:"detection"`
		HealthPolicy healthPolicy   `json:"health_policy,omitempty"`
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&old); err == nil {
		t.Fatal("previous document shape accepted shared storage")
	}
	if err := validateSharedState(nil, []membershipRecord{{
		HumanID: strings.Repeat("ab", 16), Role: RoleOwner, Generation: 1, State: memberActive,
	}}, nil, nil, nil, nil); err == nil {
		t.Fatal("memberships without an organization opened as legacy")
	}
	env.reopen(t)
	path, pass := env.path, append([]byte(nil), env.pass...)
	env.s.Lock()
	mutated := filepath.Join(t.TempDir(), "actor.db")
	copyFile(t, path, mutated)
	mutateDB(t, mutated, func(db *sql.DB) {
		if _, err := db.Exec(`UPDATE audit SET actor_id=? WHERE seq=1`, strings.Repeat("ab", 16)); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := Unlock(mutated, pass, nil); !errors.Is(err, ErrAudit) {
		t.Fatalf("v1 actor column %v", err)
	}

	broken := filepath.Join(t.TempDir(), "link.db")
	copyFile(t, path, broken)
	opened, err := Unlock(broken, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.requests) == 0 {
		t.Fatal("missing request")
	}
	opened.requests[0].RequesterGen++
	sealCurrent(t, opened)
	opened.Lock()
	if _, err := Unlock(broken, pass, nil); !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrAudit) {
		t.Fatalf("tampered generation %v", err)
	}
}

func sealCurrent(t *testing.T, s *Session) {
	t.Helper()
	plain, err := json.Marshal(document{
		Credentials: s.creds, Agents: s.agents, Grants: s.grants,
		Detection: s.detection, HealthPolicy: s.hpolicy,
		Organization: s.org, Memberships: s.members, Requests: s.requests,
	})
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := seal(s.dek, plain, dataAAD(s.id, s.header.AuditHead, s.header.AuditSeq))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=? WHERE id=?`, nonce, ct, s.id); err != nil {
		t.Fatal(err)
	}
}

func TestSharedStateSurvivesDocumentWriters(t *testing.T) {
	env := newSharedEnv(t)
	req, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Put("next", CredTypeEd25519, env.der, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Replace(env.cred.ID, env.der, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.CreateAgent("another"); err != nil {
		t.Fatal(err)
	}
	org := env.s.org.ID
	env.reopen(t)
	if env.s.org == nil || env.s.org.ID != org || len(env.s.members) != 2 {
		t.Fatal("membership was erased by a later commit")
	}
	found := false
	for _, r := range env.s.requests {
		if r.ID == req.ID && r.Status == requestPending {
			found = true
		}
	}
	if !found {
		t.Fatal("request was erased by a later commit")
	}
	legacy, pass, session := mustCreate(t, nil)
	if _, err := session.Put("solo", "generic", randBytesT(t, 8), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	opened, err := Unlock(legacy, pass, nil)
	if err != nil || opened.org != nil || len(opened.members) != 0 {
		t.Fatal("legacy open inferred a membership")
	}
	opened.Lock()
}

func TestSharedSentinelReentryAndRace(t *testing.T) {
	var logs bytes.Buffer
	env := newSharedEnvLog(t, &logs)
	sink := &MemoryNotifier{}
	if err := env.s.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	reentered := false
	env.s.notifier = reentryNotifier{fn: func(n Notification) error {
		reentered = true
		if _, err := env.alice.Credentials(); err != nil {
			t.Errorf("reentry %v", err)
		}
		return sink.Notify(n)
	}}
	req, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := env.alice.Approve(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reentered || len(sink.Snapshot()) == 0 {
		t.Fatal("owner notification did not run")
	}
	payload := []byte(env.sentinel)
	principal, err := env.s.Agent(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	att, err := principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: env.resource, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(att)
	caps, err := principal.Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	rawCaps, _ := json.Marshal(caps)
	notes, _ := json.Marshal(sink.Snapshot())
	blob := readAll(t, env.path)
	for _, surface := range [][]byte{raw, rawCaps, notes, logs.Bytes()} {
		if bytes.Contains(surface, env.secret) || bytes.Contains(surface, env.pass) || bytes.Contains(surface, []byte(env.label)) {
			t.Fatal("sentinel reached a plaintext surface")
		}
	}
	if bytes.Contains(blob, env.secret) || bytes.Contains(blob, env.pass) || bytes.Contains(blob, []byte(env.label)) {
		t.Fatal("sentinel reached the database file")
	}
	for _, ev := range env.s.audit {
		encoded, _ := json.Marshal(ev)
		if bytes.Contains(encoded, env.secret) || bytes.Contains(encoded, []byte(env.resource)) || bytes.Contains(encoded, []byte(env.label)) {
			t.Fatalf("audit row leaked %s", ev.Action)
		}
	}
	listed, err := env.bob.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range listed {
		if c.Label != "" || len(c.Secret) != 0 || c.Lifecycle != (Lifecycle{}) || c.ID == "" || c.Type == "" {
			t.Fatal("member saw more than credential id and type")
		}
	}
	if grant.ID == "" {
		t.Fatal("missing grant")
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, _ = env.bob.RequestAccess(env.requestSpec(time.Hour, 10*time.Minute))
	}()
	go func() {
		defer wg.Done()
		<-start
		_ = env.alice.Attach(mustID(t), RoleMember)
	}()
	close(start)
	wg.Wait()
	if err := validateSharedState(env.s.org, env.s.members, env.s.requests, env.s.creds, env.s.agents, env.s.grants); err != nil {
		t.Fatal(err)
	}
}

func TestSharedBootstrapRepeatIsDenied(t *testing.T) {
	env := newSharedEnv(t)
	org := env.s.org.ID
	if err := env.s.BootstrapShared(env.bobID); !errors.Is(err, ErrDenied) {
		t.Fatalf("repeat bootstrap %v", err)
	}
	if env.s.org == nil || env.s.org.ID != org || len(env.s.members) != 2 {
		t.Fatal("repeat bootstrap changed the binding")
	}
	if _, ok := env.s.member(env.bobID); !ok {
		t.Fatal("member missing")
	}
	bob, _ := env.s.member(env.bobID)
	if bob.Role != RoleMember {
		t.Fatal("repeat bootstrap promoted the member")
	}
}

func TestSharedMemberViewAndGrantStatus(t *testing.T) {
	env := newSharedEnv(t)
	owner, err := env.alice.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	member, err := env.bob.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(owner) == 0 || len(owner) != len(member) {
		t.Fatalf("inventory owner %d member %d", len(owner), len(member))
	}
	for i := range owner {
		if owner[i].Label == "" || owner[i].Lifecycle.State != StateActive {
			t.Fatalf("owner view %+v", owner[i])
		}
		if member[i].ID != owner[i].ID || member[i].Type != owner[i].Type || member[i].Label != "" || len(member[i].Secret) != 0 || member[i].Lifecycle != (Lifecycle{}) {
			t.Fatalf("member view %+v", member[i])
		}
	}
	spec := env.requestSpec(time.Hour, 20*time.Minute)
	req, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := env.bob.Requests()
	if err != nil || len(pending) != 1 || pending[0].Status != requestPending || pending[0].GrantStatus != "" {
		t.Fatalf("pending %+v %v", pending, err)
	}
	grant, err := env.alice.Approve(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st := requestStatus(t, env.bob, req.ID); st != GrantActive {
		t.Fatalf("active %s", st)
	}
	env.s.clock = func() time.Time { return spec.ExpiresAt }
	if st := requestStatus(t, env.bob, req.ID); st != GrantExpired {
		t.Fatalf("expired %s", st)
	}
	env.s.clock = nil
	if st := requestStatus(t, env.bob, req.ID); st != GrantActive {
		t.Fatalf("clock reset %s", st)
	}
	carolID := mustID(t)
	if err := env.alice.Attach(carolID, RoleOwner); err != nil {
		t.Fatal(err)
	}
	carol, err := env.s.BindHuman(carolID)
	if err != nil {
		t.Fatal(err)
	}
	if err := carol.AssignRole(env.aliceID, RoleMember); err != nil {
		t.Fatal(err)
	}
	if st := requestStatus(t, env.bob, req.ID); st != requestInvalidated {
		t.Fatalf("demotion %s", st)
	}
	if err := carol.AssignRole(env.aliceID, RoleOwner); err != nil {
		t.Fatal(err)
	}
	if st := requestStatus(t, env.bob, req.ID); st != requestInvalidated {
		t.Fatalf("repromotion revived %s", st)
	}
	env.reopen(t)
	if st := requestStatus(t, env.bob, req.ID); st != requestInvalidated {
		t.Fatalf("reopen %s", st)
	}
	daveID := mustID(t)
	if err := env.alice.Attach(daveID, RoleMember); err != nil {
		t.Fatal(err)
	}
	dave, err := env.s.BindHuman(daveID)
	if err != nil {
		t.Fatal(err)
	}
	others, err := dave.Requests()
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range others {
		if rec.ID == req.ID {
			t.Fatal("other member saw the request")
		}
	}
	again, err := env.bob.RequestAccess(env.requestSpec(2*time.Hour, 20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	second, err := env.alice.Approve(again.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.alice.RevokeGrant(second.ID); err != nil {
		t.Fatal(err)
	}
	if st := requestStatus(t, env.bob, again.ID); st != GrantRevoked {
		t.Fatalf("revoked %s", st)
	}
	env.reopen(t)
	if st := requestStatus(t, env.bob, again.ID); st != GrantRevoked {
		t.Fatalf("revoked reopen %s", st)
	}
	if grant.ID == "" || second.ID == "" {
		t.Fatal("missing grant")
	}
}

func TestCommitExtendsBootstrapBinding(t *testing.T) {
	_, _, legacy := mustCreate(t, nil)
	t.Cleanup(legacy.Lock)
	for i := 0; i < 24; i++ {
		if err := legacy.persistEvent(actionList, "", "", resultAllowed); err != nil {
			t.Fatal(err)
		}
	}
	before := len(legacy.audit)
	bootstrapApplyVisits = 0
	if err := legacy.persistEvent(actionList, "", "", resultAllowed); err != nil {
		t.Fatal(err)
	}
	if got, want := bootstrapApplyVisits, len(legacy.audit)-before; got != want {
		t.Fatalf("legacy commit visited %d rows, wrote %d", got, want)
	}
	if legacy.bootstrap.shared {
		t.Fatal("legacy binding became shared")
	}
	legacy.commitFault = func() error { return errors.New("full") }
	if err := legacy.BootstrapShared(mustID(t)); err == nil {
		t.Fatal("faulted bootstrap succeeded")
	}
	legacy.commitFault = nil
	if legacy.bootstrap.shared || legacy.org != nil {
		t.Fatal("faulted bootstrap published shared mode")
	}
	if _, err := legacy.Put("label", "generic", []byte("secret"), PutOptions{}); err != nil {
		t.Fatal(err)
	}

	env := newSharedEnv(t)
	before = len(env.s.audit)
	bootstrapApplyVisits = 0
	req, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := bootstrapApplyVisits, len(env.s.audit)-before; got != want {
		t.Fatalf("request visited %d rows, wrote %d", got, want)
	}
	marked := len(env.s.audit)
	saved := env.s.bootstrap
	org, members, requests := env.s.org, env.s.members, env.s.requests
	env.s.org, env.s.members, env.s.requests = nil, nil, nil
	ev, err := nextEvent(env.s.audit, actionList, env.s.id, "", "", resultDenied)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.s.commitBatch([]auditEvent{ev}, env.s.creds, env.s.agents, env.s.grants, false, nil, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("downgrade commit %v", err)
	}
	if len(env.s.audit) != marked || env.s.bootstrap != saved {
		t.Fatal("rejected downgrade published state")
	}
	env.s.org, env.s.members, env.s.requests = org, members, requests
	if _, err := saved.extend([]auditEvent{{
		Action: actionBootstrap, Result: resultAllowed, OrgID: mustID(t), VaultID: env.s.id,
	}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("conflicting bootstrap %v", err)
	}
	again, err := saved.extend([]auditEvent{{
		Action: actionBootstrap, Result: resultAllowed, OrgID: saved.orgID, VaultID: saved.vaultID,
	}})
	if err != nil || again != saved {
		t.Fatalf("repeat bootstrap %+v %v", again, err)
	}

	if _, err := env.alice.Approve(req.ID); err != nil {
		t.Fatal(err)
	}
	before = len(env.s.audit)
	bootstrapApplyVisits = 0
	env.attest(t, []byte("payload"))
	if got, want := bootstrapApplyVisits, len(env.s.audit)-before; got != want {
		t.Fatalf("attest visited %d rows, wrote %d", got, want)
	}
	bound, err := (bootstrapBind{}).extend(env.s.audit)
	if err != nil || env.s.bootstrap != bound {
		t.Fatalf("binding %+v chain %+v %v", env.s.bootstrap, bound, err)
	}
	env.reopen(t)
	if env.s.bootstrap != bound {
		t.Fatalf("reopen binding %+v", env.s.bootstrap)
	}
	before = len(env.s.audit)
	bootstrapApplyVisits = 0
	if _, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, want := bootstrapApplyVisits, len(env.s.audit)-before; got != want {
		t.Fatalf("reopen commit visited %d rows, wrote %d", got, want)
	}
}

func TestSharedExpiryAndHistoryDowngrade(t *testing.T) {
	env := newSharedEnv(t)
	rows, err := env.alice.Audit(AuditFilter{})
	if err != nil || len(rows) == 0 {
		t.Fatalf("owner audit %v", err)
	}
	org := env.s.org
	members := append([]membershipRecord{}, env.s.members...)
	requests := append([]requestRecord{}, env.s.requests...)
	env.s.org = nil
	env.s.members = nil
	env.s.requests = nil
	if _, err := env.s.AuditHistory(AuditFilter{}); !errors.Is(err, ErrAudit) {
		t.Fatalf("cached audit accepted a shared downgrade %v", err)
	}
	env.s.org = org
	env.s.members = members
	env.s.requests = requests

	path, pass := env.path, append([]byte(nil), env.pass...)
	env.s.org = nil
	env.s.members = nil
	env.s.requests = nil
	sealCurrent(t, env.s)
	env.s.Lock()
	if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
		t.Fatalf("empty-grant downgrade verified %v", err)
	}
	if opened, err := Unlock(path, pass, nil); err == nil {
		if _, getErr := opened.Get("any"); getErr == nil {
			t.Fatal("downgrade allowed legacy get")
		}
		opened.Lock()
		t.Fatalf("empty-grant downgrade unlocked")
	}

	live := newSharedEnv(t)
	spec := live.requestSpec(time.Hour, 20*time.Minute)
	req, err := live.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := live.alice.Approve(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range live.s.grants {
		if live.s.grants[i].ID == grant.ID {
			live.s.grants[i].ExpiresAt = spec.ExpiresAt.Add(2 * time.Hour)
		}
	}
	sealCurrent(t, live.s)
	live.s.Lock()
	if _, err := VerifyAudit(live.path, live.pass); !errors.Is(err, ErrAudit) {
		t.Fatalf("extended expiry verified %v", err)
	}
	if _, err := Unlock(live.path, live.pass, nil); !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrAudit) {
		t.Fatalf("extended expiry unlocked %v", err)
	}

	use := newSharedEnv(t)
	useSpec := use.requestSpec(time.Hour, 20*time.Minute)
	useReq, err := use.bob.RequestAccess(useSpec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := use.alice.Approve(useReq.ID); err != nil {
		t.Fatal(err)
	}
	use.s.clock = func() time.Time { return useSpec.ExpiresAt }
	principal, err := use.s.Agent(use.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := principal.LocalAttest(LocalAttestRequest{CredentialID: use.cred.ID, Resource: use.resource, Payload: []byte("late")}); !errors.Is(err, ErrDeniedExpired) {
		t.Fatalf("expired use %v", err)
	}
	use.reopen(t)
	use.s.clock = func() time.Time { return useSpec.ExpiresAt }
	principal, err = use.s.Agent(use.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := principal.LocalAttest(LocalAttestRequest{CredentialID: use.cred.ID, Resource: use.resource, Payload: []byte("late")}); !errors.Is(err, ErrDeniedExpired) {
		t.Fatalf("expired reopen %v", err)
	}
	use.s.clock = nil
	rejected, err := use.bob.RequestAccess(use.requestSpec(2*time.Hour, 20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := use.alice.Reject(rejected.ID); err != nil {
		t.Fatal(err)
	}
	use.reopen(t)
	if _, err := use.alice.Approve(rejected.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("rejected request reopened %v", err)
	}

	legacy, legacyPass, session := mustCreate(t, nil)
	secret := randBytesT(t, 16)
	cred, err := session.Put("solo", "generic", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	session.Lock()
	opened, err := Unlock(legacy, legacyPass, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := opened.Get(cred.ID)
	if err != nil || !bytes.Equal(got.Secret, secret) {
		t.Fatal("legacy retrieval")
	}
	opened.Lock()
	if _, err := VerifyAudit(legacy, legacyPass); err != nil {
		t.Fatal(err)
	}
}

func TestSharedDeniedAdminAttribution(t *testing.T) {
	env := newSharedEnv(t)
	secret := randBytesT(t, 16)
	if _, err := env.bob.Put("nope", "generic", secret, PutOptions{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("put %v", err)
	}
	if _, err := env.bob.CreateAgent("nope"); !errors.Is(err, ErrDenied) {
		t.Fatalf("agent %v", err)
	}
	if _, err := env.bob.Replace(env.cred.ID, env.der, LifecycleOptions{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("replace %v", err)
	}
	if n := inventoryCount(env.s, env.bobID, resultDenied); n != 3 {
		t.Fatalf("member denials attributed %d", n)
	}
	forged := strings.Repeat("ef", 16)
	ghost, err := env.s.BindHuman(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ghost.Put("nope", "generic", secret, PutOptions{}); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if _, err := ghost.CreateAgent("nope"); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if _, err := ghost.Replace(env.cred.ID, env.der, LifecycleOptions{}); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	for _, ev := range env.s.audit {
		if ev.ActorID == forged || ev.TargetID == forged || ev.RequestID == forged {
			t.Fatal("foreign caller became an audit id")
		}
	}
	before := len(env.s.creds)
	env.s.commitFault = func() error { return errors.New("disk") }
	if _, err := env.bob.Put("nope", "generic", secret, PutOptions{}); !errors.Is(err, ErrAudit) {
		t.Fatalf("put audit %v", err)
	}
	if _, err := env.bob.CreateAgent("nope"); !errors.Is(err, ErrAudit) {
		t.Fatalf("agent audit %v", err)
	}
	if _, err := env.bob.Replace(env.cred.ID, env.der, LifecycleOptions{}); !errors.Is(err, ErrAudit) {
		t.Fatalf("replace audit %v", err)
	}
	env.s.commitFault = nil
	if len(env.s.creds) != before {
		t.Fatal("failed denial changed credentials")
	}

	env.s.hpolicy.CompromiseOptIn = true
	var nested error
	if err := env.s.SetCompromiseChecker(callChecker{fn: func() {
		_, nested = env.bob.Put("nested", "generic", secret, PutOptions{})
	}}); err != nil {
		t.Fatal(err)
	}
	marked := len(env.s.audit)
	if _, err := env.alice.Put("weak", "password", []byte("password"), PutOptions{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("checker commit %v", err)
	}
	if !errors.Is(nested, ErrDenied) {
		t.Fatalf("nested put %v", nested)
	}
	deniedActors := inventoryActorsAfter(env.s, marked, resultDenied)
	if len(deniedActors) < 2 || deniedActors[0] != env.bobID || deniedActors[1] != env.aliceID {
		t.Fatalf("nested actors %v", deniedActors)
	}
	env.s.checker = nil

	var during error
	if err := env.s.SetNotifier(reentryNotifier{fn: func(Notification) error {
		_, during = env.bob.Put("during-notify", "generic", secret, PutOptions{})
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	marked = len(env.s.audit)
	if _, err := env.alice.Put("weak-2", "password", []byte("password1"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(during, ErrDenied) {
		t.Fatalf("notifier put %v", during)
	}
	if actor := inventoryActorAfter(env.s, marked, resultDenied); actor != env.bobID {
		t.Fatalf("notifier denial actor %s", actor)
	}
	if actor := inventoryActorAfter(env.s, marked, resultAllowed); actor != env.aliceID {
		t.Fatalf("notifier allow actor %s", actor)
	}
}

func TestSharedCallbackReplacement(t *testing.T) {
	env := newSharedEnv(t)
	req, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Approve(req.ID); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-started
		if err := env.s.SetNotifier(nil); err != nil {
			t.Errorf("clear notifier %v", err)
		}
		if err := env.s.SetNotifier(&MemoryNotifier{}); err != nil {
			t.Errorf("replace notifier %v", err)
		}
		close(release)
	}()
	if err := env.s.SetNotifier(reentryNotifier{fn: func(Notification) error {
		if _, err := env.alice.Credentials(); err != nil {
			t.Errorf("reentry %v", err)
		}
		once.Do(func() { close(started) })
		<-release
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	again, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Approve(again.ID); err != nil {
		once.Do(func() { close(started) })
		t.Fatal(err)
	}
	wg.Wait()
}

func TestAttestStopsAfterCredentialChange(t *testing.T) {
	payload := []byte("artifact-body")
	t.Run("replacement", func(t *testing.T) {
		env := approvedShared(t)
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		env.s.attestFault = func() error {
			_, err := env.alice.Replace(env.cred.ID, der, LifecycleOptions{})
			return err
		}
		att, err := env.attestErr(t, payload)
		if !errors.Is(err, ErrDeniedKey) || att != (LocalAttestation{}) {
			t.Fatalf("replacement %+v %v", att, err)
		}
	})
	t.Run("revocation", func(t *testing.T) {
		env := approvedShared(t)
		env.s.attestFault = func() error {
			g := env.s.grants[len(env.s.grants)-1]
			return env.alice.RevokeGrant(g.ID)
		}
		att, err := env.attestErr(t, payload)
		if !errors.Is(err, ErrDeniedRevoked) || att != (LocalAttestation{}) {
			t.Fatalf("revocation %+v %v", att, err)
		}
	})
	t.Run("removal", func(t *testing.T) {
		env := approvedShared(t)
		env.s.attestFault = func() error {
			return env.alice.Remove(env.bobID)
		}
		att, err := env.attestErr(t, payload)
		if !errors.Is(err, ErrDeniedRevoked) || att != (LocalAttestation{}) {
			t.Fatalf("removal %+v %v", att, err)
		}
	})
	t.Run("retarget", func(t *testing.T) {
		_, _, session := mustCreate(t, nil)
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		cred, err := session.Put("k", CredTypeEd25519, der, PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		agent, err := session.CreateAgent("w")
		if err != nil {
			t.Fatal(err)
		}
		resource := "artifact-" + randHex(t, 8)
		exp := time.Now().Add(time.Hour)
		grant, err := session.IssueGrant(GrantSpec{
			AgentID: agent.ID, CredentialID: cred.ID,
			Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: exp,
		})
		if err != nil {
			t.Fatal(err)
		}
		principal, err := session.Agent(agent.ID)
		if err != nil {
			t.Fatal(err)
		}
		_, priv2, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der2, err := x509.MarshalPKCS8PrivateKey(priv2)
		if err != nil {
			t.Fatal(err)
		}
		session.attestFault = func() error {
			if _, err := session.Replace(cred.ID, der2, LifecycleOptions{}); err != nil {
				return err
			}
			_, err := session.IssueGrant(GrantSpec{
				AgentID: agent.ID, CredentialID: cred.ID,
				Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: exp,
			})
			return err
		}
		att, err := principal.LocalAttest(LocalAttestRequest{CredentialID: cred.ID, Resource: resource, Payload: payload})
		if !errors.Is(err, ErrDeniedKey) || att != (LocalAttestation{}) || VerifyLocalAttestation(pub, resource, payload, att.Signature[:]) {
			t.Fatalf("retarget %+v %v", att, err)
		}
		denied := false
		for _, ev := range session.audit {
			if ev.Action == actionLocalAttest && ev.Result == resultDeniedKey {
				denied = true
				if ev.GrantID != grant.ID {
					t.Fatalf("authority moved to %s", ev.GrantID)
				}
			}
		}
		if !denied {
			t.Fatal("key change was not audited")
		}
	})
}

func requestStatus(t *testing.T, h *HumanPrincipal, id string) string {
	t.Helper()
	rows, err := h.Requests()
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range rows {
		if rec.ID == id {
			if rec.Status != requestConsumed {
				t.Fatalf("status %s", rec.Status)
			}
			return rec.GrantStatus
		}
	}
	t.Fatal("request missing")
	return ""
}

func inventoryCount(s *Session, actor, result string) int {
	n := 0
	for _, ev := range s.audit {
		if ev.Action == actionInventory && ev.ActorID == actor && ev.Result == result && ev.OrgID != "" {
			n++
		}
	}
	return n
}

func inventoryActorAfter(s *Session, after int, result string) string {
	actors := inventoryActorsAfter(s, after, result)
	if len(actors) == 0 {
		return ""
	}
	return actors[0]
}

func inventoryActorsAfter(s *Session, after int, result string) []string {
	var out []string
	for _, ev := range s.audit[after:] {
		if ev.Action == actionInventory && ev.Result == result && ev.OrgID != "" {
			out = append(out, ev.ActorID)
		}
	}
	return out
}

func approvedShared(t *testing.T) *sharedEnv {
	t.Helper()
	env := newSharedEnv(t)
	req, err := env.bob.RequestAccess(env.requestSpec(time.Hour, 20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Approve(req.ID); err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *sharedEnv) attestErr(t *testing.T, payload []byte) (LocalAttestation, error) {
	t.Helper()
	principal, err := e.s.Agent(e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	return principal.LocalAttest(LocalAttestRequest{CredentialID: e.cred.ID, Resource: e.resource, Payload: payload})
}

type callChecker struct{ fn func() }

func (c callChecker) Lookup(CompromiseQuery) ([]string, error) {
	if c.fn != nil {
		fn := c.fn
		c.fn = nil
		fn()
	}
	return nil, nil
}

type reentryNotifier struct {
	fn func(Notification) error
}

func (r reentryNotifier) Notify(n Notification) error { return r.fn(n) }

type sharedEnv struct {
	path, aliceID, bobID, label, resource string
	pass, secret, der                     []byte
	sentinel                              string
	s                                     *Session
	alice, bob                            *HumanPrincipal
	cred                                  Credential
	agent                                 Agent
	priv                                  ed25519.PrivateKey
}

func newSharedEnv(t *testing.T) *sharedEnv {
	t.Helper()
	return newSharedEnvLog(t, nil)
}

func newSharedEnvLog(t *testing.T, buf *bytes.Buffer) *sharedEnv {
	t.Helper()
	var logger *log.Logger
	if buf != nil {
		logger = log.New(buf, "", 0)
	}
	path, pass, session := mustCreate(t, logger)
	env := &sharedEnv{
		path: path, pass: pass, s: session,
		label:    "label-" + randHex(t, 16),
		resource: "artifact-" + randHex(t, 16),
		sentinel: "sentinel-" + randHex(t, 16),
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env.priv = priv
	env.secret = append([]byte(nil), derPlaceholder(t, priv)...)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	env.der = der
	env.cred, err = session.Put(env.label, CredTypeEd25519, der, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	env.agent, err = session.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	env.aliceID = mustID(t)
	env.bobID = mustID(t)
	if err := session.BootstrapShared(env.aliceID); err != nil {
		t.Fatal(err)
	}
	env.alice, err = session.BindHuman(env.aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.alice.Attach(env.bobID, RoleMember); err != nil {
		t.Fatal(err)
	}
	env.bob, err = session.BindHuman(env.bobID)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *sharedEnv) requestSpec(life, window time.Duration) AccessRequestSpec {
	now := time.Now().UTC()
	return AccessRequestSpec{
		AgentID: e.agent.ID, CredentialID: e.cred.ID, Resource: e.resource,
		ExpiresAt: now.Add(life), Deadline: now.Add(window),
	}
}

func (e *sharedEnv) attest(t *testing.T, payload []byte) LocalAttestation {
	t.Helper()
	principal, err := e.s.Agent(e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	att, err := principal.LocalAttest(LocalAttestRequest{CredentialID: e.cred.ID, Resource: e.resource, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func (e *sharedEnv) reopen(t *testing.T) {
	t.Helper()
	e.s.Lock()
	opened, err := Unlock(e.path, e.pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opened.Lock)
	e.s = opened
	e.alice, err = opened.BindHuman(e.aliceID)
	if err != nil {
		t.Fatal(err)
	}
	e.bob, err = opened.BindHuman(e.bobID)
	if err != nil {
		t.Fatal(err)
	}
}

func (e *sharedEnv) plaintext(t *testing.T) []byte {
	t.Helper()
	plain, err := openAEAD(e.s.dek, e.s.header.DataNonce, e.s.header.Data, dataAAD(e.s.id, e.s.header.AuditHead, e.s.header.AuditSeq))
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func sharedGrantCount(s *Session) int { return len(s.grants) }

func mustID(t *testing.T) string {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func derPlaceholder(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

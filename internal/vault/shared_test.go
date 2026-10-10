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
		if c.Label != "" || len(c.Secret) != 0 {
			t.Fatal("member saw a label or secret")
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

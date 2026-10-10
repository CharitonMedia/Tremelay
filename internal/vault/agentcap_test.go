package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAgentCapSyntheticDemo(t *testing.T) {
	var logs bytes.Buffer
	env := newSharedEnvLog(t, &logs)
	spec := env.requestSpec(time.Hour, 30*time.Minute)
	req, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := env.alice.Approve(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	cap := bindCap(t, env.s, env.agent.ID)
	listed := capCall(t, cap, okBytes(t)(encodeCapList()))
	if listed.method != capMethodList || len(listed.entries) != 1 {
		t.Fatalf("catalog %+v", listed)
	}
	entry := listed.entries[0]
	if entry.operation != OpLocalArtifactAttest || entry.resource != spec.Resource || entry.keyID != grant.KeyID || entry.status != GrantActive {
		t.Fatalf("entry %+v", entry)
	}
	if _, ok := canonicalAuditTime(entry.expires.Format(time.RFC3339Nano)); !ok {
		t.Fatal(entry.expires)
	}
	rawList, err := cap.Exchange(okBytes(t)(encodeCapList()))
	if err != nil {
		t.Fatal(err)
	}
	assertNoCapLeak(t, rawList, env, grant, nil)
	described := capCall(t, cap, okBytes(t)(encodeCapDescribe(entry.handle)))
	if described.entry.handle != entry.handle || described.entry.resource != entry.resource || described.entry.keyID != entry.keyID || described.entry.status != GrantActive {
		t.Fatalf("describe %+v", described.entry)
	}
	payload := []byte("demo-artifact")
	invoked := capCall(t, cap, okBytes(t)(encodeCapInvoke(entry.handle, payload)))
	if invoked.method != capMethodInvoke || !VerifyLocalAttestation(invoked.att.PublicKey[:], spec.Resource, payload, invoked.att.Signature[:]) {
		t.Fatal("signature did not verify")
	}
	if invoked.att.Domain != AttestDomain || invoked.att.Purpose != AttestPurpose || invoked.att.Resource != spec.Resource {
		t.Fatalf("projection %+v", invoked.att)
	}
	rawInv, err := cap.Exchange(okBytes(t)(encodeCapInvoke(entry.handle, payload)))
	if err != nil {
		t.Fatal(err)
	}
	assertNoCapLeak(t, rawInv, env, grant, payload)
	beforeReq, beforeGrant := len(env.s.requests), len(env.s.grants)
	unsupported := capCall(t, cap, okBytes(t)(encodeCapRequest()))
	if unsupported.code != capUnsupported || unsupported.message != "method is not supported" {
		t.Fatalf("request %+v", unsupported)
	}
	if len(env.s.requests) != beforeReq || len(env.s.grants) != beforeGrant {
		t.Fatal("unsupported request created authority")
	}
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, logs.Bytes(), [][]byte{payload, env.der, []byte(env.sentinel)})
	sawList, sawDescribe, sawAllowed, sawCompleted := false, false, false, false
	for _, ev := range env.s.audit {
		if bytes.Contains([]byte(ev.Operation+ev.Result+ev.AgentID+ev.GrantID), payload) {
			t.Fatal("payload entered an audit field")
		}
		switch {
		case ev.Action == actionCapList && ev.Result == resultAllowed && ev.AgentID == env.agent.ID && ev.GrantID == "":
			sawList = true
		case ev.Action == actionAgentCap && ev.Result == resultAllowed && ev.GrantID == grant.ID && ev.Operation == OpLocalArtifactAttest:
			sawDescribe = true
		case ev.Action == actionLocalAttest && ev.Result == resultAllowed && ev.GrantID == grant.ID:
			sawAllowed = true
		case ev.Action == actionLocalAttest && ev.Result == resultCompleted && ev.GrantID == grant.ID:
			sawCompleted = true
		}
	}
	if !sawList || !sawDescribe || !sawAllowed || !sawCompleted {
		t.Fatalf("audit list=%v describe=%v allowed=%v completed=%v", sawList, sawDescribe, sawAllowed, sawCompleted)
	}
}

func TestAgentCapSchemaAndFixedErrors(t *testing.T) {
	session, cap, _, pub, resource := newSingleAttestCap(t)
	sentinel := "sentinel-schema-" + strings.Repeat("Z", 24)
	cases := []struct {
		name string
		msg  []byte
		code string
	}{
		{"empty", nil, capMalformed},
		{"version", []byte{9, capMethodList, 0, 0}, capUnsupportedVersion},
		{"unknown", []byte{AgentCapVersion, 9, 0, 0}, capUnknownMethod},
		{"trailing", append(okBytes(t)(encodeCapList()), 0), capMalformed},
		{"duplicate", duplicateHandleMessage(), capMalformed},
		{"extra", okBytes(t)(encodeCap(capMethodList, []capWire{{id: capFieldPayload, typ: capTypeBytes, val: []byte(sentinel)}})), capMalformed},
		{"type", okBytes(t)(encodeCap(capMethodDescribe, []capWire{{id: capFieldHandle, typ: capTypeString, val: []byte(sentinel)}})), capMalformed},
		{"short", []byte{AgentCapVersion, capMethodInvoke}, capMalformed},
		{"oversize", bytes.Repeat([]byte{AgentCapVersion}, MaxAgentCapMessage+1), capMalformed},
		{"payload", okBytes(t)(encodeCapInvoke([32]byte{}, append([]byte(sentinel), bytes.Repeat([]byte{1}, MaxAttestPayload)...))), capMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := cap.Exchange(tc.msg)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := decodeCapResponse(raw)
			if err != nil || resp.code != tc.code {
				t.Fatalf("%s %+v %v", tc.code, resp, err)
			}
			text, ok := capText(tc.code)
			if !ok || resp.message != text || bytes.Contains(raw, []byte(sentinel)) {
				t.Fatalf("reflected %q in %q", sentinel, resp.message)
			}
		})
	}
	var handle [32]byte
	listed := capCall(t, cap, okBytes(t)(encodeCapList()))
	handle = listed.entries[0].handle
	swapped := swappedInvoke(t, handle, []byte("ordered"))
	got := capCall(t, cap, swapped)
	if !VerifyLocalAttestation(pub, resource, []byte("ordered"), got.att.Signature[:]) {
		t.Fatal("field order was rejected")
	}
	maxPayload := bytes.Repeat([]byte{'m'}, MaxAttestPayload)
	maxGot := capCall(t, cap, okBytes(t)(encodeCapInvoke(handle, maxPayload)))
	if !VerifyLocalAttestation(pub, resource, maxPayload, maxGot.att.Signature[:]) {
		t.Fatal("maximum payload")
	}
	if _, err := cap.Exchange(nil); err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(session.audit); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	raw, err := cap.Exchange(okBytes(t)(encodeCapList()))
	if raw != nil || !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("locked %x %v", raw, err)
	}
}

func TestAgentCapIsolationAndCatalog(t *testing.T) {
	env := newSharedEnv(t)
	other, err := env.alice.CreateAgent("worker-2")
	if err != nil {
		t.Fatal(err)
	}
	mine := approveExact(t, env, env.agent.ID, env.resource)
	theirs := approveExact(t, env, other.ID, "artifact-"+randHex(t, 8))
	a := bindCap(t, env.s, env.agent.ID)
	b := bindCap(t, env.s, other.ID)
	alist := capCall(t, a, okBytes(t)(encodeCapList()))
	blist := capCall(t, b, okBytes(t)(encodeCapList()))
	if len(alist.entries) != 1 || len(blist.entries) != 1 || alist.entries[0].resource != mine.Resource || blist.entries[0].resource != theirs.Resource {
		t.Fatal("catalogs were not isolated")
	}
	if alist.entries[0].handle == blist.entries[0].handle {
		t.Fatal("handles collided")
	}
	foreignRaw := mustRaw(t, a, okBytes(t)(encodeCapDescribe(blist.entries[0].handle)))
	foreign, err := decodeCapResponse(foreignRaw)
	if err != nil || foreign.code != capUnknownHandle || bytes.Contains(foreignRaw, []byte(theirs.Resource)) {
		t.Fatalf("foreign describe %+v %v", foreign, err)
	}
	again := bindCap(t, env.s, env.agent.ID)
	if stale := capCall(t, again, okBytes(t)(encodeCapInvoke(alist.entries[0].handle, []byte("stale-handle")))); stale.code != capUnknownHandle {
		t.Fatalf("stale adapter %+v", stale)
	}
	raw, err := a.Exchange(okBytes(t)(encodeCapInvoke(blist.entries[0].handle, []byte("foreign-invoke"))))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := decodeCapResponse(raw)
	if err != nil || resp.code != capUnknownHandle || bytes.Contains(raw, []byte(theirs.ID)) || bytes.Contains(raw, blist.entries[0].handle[:]) {
		t.Fatal("foreign invoke leaked")
	}
	for _, ev := range env.s.audit {
		if ev.GrantID == theirs.ID && ev.AgentID == env.agent.ID {
			t.Fatal("foreign grant was attributed to this agent")
		}
	}

	session, principalCap, attest, _, resource := newSingleAttestCap(t)
	httpResource := "GET https://svc.example/v1/ping"
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: attest.AgentID, CredentialID: attest.CredentialID,
		Operations: []string{OpHTTPRequest}, Resource: httpResource, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	hostPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshResource := "ssh-" + randHex(t, 8)
	sshUser := "ssh-user-" + randHex(t, 4)
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: attest.AgentID, CredentialID: attest.CredentialID,
		Operations: []string{OpSSHUserAuth}, Resource: sshResource, ExpiresAt: time.Now().Add(time.Hour),
		SSHUsername: sshUser, SSHHostKey: marshalEd25519Pub(hostPub),
	}); err != nil {
		t.Fatal(err)
	}
	catalog := mustRaw(t, principalCap, okBytes(t)(encodeCapList()))
	decoded, err := decodeCapResponse(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.entries) != 1 || decoded.entries[0].resource != resource || decoded.entries[0].operation != OpLocalArtifactAttest {
		t.Fatalf("filtered catalog %+v code %s", decoded.entries, decoded.code)
	}
	for _, hidden := range []string{httpResource, sshResource, sshUser, OpHTTPRequest, OpSSHUserAuth, "ssh-ed25519"} {
		if bytes.Contains(catalog, []byte(hidden)) {
			t.Fatalf("catalog exposed %s", hidden)
		}
	}
	if err := verifyChain(env.s.audit); err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(session.audit); err != nil {
		t.Fatal(err)
	}
}

func TestAgentCapExactGrantDoesNotRetarget(t *testing.T) {
	env := newSharedEnv(t)
	first := approveExact(t, env, env.agent.ID, env.resource)
	second := approveExact(t, env, env.agent.ID, env.resource)
	cap := bindCap(t, env.s, env.agent.ID)
	listed := capCall(t, cap, okBytes(t)(encodeCapList()))
	if len(listed.entries) != 2 {
		t.Fatalf("entries %d", len(listed.entries))
	}
	oldH, keepH := handlesFor(t, cap, first.ID, second.ID)
	if listed.entries[0].status != GrantActive || listed.entries[1].status != GrantActive {
		t.Fatal("status")
	}
	if err := env.alice.RevokeGrant(first.ID); err != nil {
		t.Fatal(err)
	}
	denied := capCall(t, cap, okBytes(t)(encodeCapInvoke(oldH, []byte("revoked-grant"))))
	if denied.code != capDeniedRevoked {
		t.Fatalf("revoked handle %+v", denied)
	}
	kept := capCall(t, cap, okBytes(t)(encodeCapInvoke(keepH, []byte("other-grant"))))
	if !VerifyLocalAttestation(env.priv.Public().(ed25519.PublicKey), env.resource, []byte("other-grant"), kept.att.Signature[:]) {
		t.Fatal("remaining grant did not sign")
	}
	if !auditHasGrant(env.s, actionLocalAttest, resultDeniedRevoked, first.ID) {
		t.Fatal("revocation was not recorded on the selected grant")
	}
	if auditHasGrant(env.s, actionLocalAttest, resultDeniedRevoked, second.ID) {
		t.Fatal("the other grant was blamed")
	}

	fresh := newSharedEnv(t)
	old := approveExact(t, fresh, fresh.agent.ID, fresh.resource)
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der2, err := x509.MarshalPKCS8PrivateKey(priv2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.alice.Replace(fresh.cred.ID, der2, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	next := approveExact(t, fresh, fresh.agent.ID, fresh.resource)
	if next.KeyID == old.KeyID {
		t.Fatal("replacement kept the old key id")
	}
	bound := bindCap(t, fresh.s, fresh.agent.ID)
	entries := capCall(t, bound, okBytes(t)(encodeCapList()))
	oldHandle, newHandle := handlesFor(t, bound, old.ID, next.ID)
	for _, entry := range entries.entries {
		if entry.handle == oldHandle && entry.status != GrantActive {
			t.Fatal("discovered status stopped being advisory")
		}
		if entry.handle == oldHandle && entry.keyID != old.KeyID {
			t.Fatal("old handle was retargeted")
		}
	}
	keyDenied := capCall(t, bound, okBytes(t)(encodeCapInvoke(oldHandle, []byte("old-key"))))
	if keyDenied.code != capDeniedKey {
		t.Fatalf("old key %+v", keyDenied)
	}
	signed := capCall(t, bound, okBytes(t)(encodeCapInvoke(newHandle, []byte("new-key"))))
	if !VerifyLocalAttestation(priv2.Public().(ed25519.PublicKey), fresh.resource, []byte("new-key"), signed.att.Signature[:]) {
		t.Fatal("new handle did not verify")
	}
	if VerifyLocalAttestation(fresh.priv.Public().(ed25519.PublicKey), fresh.resource, []byte("new-key"), signed.att.Signature[:]) {
		t.Fatal("new handle used the old key")
	}
	if !auditHasGrant(fresh.s, actionLocalAttest, resultDeniedKey, old.ID) {
		t.Fatal("key denial left the selected grant")
	}
	principal, err := fresh.s.Agent(fresh.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := principal.LocalAttest(LocalAttestRequest{CredentialID: fresh.cred.ID, Resource: fresh.resource, Payload: []byte("legacy-path")})
	if err != nil || !VerifyLocalAttestation(priv2.Public().(ed25519.PublicKey), fresh.resource, []byte("legacy-path"), legacy.Signature[:]) {
		t.Fatalf("existing LocalAttest %v", err)
	}

	fresh.s.attestFault = func() error {
		return fresh.alice.RevokeGrant(next.ID)
	}
	during, err := bound.Exchange(okBytes(t)(encodeCapInvoke(newHandle, []byte("during-callback"))))
	fresh.s.attestFault = nil
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCapResponse(during)
	if err != nil || decoded.code != capDeniedRevoked || decoded.method != capMethodError {
		t.Fatalf("callback %+v %v", decoded, err)
	}
	if !auditHasGrant(fresh.s, actionLocalAttest, resultDeniedRevoked, next.ID) {
		t.Fatal("final check left the selected grant")
	}
	if err := verifyChain(env.s.audit); err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(fresh.s.audit); err != nil {
		t.Fatal(err)
	}
}

func TestAgentCapAuthorityAndAuditFailures(t *testing.T) {
	env := approvedShared(t)
	cap := bindCap(t, env.s, env.agent.ID)
	entry := capCall(t, cap, okBytes(t)(encodeCapList())).entries[0]
	payload := []byte("authority-artifact")
	if err := env.alice.RevokeGrant(env.s.grants[len(env.s.grants)-1].ID); err != nil {
		t.Fatal(err)
	}
	if got := capCall(t, cap, okBytes(t)(encodeCapInvoke(entry.handle, payload))); got.code != capDeniedRevoked {
		t.Fatalf("revoke %+v", got)
	}
	described := capCall(t, cap, okBytes(t)(encodeCapDescribe(entry.handle)))
	if described.entry.status != GrantRevoked {
		t.Fatalf("describe status %s", described.entry.status)
	}

	exp := newSharedEnv(t)
	approveExact(t, exp, exp.agent.ID, exp.resource)
	expCap := bindCap(t, exp.s, exp.agent.ID)
	expHandle := capCall(t, expCap, okBytes(t)(encodeCapList())).entries[0].handle
	exp.s.clock = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if got := capCall(t, expCap, okBytes(t)(encodeCapDescribe(expHandle))); got.entry.status != GrantExpired {
		t.Fatalf("expiry status %s", got.entry.status)
	}
	if got := capCall(t, expCap, okBytes(t)(encodeCapInvoke(expHandle, payload))); got.code != capDeniedExpired {
		t.Fatalf("expiry %+v", got)
	}

	sus := approvedShared(t)
	susCap := bindCap(t, sus.s, sus.agent.ID)
	susHandle := capCall(t, susCap, okBytes(t)(encodeCapList())).entries[0].handle
	for i := range sus.s.agents {
		if sus.s.agents[i].ID == sus.agent.ID {
			sus.s.agents[i].State = agentStateSuspended
		}
	}
	secretPayload := []byte("suspended-" + sus.sentinel)
	raw, err := susCap.Exchange(okBytes(t)(encodeCapInvoke(susHandle, secretPayload)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeCapResponse(raw)
	if err != nil || got.code != capDeniedAgent || bytes.Contains(raw, secretPayload) {
		t.Fatalf("suspended %+v", got)
	}
	if bytes.Contains(readAll(t, sus.path), secretPayload) {
		t.Fatal("suspended payload was stored")
	}

	mem := approvedShared(t)
	memCap := bindCap(t, mem.s, mem.agent.ID)
	memHandle := capCall(t, memCap, okBytes(t)(encodeCapList())).entries[0].handle
	if err := mem.alice.Remove(mem.bobID); err != nil {
		t.Fatal(err)
	}
	if got := capCall(t, memCap, okBytes(t)(encodeCapInvoke(memHandle, payload))); got.code != capDeniedRevoked {
		t.Fatalf("membership %+v", got)
	}

	stale := approvedShared(t)
	staleCap := bindCap(t, stale.s, stale.agent.ID)
	staleHandle := capCall(t, staleCap, okBytes(t)(encodeCapList())).entries[0].handle
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
	before := len(stale.s.audit)
	raw, err = staleCap.Exchange(okBytes(t)(encodeCapInvoke(staleHandle, payload)))
	if raw != nil || !errors.Is(err, ErrStale) || len(stale.s.audit) != before {
		t.Fatalf("stale %x %v rows %d", raw, err, len(stale.s.audit)-before)
	}

	fault := approvedShared(t)
	faultCap := bindCap(t, fault.s, fault.agent.ID)
	faultHandle := capCall(t, faultCap, okBytes(t)(encodeCapList())).entries[0].handle
	before = len(fault.s.audit)
	fault.s.commitFault = func() error { return errors.New("induced " + string(payload)) }
	raw, err = faultCap.Exchange(okBytes(t)(encodeCapInvoke(faultHandle, payload)))
	fault.s.commitFault = nil
	if raw != nil || !errors.Is(err, ErrAudit) || len(fault.s.audit) != before || strings.Contains(err.Error(), string(payload)) {
		t.Fatalf("audit fault %x %v", raw, err)
	}
	raw, err = faultCap.Exchange([]byte{AgentCapVersion, 9, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	fault.s.commitFault = func() error { return errors.New("induced") }
	before = len(fault.s.audit)
	raw, err = faultCap.Exchange([]byte{AgentCapVersion, 9, 0, 0})
	fault.s.commitFault = nil
	if raw != nil || !errors.Is(err, ErrAudit) || len(fault.s.audit) != before {
		t.Fatalf("malformed audit fault %x %v", raw, err)
	}

	cut := approvedShared(t)
	cutCap := bindCap(t, cut.s, cut.agent.ID)
	cutHandle := capCall(t, cutCap, okBytes(t)(encodeCapList())).entries[0].handle
	var writes int
	cut.s.commitFault = func() error {
		writes++
		if writes == 1 {
			return nil
		}
		return errors.New("induced")
	}
	raw, err = cutCap.Exchange(okBytes(t)(encodeCapInvoke(cutHandle, payload)))
	cut.s.commitFault = nil
	if raw != nil || !errors.Is(err, ErrAudit) {
		t.Fatalf("completion fault %x %v", raw, err)
	}
	allowed, completed := false, false
	for _, ev := range cut.s.audit {
		if ev.Action == actionLocalAttest && ev.Result == resultAllowed {
			allowed = true
		}
		if ev.Action == actionLocalAttest && ev.Result == resultCompleted {
			completed = true
		}
	}
	if !allowed || completed {
		t.Fatalf("allowed %v completed %v", allowed, completed)
	}
	for _, s := range []*Session{env.s, exp.s, sus.s, mem.s, fault.s, cut.s} {
		if err := verifyChain(s.audit); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAgentCapBoundsAndShape(t *testing.T) {
	if _, err := BindAgentCapability(nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	var empty AgentCapability
	if raw, err := empty.Exchange([]byte{AgentCapVersion, capMethodList, 0, 0}); raw != nil || !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	typ := reflect.TypeOf(AgentCapability{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type == reflect.TypeOf(&Session{}) {
			t.Fatal("adapter holds a session")
		}
	}
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		if name != "Exchange" {
			t.Fatal(name)
		}
	}
	session, _, grant, _, _ := newSingleAttestCap(t)
	for i := 0; i < maxAgentCapEntries; i++ {
		if _, err := session.IssueGrant(GrantSpec{
			AgentID: grant.AgentID, CredentialID: grant.CredentialID,
			Operations: []string{OpLocalArtifactAttest}, Resource: "artifact-" + randHex(t, 6),
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	over := bindCap(t, session, grant.AgentID)
	got := capCall(t, over, okBytes(t)(encodeCapList()))
	if got.code != capDenied || len(got.entries) != 0 {
		t.Fatalf("over catalog %+v", got)
	}
	ev := auditEvent{Action: actionAgentCap, Result: resultAllowed, AgentID: grant.AgentID, Operation: "caller-text"}
	if validAgentCapAudit(ev) == nil {
		t.Fatal("caller text was an operation")
	}
	ev.Operation = OpLocalArtifactAttest
	ev.GrantID = grant.ID
	ev.CredID = grant.CredentialID
	ev.CredType = CredTypeEd25519
	if err := validAgentCapAudit(ev); err != nil {
		t.Fatal(err)
	}
	ev.Result = resultDenied
	ev.GrantID = grant.ID
	if validAgentCapAudit(ev) == nil {
		t.Fatal("denied describe kept a grant")
	}
	if err := verifyChain(session.audit); err != nil {
		t.Fatal(err)
	}
}

func newSingleAttestCap(t *testing.T) (*Session, *AgentCapability, Grant, ed25519.PublicKey, string) {
	t.Helper()
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
	grant, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: cred.ID,
		Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session, bindCap(t, session, agent.ID), grant, pub, resource
}

func approveExact(t *testing.T, env *sharedEnv, agentID, resource string) Grant {
	t.Helper()
	spec := env.requestSpec(time.Hour, 20*time.Minute)
	spec.AgentID = agentID
	spec.Resource = resource
	req, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := env.alice.Approve(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func bindCap(t *testing.T, s *Session, agentID string) *AgentCapability {
	t.Helper()
	p, err := s.Agent(agentID)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := BindAgentCapability(p)
	if err != nil {
		t.Fatal(err)
	}
	return cap
}

func capCall(t *testing.T, cap *AgentCapability, msg []byte) capResponse {
	t.Helper()
	resp, err := decodeCapResponse(mustRaw(t, cap, msg))
	if err != nil {
		t.Fatalf("decode %v", err)
	}
	return resp
}

func okBytes(t *testing.T) func([]byte, error) []byte {
	t.Helper()
	return func(raw []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
}

func mustRaw(t *testing.T, cap *AgentCapability, msg []byte) []byte {
	t.Helper()
	raw, err := cap.Exchange(msg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func duplicateHandleMessage() []byte {
	var handle [32]byte
	body := appendCapField(nil, capWire{id: capFieldHandle, typ: capTypeBytes, val: handle[:]})
	body = appendCapField(body, capWire{id: capFieldHandle, typ: capTypeBytes, val: handle[:]})
	out := []byte{AgentCapVersion, capMethodDescribe, 0, 2}
	return append(out, body...)
}

func swappedInvoke(t *testing.T, handle [32]byte, payload []byte) []byte {
	t.Helper()
	body := appendCapField(nil, capWire{id: capFieldPayload, typ: capTypeBytes, val: payload})
	body = appendCapField(body, capWire{id: capFieldHandle, typ: capTypeBytes, val: handle[:]})
	out := []byte{AgentCapVersion, capMethodInvoke, 0, 2}
	out = append(out, body...)
	if len(out) > MaxAgentCapMessage {
		t.Fatal("fixture too large")
	}
	return out
}

func handlesFor(t *testing.T, cap *AgentCapability, first, second string) (old, keep [32]byte) {
	t.Helper()
	cap.mu.Lock()
	defer cap.mu.Unlock()
	for handle, bound := range cap.byHandle {
		switch bound.grantID {
		case first:
			old = handle
		case second:
			keep = handle
		}
	}
	if old == ([32]byte{}) || keep == ([32]byte{}) {
		t.Fatal("handles were not bound to the issued grants")
	}
	return old, keep
}

func auditHasGrant(s *Session, action, result, grantID string) bool {
	for _, ev := range s.audit {
		if ev.Action == action && ev.Result == result && ev.GrantID == grantID {
			return true
		}
	}
	return false
}

func assertNoCapLeak(t *testing.T, raw []byte, env *sharedEnv, grant Grant, payload []byte) {
	t.Helper()
	for _, hidden := range []string{env.label, env.aliceID, env.bobID, grant.ID, grant.CredentialID, env.sentinel} {
		if hidden != "" && bytes.Contains(raw, []byte(hidden)) {
			t.Fatalf("response exposed %s", hidden)
		}
	}
	assertNoSecrets(t, raw, [][]byte{payload, env.der, env.priv.Seed(), append([]byte(nil), env.priv...)})
}

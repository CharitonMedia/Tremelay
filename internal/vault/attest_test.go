package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"
)

func ExampleVerifyLocalAttestation() {
	// Published test vector. This seed is not a vault credential.
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	const resource = "artifact:demo"
	payload := []byte("demo-artifact")
	msg, err := AttestMessage(resource, payload)
	if err != nil {
		fmt.Println("message")
		return
	}
	if !VerifyLocalAttestation(pub, resource, payload, ed25519.Sign(priv, msg)) {
		fmt.Println("rejected")
		return
	}
	fmt.Println("verified")
	// Output:
	// verified
}

func TestAttestMessage(t *testing.T) {
	payload := []byte("artifact-body")
	msg, err := AttestMessage("artifact:demo", payload)
	if err != nil || !bytes.HasPrefix(msg, []byte(attestMagic)) {
		t.Fatal(err)
	}
	again, err := AttestMessage("artifact:demo", payload)
	if err != nil || !bytes.Equal(msg, again) {
		t.Fatal("encoding drifted")
	}
	otherPayload, err := AttestMessage("artifact:demo", []byte("artifact-body-2"))
	if err != nil || bytes.Equal(msg, otherPayload) {
		t.Fatal("payload was not bound")
	}
	otherResource, err := AttestMessage("artifact:other", payload)
	if err != nil || bytes.Equal(msg, otherResource) {
		t.Fatal("resource was not bound")
	}
	otherDomain, err := attestMessage("tremelay/other/v1", AttestPurpose, "artifact:demo", payload)
	if err != nil || bytes.Equal(msg, otherDomain) {
		t.Fatal("domain was not bound")
	}
	otherPurpose, err := attestMessage(AttestDomain, "other-purpose", "artifact:demo", payload)
	if err != nil || bytes.Equal(msg, otherPurpose) {
		t.Fatal("purpose was not bound")
	}
	if _, err := AttestMessage("artifact:demo", nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := AttestMessage("artifact:demo", []byte{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := AttestMessage("artifact:demo", bytes.Repeat([]byte{'p'}, MaxAttestPayload+1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversize payload")
	}
	if _, err := AttestMessage("artifact:demo", bytes.Repeat([]byte{'p'}, MaxAttestPayload)); err != nil {
		t.Fatal(err)
	}
	if _, err := AttestMessage(strings.Repeat("a", maxLabel), payload); err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"", "*", "artifact:*", strings.Repeat("a", maxLabel+1), "artifact:\nnext"} {
		if _, err := AttestMessage(resource, payload); !errors.Is(err, ErrInvalid) {
			t.Fatalf("resource %q: %v", resource, err)
		}
	}
	pub, priv := mustEd25519(t)
	sig := ed25519.Sign(priv, msg)
	if !VerifyLocalAttestation(pub, "artifact:demo", payload, sig) {
		t.Fatal("verify")
	}
	if ed25519.Verify(pub, payload, sig) {
		t.Fatal("raw payload verified")
	}
	if ed25519.Verify(pub, otherDomain, sig) || ed25519.Verify(pub, otherPurpose, sig) {
		t.Fatal("domain separation failed")
	}
	if VerifyLocalAttestation(pub, "artifact:other", payload, sig) || VerifyLocalAttestation(pub, "artifact:demo", []byte("other"), sig) {
		t.Fatal("verifier ignored a change")
	}
	sig[0] ^= 0xff
	if VerifyLocalAttestation(pub, "artifact:demo", payload, sig) {
		t.Fatal("mutated signature verified")
	}
	if VerifyLocalAttestation(bytes.Repeat([]byte{2}, ed25519.PublicKeySize), "artifact:demo", payload, ed25519.Sign(priv, msg)) {
		t.Fatal("other key verified")
	}
}

func TestParseEd25519Private(t *testing.T) {
	pub, priv := mustEd25519(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil || len(der) != maxAttestKey {
		t.Fatalf("canonical length %d %v", len(der), err)
	}
	got, err := parseEd25519Private(der)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(got)
	if !bytes.Equal(got.Public().(ed25519.PublicKey), pub) {
		t.Fatal("public key")
	}
	seed := priv.Seed()
	expanded := append([]byte(nil), priv...)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xDER, err := x509.MarshalPKCS8PrivateKey(xKey)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), der...)
	mutated[4] ^= 0x01
	sentinel := make([]byte, maxAttestKey)
	copy(sentinel, "BADKEY-SENTINEL-VALUE")
	rejected := [][]byte{
		nil,
		{},
		seed,
		expanded,
		pemBytes,
		append(append([]byte(nil), der...), 0),
		rsaDER,
		ecDER,
		xDER,
		mutated,
		sentinel,
		[]byte("openssh-key-v1\x00" + strings.Repeat("k", maxAttestKey)),
		bytes.Repeat([]byte{0x30}, maxAttestKey),
	}
	for i, in := range rejected {
		key, err := parseEd25519Private(in)
		wipe(key)
		if err == nil || err.Error() != ErrSignFailed.Error() || key != nil {
			t.Fatalf("encoding %d accepted %v", i, err)
		}
		if (len(in) > 0 && bytes.Contains([]byte(err.Error()), in)) || strings.Contains(err.Error(), "asn1") || strings.Contains(err.Error(), "BADKEY") || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("encoding %d echoed input: %v", i, err)
		}
	}
}

func TestAttestGrantDocument(t *testing.T) {
	now := time.Now().UTC()
	agent := strings.Repeat("ab", 16)
	cred := strings.Repeat("cd", 16)
	keyID := strings.Repeat("ab", 32)
	base := grantRecord{
		ID: strings.Repeat("ef", 16), AgentID: agent, CredentialID: cred,
		Operations: []string{OpLocalArtifactAttest}, Resource: "artifact:one",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: keyID,
	}
	if err := attestFixture(t, now, agent, cred, CredTypeEd25519, base); err != nil {
		t.Fatal(err)
	}
	legacy := base
	legacy.Operations = []string{OpSign}
	legacy.KeyID = ""
	if err := attestFixture(t, now, agent, cred, CredTypeEd25519, legacy); err != nil {
		t.Fatal(err)
	}
	httpGrant := base
	httpGrant.Operations = []string{OpHTTPRequest}
	httpGrant.KeyID = ""
	if err := attestFixture(t, now, agent, cred, "api_key", httpGrant); err != nil {
		t.Fatal(err)
	}
	bad := []grantRecord{
		func() grantRecord {
			g := base
			g.CredentialID = ""
			g.CredentialClass = CredTypeEd25519
			return g
		}(),
		func() grantRecord { g := base; g.KeyID = ""; return g }(),
		func() grantRecord { g := base; g.KeyID = strings.ToUpper(keyID); return g }(),
		func() grantRecord {
			g := base
			g.Operations = []string{OpHTTPRequest, OpLocalArtifactAttest}
			return g
		}(),
		func() grantRecord { g := httpGrant; g.KeyID = keyID; return g }(),
		func() grantRecord { g := base; g.Resource = "*"; return g }(),
	}
	for i, g := range bad {
		if err := attestFixture(t, now, agent, cred, CredTypeEd25519, g); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("document %d: %v", i, err)
		}
	}
	if result, _ := decideAccess(nil, true, agent, cred, CredTypeEd25519, true, OpLocalArtifactAttest, "artifact:one", now); result != resultDeniedMissing {
		t.Fatal(result)
	}
	classed := base
	classed.CredentialID = ""
	classed.CredentialClass = CredTypeEd25519
	if result, _ := decideAccess([]grantRecord{classed}, true, agent, cred, CredTypeEd25519, true, OpLocalArtifactAttest, "artifact:one", now); result != resultDeniedCredential {
		t.Fatal(result)
	}
}

func TestLocalAttestAuditShape(t *testing.T) {
	vaultID := strings.Repeat("ab", 16)
	agentID := strings.Repeat("cd", 16)
	grantID := strings.Repeat("ef", 16)
	credID := strings.Repeat("12", 16)
	create, err := nextEvent(nil, actionCreate, vaultID, "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	chain := []auditEvent{create}
	for _, result := range []string{resultAllowed, resultCompleted, resultFailed, resultDeniedKey, resultDenied, resultDeniedRevoked} {
		ev := auditEvent{Action: actionLocalAttest, Result: result, AgentID: agentID, GrantID: grantID, CredID: credID, CredType: CredTypeEd25519, Operation: OpLocalArtifactAttest}
		if result == resultDenied {
			ev = auditEvent{Action: actionLocalAttest, Result: resultDenied}
		}
		next, err := nextAudit(chain, vaultID, ev)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, next)
		if err := verifyChain(chain); err != nil {
			t.Fatalf("%s: %v", result, err)
		}
		prev, err := hex.DecodeString(next.Prev)
		if err != nil {
			t.Fatal(err)
		}
		v2 := eventHashV2(prev, next.Seq, next.Time, next.Action, next.VaultID, next.CredID, next.CredType, next.Result, next.AgentID, next.GrantID, next.Operation)
		v1 := eventHash(prev, next.Seq, next.Time, next.Action, next.VaultID, next.CredID, next.CredType, next.Result)
		if hex.EncodeToString(v2) != next.Hash || bytes.Equal(v1, v2) {
			t.Fatal("attestation preimage changed the published versions")
		}
	}
	broker := auditEvent{
		Action: actionBroker, Result: resultCompleted, AgentID: agentID, GrantID: grantID,
		CredID: credID, CredType: CredTypeEd25519, Operation: OpLocalArtifactAttest,
	}
	next, err := nextAudit(chain, vaultID, broker)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(append(chain, next)); !errors.Is(err, ErrAudit) {
		t.Fatal("broker row accepted the attestation operation")
	}
	tampered := append([]auditEvent{}, chain...)
	tampered[len(tampered)-1].Result = resultAllowed
	if err := verifyChain(tampered); !errors.Is(err, ErrAudit) {
		t.Fatal("tampered attestation row verified")
	}
}

func TestLocalAttestDetection(t *testing.T) {
	agent := strings.Repeat("ab", 16)
	var chain []auditEvent
	for i := 0; i < detectionThreshold-1; i++ {
		chain = append(chain, auditEvent{Seq: uint64(len(chain) + 1), Action: actionBroker, Result: resultDeniedMissing, AgentID: agent})
	}
	for i := 0; i < detectionLookback; i++ {
		chain = append(chain, auditEvent{Seq: uint64(len(chain) + 1), Action: actionLocalAttest, Result: resultDeniedKey, AgentID: agent})
	}
	if got := classify(chain, chain[len(chain)-1]); got.Class != ClassExpectedDenial || got.Severity != SeverityLow {
		t.Fatalf("attest denials promoted %+v", got)
	}
	chain = append(chain, auditEvent{Seq: uint64(len(chain) + 1), Action: actionBroker, Result: resultDeniedMissing, AgentID: agent})
	if got := classify(chain, chain[len(chain)-1]); got.Class != ClassRepeatedDenial || got.Severity != SeverityHigh {
		t.Fatalf("broker threshold moved %+v", got)
	}
}

func TestLocalAttest(t *testing.T) {
	var logs bytes.Buffer
	logger := log.New(&logs, "", 0)
	path, pass, session := mustCreate(t, logger)
	pub, priv := mustEd25519(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, otherPriv := mustEd25519(t)
	otherDER, err := x509.MarshalPKCS8PrivateKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("Pa" + randHex(t, 16) + `/\"`)
	resource := "artifact:" + randHex(t, 16)
	cred, err := session.Put("signing-key", CredTypeEd25519, der, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := session.Put("other-key", CredTypeEd25519, otherDER, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	badKey := make([]byte, maxAttestKey)
	copy(badKey, "BADKEY-SENTINEL-VALUE")
	malformed, err := session.Put("malformed", CredTypeEd25519, badKey, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sshSecret := append([]byte(nil), der...)
	sshCred, err := session.Put("ssh-shaped", "ssh_key", sshSecret, PutOptions{})
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
	exp := time.Now().Add(time.Hour).UTC()
	for _, op := range []string{OpSign, OpHTTPRequest, OpGitHubIssueState} {
		if _, err := session.IssueGrant(GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{op}, Resource: resource, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	req := LocalAttestRequest{CredentialID: cred.ID, Resource: resource, Payload: payload}
	var zero LocalAttestation
	if got, err := principal.LocalAttest(req); !errors.Is(err, ErrDeniedOperation) || got != zero {
		t.Fatalf("legacy grant authorized attestation %+v %v", got, err)
	}
	if id, err := principal.Authorize(cred.ID, OpSign, resource); err != nil || id == "" {
		t.Fatalf("sign placeholder authorize %s %v", id, err)
	}
	session.Lock()
	session, err = Unlock(path, pass, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Lock()
	principal, err = session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := principal.LocalAttest(req); !errors.Is(err, ErrDeniedOperation) || got != zero {
		t.Fatalf("reopen transferred a legacy grant %+v %v", got, err)
	}
	rejects := []GrantSpec{
		{AgentID: agent.ID, CredentialClass: CredTypeEd25519, Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: exp},
		{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpLocalArtifactAttest, OpHTTPRequest}, Resource: resource, ExpiresAt: exp},
		{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpLocalArtifactAttest}, Resource: "*", ExpiresAt: exp},
		{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpLocalArtifactAttest}, Resource: strings.Repeat("a", maxLabel+1), ExpiresAt: exp},
		{AgentID: agent.ID, CredentialID: malformed.ID, Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: exp},
		{AgentID: agent.ID, CredentialID: sshCred.ID, Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: exp},
	}
	for i, spec := range rejects {
		if _, err := session.IssueGrant(spec); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "BADKEY") || bytes.Contains([]byte(err.Error()), der) {
			t.Fatalf("grant %d: %v", i, err)
		}
	}
	grant, err := session.IssueGrant(GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: exp})
	if err != nil || grant.KeyID != hex.EncodeToString(pub) || grant.CredentialClass != "" {
		t.Fatalf("grant %+v %v", grant, err)
	}
	if id, err := principal.Authorize(cred.ID, OpLocalArtifactAttest, resource); err != nil || id != grant.ID {
		t.Fatalf("authorize %s %v", id, err)
	}
	if _, err := session.IssueGrant(GrantSpec{AgentID: otherAgent.ID, CredentialID: other.ID, Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	deny := func(p *AgentPrincipal, call LocalAttestRequest, want error) {
		t.Helper()
		got, err := p.LocalAttest(call)
		if !errors.Is(err, want) || got != zero || echoedSecret(err, payload, der, priv.Seed(), badKey) {
			t.Fatalf("got %+v err %v want %v", got, err, want)
		}
	}
	deny(principal, LocalAttestRequest{CredentialID: cred.ID, Resource: resource}, ErrInvalid)
	deny(principal, LocalAttestRequest{CredentialID: cred.ID, Resource: resource, Payload: bytes.Repeat([]byte{'p'}, MaxAttestPayload+1)}, ErrInvalid)
	deny(principal, LocalAttestRequest{CredentialID: cred.ID, Resource: "", Payload: payload}, ErrInvalid)
	deny(principal, LocalAttestRequest{CredentialID: cred.ID, Resource: "artifact:*", Payload: payload}, ErrInvalid)
	deny(principal, LocalAttestRequest{CredentialID: "not-an-id", Resource: resource, Payload: payload}, ErrInvalid)
	deny(principal, LocalAttestRequest{CredentialID: cred.ID, Resource: "artifact:other", Payload: payload}, ErrDeniedScope)
	otherPrincipal, err := session.Agent(otherAgent.ID)
	if err != nil {
		t.Fatal(err)
	}
	deny(otherPrincipal, req, ErrDeniedCredential)
	barePrincipal, err := session.Agent(bare.ID)
	if err != nil {
		t.Fatal(err)
	}
	deny(barePrincipal, req, ErrDeniedAgent)
	deny(principal, LocalAttestRequest{CredentialID: other.ID, Resource: resource, Payload: payload}, ErrDeniedCredential)

	session.commitFault = func() error { return errors.New("induced " + string(payload)) }
	deny(principal, req, ErrAudit)
	session.commitFault = nil
	if attestCount(t, path, resultAllowed) != 0 || attestCount(t, path, resultCompleted) != 0 {
		t.Fatal("failed authorization audit was recorded as a signing attempt")
	}

	got, err := principal.LocalAttest(req)
	if err != nil {
		t.Fatal(err)
	}
	if !attestVerified(pub, resource, payload, got) {
		t.Fatal("independent verification failed")
	}
	if ed25519.Verify(pub, payload, got.Signature[:]) || VerifyLocalAttestation(otherPub, resource, payload, got.Signature[:]) {
		t.Fatal("signature was not bound")
	}
	rawDomain, err := attestMessage("tremelay/other/v1", AttestPurpose, resource, payload)
	if err != nil || ed25519.Verify(pub, rawDomain, got.Signature[:]) {
		t.Fatal("domain")
	}
	rawPurpose, err := attestMessage(AttestDomain, "other-purpose", resource, payload)
	if err != nil || ed25519.Verify(pub, rawPurpose, got.Signature[:]) {
		t.Fatal("purpose")
	}
	changed := append([]byte(nil), payload...)
	changed[0] ^= 0xff
	if VerifyLocalAttestation(pub, resource, changed, got.Signature[:]) || VerifyLocalAttestation(pub, resource+"x", payload, got.Signature[:]) {
		t.Fatal("verifier accepted a changed input")
	}
	flipped := got.Signature
	flipped[0] ^= 0xff
	if VerifyLocalAttestation(pub, resource, payload, flipped[:]) {
		t.Fatal("verifier accepted a changed signature")
	}
	first := got
	maxPayload := bytes.Repeat([]byte{'m'}, MaxAttestPayload)
	maxGot, err := principal.LocalAttest(LocalAttestRequest{CredentialID: cred.ID, Resource: resource, Payload: maxPayload})
	if err != nil || !attestVerified(pub, resource, maxPayload, maxGot) {
		t.Fatal(err)
	}

	var writes int
	session.commitFault = func() error {
		writes++
		if writes == 1 {
			return nil
		}
		return errors.New("induced")
	}
	deny(principal, req, ErrAudit)
	session.commitFault = nil
	if attestCount(t, path, resultAllowed) != attestCount(t, path, resultCompleted)+1 {
		t.Fatal("interrupted attempt was recorded as a completion")
	}
	session.attestFault = func() error { return errors.New("fault " + string(payload)) }
	deny(principal, req, ErrSignFailed)
	session.attestFault = nil
	if attestCount(t, path, resultFailed) != 1 {
		t.Fatal("signing fault was not recorded")
	}

	completed := attestCount(t, path, resultCompleted)
	second, err := principal.LocalAttest(req)
	// Ed25519 is deterministic. A repeat is a new audit pair, not a new signature.
	if err != nil || !attestVerified(pub, resource, payload, second) || second.Signature != first.Signature || attestCount(t, path, resultCompleted) != completed+1 {
		t.Fatalf("repeat %v completed %d", err, attestCount(t, path, resultCompleted))
	}
	past := time.Now().Add(-time.Hour).UTC()
	if _, err := session.SetLifecycle(cred.ID, LifecycleOptions{ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	health, err := session.Health(cred.ID)
	if err != nil || !finding(health, ReasonExpired) {
		t.Fatalf("health %+v %v", health, err)
	}
	if _, err := principal.LocalAttest(req); err != nil {
		t.Fatal("health finding blocked signing")
	}
	if _, err := session.Replace(cred.ID, der, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := principal.LocalAttest(req); err != nil {
		t.Fatal("identical key bytes dropped the grant")
	}
	if _, err := session.Replace(cred.ID, otherDER, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	caps, err := principal.Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	for _, cap := range caps {
		if cap.GrantID == grant.ID && cap.KeyID != hex.EncodeToString(pub) {
			t.Fatal("replacement rewrote the grant key id")
		}
	}
	deny(principal, req, ErrDeniedKey)
	if id, err := principal.Authorize(cred.ID, OpLocalArtifactAttest, resource); err == nil || id != "" || !errors.Is(err, ErrDeniedKey) {
		t.Fatalf("authorize after replacement %s %v", id, err)
	}
	if !VerifyLocalAttestation(pub, resource, payload, first.Signature[:]) || VerifyLocalAttestation(otherPub, resource, payload, first.Signature[:]) {
		t.Fatal("replacement changed an issued signature")
	}
	huge := bytes.Repeat([]byte{'H'}, maxAttestKey+1)
	if _, err := session.Replace(cred.ID, huge, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	deny(principal, req, ErrSignFailed)
	if _, err := session.Replace(cred.ID, badKey, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	deny(principal, req, ErrSignFailed)
	if _, err := session.Replace(cred.ID, der, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	restored, err := principal.LocalAttest(req)
	if err != nil || !attestVerified(pub, resource, payload, restored) {
		t.Fatal(err)
	}

	session.clock = func() time.Time { return exp }
	deny(principal, req, ErrDeniedExpired)
	session.clock = nil
	if _, err := principal.LocalAttest(req); err != nil {
		t.Fatal("clock reset did not restore the grant")
	}
	if err := session.RevokeGrant(grant.ID); err != nil {
		t.Fatal(err)
	}
	deny(principal, req, ErrDeniedRevoked)
	if !VerifyLocalAttestation(pub, resource, payload, restored.Signature[:]) {
		t.Fatal("revocation invalidated an issued signature")
	}
	for i := range session.agents {
		if session.agents[i].ID == agent.ID {
			session.agents[i].State = agentStateSuspended
		}
	}
	deny(principal, req, ErrDeniedAgent)

	session.Lock()
	before := len(mustAudit(t, path))
	if got, err := principal.LocalAttest(req); !errors.Is(err, ErrUnauthenticated) || got != zero || len(mustAudit(t, path)) != before {
		t.Fatalf("locked session %+v %v", got, err)
	}

	sum := sha256.Sum256(payload)
	secretBlobs := [][]byte{payload, der, priv.Seed(), append([]byte(nil), priv...), badKey, sum[:], otherDER}
	assertNoSecrets(t, logs.Bytes(), secretBlobs)
	assertNoSecrets(t, readAll(t, path), secretBlobs)
	for _, ev := range mustAudit(t, path) {
		fields := strings.Join([]string{ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation, ev.Class, ev.Time, ev.Reasons, ev.Prev, ev.Hash}, "\n")
		if strings.Contains(fields, resource) || strings.Contains(fields, hex.EncodeToString(pub)) {
			t.Fatal("audit recorded the resource or public key")
		}
		assertNoSecrets(t, []byte(fields), secretBlobs)
	}
	encoded, err := json.Marshal(first)
	if err != nil || bytes.Contains(encoded, payload) || bytes.Contains(encoded, der) {
		t.Fatal("response disclosed payload or private key")
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
	tamperPath := path + ".tamper"
	copyFile(t, path, tamperPath)
	mutateDB(t, tamperPath, func(db *sql.DB) {
		if _, err := db.Exec(`UPDATE audit SET result = ? WHERE action = ? AND result = ?`, resultAllowed, actionLocalAttest, resultCompleted); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := VerifyAudit(tamperPath, pass); !errors.Is(err, ErrAudit) {
		t.Fatalf("tampered chain verified: %v", err)
	}
}

func TestLocalAttestContainment(t *testing.T) {
	var logs bytes.Buffer
	path, pass, session := mustCreate(t, log.New(&logs, "", 0))
	pub, priv := mustEd25519(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("contain-" + randHex(t, 16))
	resource := "artifact:" + randHex(t, 8)
	cred, err := session.Put("signing-key", CredTypeEd25519, der, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := session.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).UTC()
	grant, err := session.IssueGrant(GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	sink := &MemoryNotifier{}
	if err := session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	req := LocalAttestRequest{CredentialID: cred.ID, Resource: resource, Payload: payload}
	if _, err := principal.LocalAttest(LocalAttestRequest{CredentialID: cred.ID, Resource: "artifact:nope", Payload: payload}); !errors.Is(err, ErrDeniedScope) || len(sink.Snapshot()) != 0 {
		t.Fatal("ordinary denial notified")
	}
	if err := session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	if err := session.RevokeGrant(grant.ID); err != nil {
		t.Fatal(err)
	}
	got, err := principal.LocalAttest(req)
	var zero LocalAttestation
	if !errors.Is(err, ErrDeniedRevoked) || got != zero {
		t.Fatalf("%+v %v", got, err)
	}
	notes := sink.Snapshot()
	if len(notes) != 1 || notes[0].Class != ClassReplay || notes[0].Action != actionLocalAttest || notes[0].Result != resultDeniedRevoked {
		t.Fatalf("alert %+v", notes)
	}
	raw, err := json.Marshal(notes[0])
	if err != nil || bytes.Contains(raw, payload) || bytes.Contains(raw, der) || bytes.Contains(raw, pub) {
		t.Fatal("alert disclosed material")
	}
	suspended := false
	for _, a := range session.agents {
		if a.ID == agent.ID && a.State == agentStateSuspended {
			suspended = true
		}
	}
	if !suspended {
		t.Fatal("replay did not suspend the agent")
	}
	assertNoSecrets(t, logs.Bytes(), [][]byte{payload, der})
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
}

func TestLocalAttestInvalidLifecycle(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	_, priv := mustEd25519(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := session.Put("signing-key", CredTypeEd25519, der, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := session.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	resource := "artifact:lifecycle"
	if _, err := session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpLocalArtifactAttest},
		Resource: resource, ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range session.creds {
		if session.creds[i].ID == cred.ID {
			session.creds[i].Lifecycle.State = "disabled"
		}
	}
	got, err := principal.LocalAttest(LocalAttestRequest{CredentialID: cred.ID, Resource: resource, Payload: []byte("body")})
	var zero LocalAttestation
	if !errors.Is(err, ErrSignFailed) || got != zero || attestCount(t, path, resultFailed) != 1 || attestCount(t, path, resultCompleted) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	session.Lock()
	if _, err := Unlock(path, pass, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid lifecycle reopened: %v", err)
	}
}

func TestLocalAttestSelectsCurrentKey(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	defer session.Lock()
	oldPub, oldPriv := mustEd25519(t)
	newPub, newPriv := mustEd25519(t)
	oldDER, err := x509.MarshalPKCS8PrivateKey(oldPriv)
	if err != nil {
		t.Fatal(err)
	}
	newDER, err := x509.MarshalPKCS8PrivateKey(newPriv)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("rotate-" + randHex(t, 16))
	resource := "artifact:" + randHex(t, 8)
	cred, err := session.Put("signing-key", CredTypeEd25519, oldDER, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := session.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).UTC()
	spec := GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpLocalArtifactAttest}, Resource: resource, ExpiresAt: exp}
	stale, err := session.IssueGrant(spec)
	if err != nil || stale.KeyID != hex.EncodeToString(oldPub) {
		t.Fatalf("stale grant %+v %v", stale, err)
	}
	if _, err := session.Replace(cred.ID, newDER, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	fresh, err := session.IssueGrant(spec)
	if err != nil || fresh.KeyID != hex.EncodeToString(newPub) || fresh.KeyID == stale.KeyID {
		t.Fatalf("fresh grant %+v %v", fresh, err)
	}
	// The stale grant must sort first. Random ids do not guarantee that.
	const staleID = "00000000000000000000000000000001"
	const freshID = "fffffffffffffffffffffffffffffffe"
	bound := 0
	for i := range session.grants {
		switch session.grants[i].ID {
		case stale.ID:
			session.grants[i].ID = staleID
			bound++
		case fresh.ID:
			session.grants[i].ID = freshID
			bound++
		}
	}
	if bound != 2 {
		t.Fatal("grant ids were not ordered")
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	req := LocalAttestRequest{CredentialID: cred.ID, Resource: resource, Payload: payload}
	if id, err := principal.Authorize(cred.ID, OpLocalArtifactAttest, resource); err != nil || id != freshID {
		t.Fatalf("authorize %s %v", id, err)
	}
	got, err := principal.LocalAttest(req)
	if err != nil || !attestVerified(newPub, resource, payload, got) || VerifyLocalAttestation(oldPub, resource, payload, got.Signature[:]) {
		t.Fatalf("attest %+v %v", got, err)
	}
	completed := 0
	for _, ev := range mustAudit(t, path) {
		if ev.Action != actionLocalAttest || ev.Result != resultCompleted {
			continue
		}
		completed++
		if ev.GrantID != freshID {
			t.Fatalf("completed grant %s", ev.GrantID)
		}
	}
	if completed != 1 {
		t.Fatalf("completed rows %d", completed)
	}
	if err := session.RevokeGrant(freshID); err != nil {
		t.Fatal(err)
	}
	var zero LocalAttestation
	revoked, err := principal.LocalAttest(req)
	if !errors.Is(err, ErrDeniedRevoked) || revoked != zero || echoedSecret(err, payload, oldDER, newDER) {
		t.Fatalf("revoked current key %+v %v", revoked, err)
	}
	if id, err := principal.Authorize(cred.ID, OpLocalArtifactAttest, resource); err == nil || id != "" || !errors.Is(err, ErrDeniedRevoked) {
		t.Fatalf("authorize revoked %s %v", id, err)
	}
	for _, ev := range mustAudit(t, path) {
		if ev.Result == resultDeniedRevoked && ev.GrantID != freshID {
			t.Fatalf("revocation named %s on %s", ev.GrantID, ev.Action)
		}
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
}

func attestVerified(pub ed25519.PublicKey, resource string, payload []byte, got LocalAttestation) bool {
	return got.Domain == AttestDomain && got.Purpose == AttestPurpose && got.Resource == resource &&
		bytes.Equal(got.PublicKey[:], pub) && VerifyLocalAttestation(pub, resource, payload, got.Signature[:]) &&
		got.Signature != [ed25519.SignatureSize]byte{}
}

func attestCount(t *testing.T, path, result string) int {
	t.Helper()
	n := 0
	for _, ev := range mustAudit(t, path) {
		if ev.Action == actionLocalAttest && ev.Result == result {
			n++
		}
	}
	return n
}

func attestFixture(t *testing.T, now time.Time, agent, cred, credType string, g grantRecord) error {
	t.Helper()
	doc := document{
		Credentials: []credential{{
			ID: cred, Label: "key", Type: credType, Secret: []byte("x"),
			Lifecycle: lifecycle{State: StateActive, CreatedAt: now, UpdatedAt: now},
		}},
		Agents: []agentRecord{{
			ID: agent, Label: "agent", Kind: principalAgent, State: agentStateActive, CreatedAt: now,
		}},
		Grants: []grantRecord{g},
	}
	if credType == "api_key" {
		doc.Credentials[0].Type = "api_key"
	}
	return validateAgentsAndGrants(doc)
}

func mustEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func echoedSecret(err error, parts ...[]byte) bool {
	if err == nil {
		return false
	}
	text := []byte(err.Error())
	for _, part := range parts {
		if len(part) > 0 && bytes.Contains(text, part) {
			return true
		}
	}
	return false
}

func assertNoSecrets(t *testing.T, blob []byte, secrets [][]byte) {
	t.Helper()
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		if bytes.Contains(blob, secret) {
			t.Fatalf("found %d secret bytes", len(secret))
		}
		forms := []string{hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret)}
		for _, form := range forms {
			if form != "" && bytes.Contains(blob, []byte(form)) {
				t.Fatalf("found encoded secret form len %d", len(form))
			}
		}
	}
}

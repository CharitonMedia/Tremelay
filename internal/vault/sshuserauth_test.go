package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSSHUserAuthInterop(t *testing.T) {
	env := newSSHEnv(t)
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	before := runtime.NumGoroutine()
	done := make(chan error, 1)
	go func() {
		done <- env.stream.Serve(server)
	}()
	peer := agent.NewClient(client)
	keys, err := peer.List()
	if err != nil || len(keys) != 0 {
		t.Fatalf("unbound list %+v %v", keys, err)
	}
	sessionID := env.sessionID(32)
	if _, err := peer.Extension(sshExtSessionBind, env.bindContents(sessionID, false)); err != nil {
		t.Fatal(err)
	}
	keys, err = peer.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "" || !bytes.Equal(keys[0].Blob, env.userBlob) {
		t.Fatalf("list %+v %v", keys, err)
	}
	if _, err := ssh.ParsePublicKey(keys[0].Blob); err != nil {
		t.Fatal(err)
	}
	preimage := env.preimage(sessionID, env.user, env.userBlob, env.hostBlob)
	sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(env.userPub))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := peer.Sign(sshPub, preimage)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != sshAlgoEd25519 || len(sig.Blob) != ed25519.SignatureSize {
		t.Fatalf("signature format %+v", sig)
	}
	if !bytes.Equal(marshalEd25519Sig(sig.Blob), ssh.Marshal(sig)) {
		t.Fatal("signature encoding drifted from the SSH library")
	}
	parsed, err := ssh.ParsePublicKey(env.userBlob)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(preimage, sig); err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(env.userPub, preimage, sig.Blob) {
		t.Fatal("raw verification failed")
	}
	changed := append([]byte(nil), preimage...)
	changed[len(changed)-1] ^= 0xff
	if parsed.Verify(changed, sig) == nil || ed25519.Verify(env.userPub, changed, sig.Blob) {
		t.Fatal("signature verified a different preimage")
	}
	if bytes.HasPrefix(preimage, []byte(attestMagic)) || ed25519.Verify(env.userPub, []byte(attestMagic), sig.Blob) {
		t.Fatal("SSH preimage used the local-attestation domain")
	}
	client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before {
		t.Fatalf("goroutines %d -> %d", before, got)
	}
	env.assertClean(t, preimage, sessionID, sig.Blob)
}

func TestSSHUserAuthContextDenials(t *testing.T) {
	env := newSSHEnv(t)
	sessionID := env.sessionID(32)
	otherID := env.sessionID(32)
	otherUserPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherUser := marshalEd25519Pub(otherUserPub)
	_, otherHostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherHost := marshalEd25519Pub(otherHostPriv.Public().(ed25519.PublicKey))
	preimage := env.preimage(sessionID, env.user, env.userBlob, env.hostBlob)

	if resp, err := env.stream.roundTrip([]byte{sshAgentRequestIdentities}); err != nil || !bytes.Equal(resp, sshEmptyIdentities()) {
		t.Fatalf("unbound list %x %v", resp, err)
	}
	if resp, err := env.stream.roundTrip(env.signBody(env.userBlob, preimage, 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
		t.Fatalf("unbound sign %x %v", resp, err)
	}
	if id, err := env.principal.Authorize(env.cred.ID, OpSSHUserAuth, env.resource); err != nil || id != env.grant.ID {
		t.Fatalf("authorize %s %v", id, err)
	}
	if resp, err := env.stream.roundTrip(env.signBody(env.userBlob, preimage, 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
		t.Fatal("authorize substituted for a binding")
	}

	badBinds := [][]byte{
		env.bindBody(sessionID, env.hostBlob, env.hostSig(otherHostPriv, sessionID), 0),
		env.bindBody(sessionID, otherHost, env.hostSig(otherHostPriv, sessionID), 0),
		env.bindBody(sessionID, env.hostBlob, env.hostSig(env.hostPriv, otherID), 0),
		env.bindBody(sessionID, env.hostBlob, env.hostSig(env.hostPriv, sessionID), 1),
		env.bindBody(sessionID, env.hostBlob, env.hostSig(env.hostPriv, sessionID), 2),
		append(env.bindBody(sessionID, env.hostBlob, env.hostSig(env.hostPriv, sessionID), 0), 0),
	}
	for i, body := range badBinds {
		if resp, err := env.stream.roundTrip(body); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) || env.stream.bound {
			t.Fatalf("bad bind %d resp %x bound %v err %v", i, resp, env.stream.bound, err)
		}
	}
	if resp, err := env.stream.roundTrip(env.bindBody(sessionID, env.hostBlob, env.hostSig(env.hostPriv, sessionID), 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentSuccess}) || !env.stream.bound {
		t.Fatalf("bind %x %v", resp, err)
	}
	if resp, err := env.stream.roundTrip(env.bindBody(sessionID, env.hostBlob, env.hostSig(env.hostPriv, sessionID), 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) || !bytes.Equal(env.stream.sessionID, sessionID) {
		t.Fatal("duplicate bind replaced the session")
	}
	if resp, err := env.stream.roundTrip(env.bindBody(otherID, env.hostBlob, env.hostSig(env.hostPriv, otherID), 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) || !bytes.Equal(env.stream.sessionID, sessionID) {
		t.Fatal("rebinding replaced the session")
	}

	cases := [][]byte{
		env.signBody(env.userBlob, env.preimage(sessionID, "other-user", env.userBlob, env.hostBlob), 0),
		env.signBody(env.userBlob, env.preimage(otherID, env.user, env.userBlob, env.hostBlob), 0),
		env.signBody(env.userBlob, env.preimage(sessionID, env.user, otherUser, env.hostBlob), 0),
		env.signBody(otherUser, env.preimage(sessionID, env.user, otherUser, env.hostBlob), 0),
		env.signBody(env.userBlob, env.preimage(sessionID, env.user, env.userBlob, otherHost), 0),
		env.signBody(env.userBlob, env.methodPreimage(sessionID, "publickey"), 0),
		env.signBody(env.userBlob, []byte("not-a-userauth-request"), 0),
		env.signBody(env.userBlob, append([]byte("SSHSIG"), bytes.Repeat([]byte{1}, 32)...), 0),
		env.signBody(env.userBlob, env.boolPreimage(sessionID, 0), 0),
		env.signBody(env.userBlob, env.boolPreimage(sessionID, 2), 0),
		env.signBody(env.userBlob, append(preimage, 0), 0),
		env.signBody(env.userBlob, preimage, 1),
		env.signBody(env.userBlob, env.algoPreimage(sessionID, "ssh-rsa"), 0),
		env.signBody(env.userBlob, env.algoPreimage(sessionID, "ssh-ed25519-cert-v01@openssh.com"), 0),
		env.signBody(env.userBlob, env.servicePreimage(sessionID, "ssh-userauth"), 0),
	}
	for i, body := range cases {
		resp, err := env.stream.roundTrip(body)
		if err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
			t.Fatalf("case %d %x %v", i, resp, err)
		}
	}
	if _, err := peerSign(env, sessionID); err != nil {
		t.Fatal(err)
	}

	other := env.secondStream(t)
	if resp, err := other.roundTrip([]byte{sshAgentRequestIdentities}); err != nil || !bytes.Equal(resp, sshEmptyIdentities()) {
		t.Fatal("second stream saw the first binding")
	}
	if resp, err := other.roundTrip(env.signBody(env.userBlob, preimage, 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
		t.Fatal("second stream borrowed the session")
	}
	borrowed := env.preimage(otherID, env.user, env.userBlob, env.hostBlob)
	if resp, err := other.roundTrip(env.bindBody(otherID, env.hostBlob, env.hostSig(env.hostPriv, otherID), 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentSuccess}) {
		t.Fatalf("second bind %x %v", resp, err)
	}
	if resp, err := env.stream.roundTrip(env.signBody(env.userBlob, borrowed, 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
		t.Fatal("first stream accepted the second session")
	}
	if resp, err := other.roundTrip(env.signBody(env.userBlob, preimage, 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
		t.Fatal("second stream accepted the first session")
	}
}

func TestSSHUserAuthLegacyAndIssuance(t *testing.T) {
	env := newSSHEnv(t)
	exp := time.Now().Add(time.Hour).UTC()
	rejects := []GrantSpec{
		{AgentID: env.agent.ID, CredentialClass: CredTypeEd25519, Operations: []string{OpSSHUserAuth}, Resource: env.resource, ExpiresAt: exp, SSHUsername: env.user, SSHHostKey: env.hostBlob},
		{AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSSHUserAuth, OpHTTPRequest}, Resource: env.resource, ExpiresAt: exp, SSHUsername: env.user, SSHHostKey: env.hostBlob},
		{AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSSHUserAuth}, Resource: "*", ExpiresAt: exp, SSHUsername: env.user, SSHHostKey: env.hostBlob},
		{AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSSHUserAuth}, Resource: env.resource, ExpiresAt: exp, SSHHostKey: env.hostBlob},
		{AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSSHUserAuth}, Resource: env.resource, ExpiresAt: exp, SSHUsername: "bad\nuser", SSHHostKey: env.hostBlob},
		{AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSSHUserAuth}, Resource: env.resource, ExpiresAt: exp, SSHUsername: env.user, SSHHostKey: env.userPub},
		{AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSign}, Resource: env.resource, ExpiresAt: exp, SSHUsername: env.user, SSHHostKey: env.hostBlob},
	}
	for i, spec := range rejects {
		if _, err := env.session.IssueGrant(spec); !errors.Is(err, ErrInvalid) {
			t.Fatalf("issuance %d %v", i, err)
		}
	}
	legacy := []string{OpSign, OpHTTPRequest, OpGitHubIssueState, OpLocalArtifactAttest}
	var legacyIDs []string
	for _, op := range legacy {
		spec := GrantSpec{AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{op}, Resource: env.resource, ExpiresAt: exp}
		if op == OpLocalArtifactAttest {
			spec.Resource = "artifact:" + env.resource
		}
		g, err := env.session.IssueGrant(spec)
		if err != nil {
			t.Fatal(err)
		}
		legacyIDs = append(legacyIDs, g.ID)
		if _, err := env.principal.SSHUserAuth(g.ID); !errors.Is(err, ErrDeniedOperation) {
			t.Fatalf("%s constructed an SSH stream: %v", op, err)
		}
		if id, err := env.principal.Authorize(env.cred.ID, OpSSHUserAuth, env.resource); err != nil || id != env.grant.ID {
			t.Fatalf("legacy authorize %s %v", id, err)
		}
	}
	if _, err := env.principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: env.resource, Payload: []byte("payload-bytes")}); err == nil {
		t.Fatal("ssh grant authorized local attestation")
	}
	if _, err := env.principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: "artifact:" + env.resource, Payload: []byte("payload-bytes")}); err != nil {
		t.Fatal(err)
	}
	env.session.Lock()
	opened, err := Unlock(env.path, env.pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Lock() })
	again, err := opened.Agent(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range legacyIDs {
		if _, err := again.SSHUserAuth(id); !errors.Is(err, ErrDeniedOperation) {
			t.Fatalf("reopen constructed %s: %v", id, err)
		}
	}
	stream, err := again.SSHUserAuth(env.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: "artifact:" + env.resource, Payload: []byte("payload-bytes")}); err != nil {
		t.Fatal(err)
	}
	sid := env.sessionID(16)
	if resp, err := stream.roundTrip(env.bindBody(sid, env.hostBlob, env.hostSig(env.hostPriv, sid), 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentSuccess}) {
		t.Fatalf("reopen bind %x %v", resp, err)
	}

	now := time.Now().UTC()
	base := grantRecord{
		ID: env.grant.ID, AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSSHUserAuth},
		Resource: env.resource, CreatedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: env.grant.KeyID,
		SSHUsername: env.user, SSHHostKey: env.hostBlob,
	}
	if err := sshFixture(t, now, env.agent.ID, env.cred.ID, base); err != nil {
		t.Fatal(err)
	}
	signGrant := base
	signGrant.Operations = []string{OpSign}
	signGrant.KeyID = ""
	signGrant.SSHUsername = ""
	signGrant.SSHHostKey = nil
	if err := sshFixture(t, now, env.agent.ID, env.cred.ID, signGrant); err != nil {
		t.Fatal(err)
	}
	bad := []grantRecord{
		func() grantRecord { g := base; g.SSHUsername = ""; return g }(),
		func() grantRecord { g := base; g.SSHHostKey = nil; return g }(),
		func() grantRecord { g := base; g.SSHHostKey = env.userPub; return g }(),
		func() grantRecord { g := base; g.KeyID = ""; return g }(),
		func() grantRecord { g := base; g.CredentialClass = CredTypeEd25519; g.CredentialID = ""; return g }(),
		func() grantRecord { g := signGrant; g.SSHUsername = env.user; return g }(),
		func() grantRecord { g := signGrant; g.SSHHostKey = env.hostBlob; return g }(),
		func() grantRecord { g := signGrant; g.KeyID = env.grant.KeyID; return g }(),
		func() grantRecord {
			g := base
			g.Operations = []string{OpLocalArtifactAttest}
			g.SSHUsername = ""
			g.SSHHostKey = nil
			g.SSHUsername = env.user
			return g
		}(),
	}
	for i, g := range bad {
		if err := sshFixture(t, now, env.agent.ID, env.cred.ID, g); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corrupt %d %v", i, err)
		}
	}
	for i := range opened.grants {
		if opened.grants[i].ID == legacyIDs[0] {
			opened.grants[i].SSHUsername = env.user
		}
	}
	if err := opened.RejectAuthorize(ErrInvalid); err != nil && !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	opened.Lock()
	if _, err := Unlock(env.path, env.pass, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cross-operation document reopened: %v", err)
	}
}

func TestSSHUserAuthLifecycleAndGrantPin(t *testing.T) {
	env := newSSHEnv(t)
	sid := env.sessionID(32)
	env.mustBind(t, sid)
	first := env.mustSign(t, sid)
	second := env.mustSign(t, sid)
	if !bytes.Equal(first, second) {
		t.Fatal("repeated Ed25519 signature changed")
	}
	if sshCount(t, env.path, resultCompleted) < 2 || sshCount(t, env.path, resultAllowed) < 2 {
		t.Fatal("repeated requests were not audited separately")
	}
	past := time.Now().Add(-time.Hour).UTC()
	if _, err := env.session.SetLifecycle(env.cred.ID, LifecycleOptions{ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	health, err := env.session.Health(env.cred.ID)
	if err != nil || !finding(health, ReasonExpired) {
		t.Fatalf("health %+v %v", health, err)
	}
	if !bytes.Equal(env.mustSign(t, sid), first) {
		t.Fatal("health finding blocked signing")
	}
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatal(err)
	}

	env.session.clock = func() time.Time { return env.grant.ExpiresAt }
	if resp, err := env.stream.roundTrip(env.signBody(env.userBlob, env.preimage(sid, env.user, env.userBlob, env.hostBlob), 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
		t.Fatal("expired grant signed")
	}
	env.session.clock = nil
	if !bytes.Equal(env.mustSign(t, sid), first) {
		t.Fatal("clock reset did not restore the grant")
	}
	for i := range env.session.agents {
		if env.session.agents[i].ID == env.agent.ID {
			env.session.agents[i].State = agentStateSuspended
		}
	}
	if resp, err := env.stream.roundTrip([]byte{sshAgentRequestIdentities}); err != nil || !bytes.Equal(resp, sshEmptyIdentities()) {
		t.Fatal("suspended principal listed a key")
	}
	for i := range env.session.agents {
		if env.session.agents[i].ID == env.agent.ID {
			env.session.agents[i].State = agentStateActive
		}
	}
	for i := range env.session.creds {
		if env.session.creds[i].ID == env.cred.ID {
			env.session.creds[i].Lifecycle.State = "disabled"
		}
	}
	if resp, err := env.stream.roundTrip(env.signBody(env.userBlob, env.preimage(sid, env.user, env.userBlob, env.hostBlob), 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) || sshCount(t, env.path, resultCompleted) == 0 {
		t.Fatalf("inactive lifecycle %x %v", resp, err)
	}
	if sshCount(t, env.path, resultFailed) == 0 {
		t.Fatal("inactive lifecycle was not recorded")
	}
	env.session.Lock()
	if _, err := Unlock(env.path, env.pass, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("inactive lifecycle reopened: %v", err)
	}
}

func TestSSHUserAuthGrantPinOrder(t *testing.T) {
	for _, currentHigher := range []bool{false, true} {
		name := "current_lower_id"
		if currentHigher {
			name = "current_higher_id"
		}
		t.Run(name, func(t *testing.T) {
			path, pass, s := mustCreate(t, nil)
			pubA, privA := mustEd25519(t)
			pubB, privB := mustEd25519(t)
			derA, err := x509.MarshalPKCS8PrivateKey(privA)
			if err != nil {
				t.Fatal(err)
			}
			derB, err := x509.MarshalPKCS8PrivateKey(privB)
			if err != nil {
				t.Fatal(err)
			}
			cred, err := s.Put("synthetic-key", CredTypeEd25519, derA, PutOptions{})
			if err != nil {
				t.Fatal(err)
			}
			agent, err := s.CreateAgent("worker")
			if err != nil {
				t.Fatal(err)
			}
			hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			hostBlob := marshalEd25519Pub(hostPub)
			user := "acct-" + randHex(t, 8)
			resource := "ssh:" + randHex(t, 8)
			spec := GrantSpec{
				AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpSSHUserAuth},
				Resource: resource, ExpiresAt: time.Now().Add(time.Hour).UTC(), SSHUsername: user, SSHHostKey: hostBlob,
			}
			grantA, err := s.IssueGrant(spec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Replace(cred.ID, derB, LifecycleOptions{}); err != nil {
				t.Fatal(err)
			}
			grantB, err := s.IssueGrant(spec)
			if err != nil {
				t.Fatal(err)
			}
			current, stale := grantB, grantA
			currentPub := ed25519.PublicKey(pubB)
			stalePub := ed25519.PublicKey(pubA)
			currentDER := derB
			if (grantB.ID > grantA.ID) != currentHigher {
				current, stale = grantA, grantB
				currentPub, stalePub = pubA, pubB
				currentDER = derA
				if _, err = s.Replace(cred.ID, currentDER, LifecycleOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			p, err := s.Agent(agent.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stale.ID < current.ID {
				if id, err := p.Authorize(cred.ID, OpSSHUserAuth, resource); id != "" || !errors.Is(err, ErrDeniedKey) {
					t.Fatalf("lowest stale grant was selected %s %v", id, err)
				}
			} else if id, err := p.Authorize(cred.ID, OpSSHUserAuth, resource); err != nil || id != current.ID {
				t.Fatalf("authorize %s %v", id, err)
			}
			staleStream, err := p.SSHUserAuth(stale.ID)
			if err != nil {
				t.Fatal(err)
			}
			currentStream, err := p.SSHUserAuth(current.ID)
			if err != nil {
				t.Fatal(err)
			}
			sid := bytes.Repeat([]byte{0x3c}, 32)
			sig := marshalEd25519Sig(ed25519.Sign(hostPriv, sid))
			bind := bindMessage(hostBlob, sid, sig, 0)
			if resp, err := staleStream.roundTrip(bind); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) || staleStream.bound {
				t.Fatalf("stale grant accepted a binding %x bound %v %v", resp, staleStream.bound, err)
			}
			if resp, err := currentStream.roundTrip(bind); err != nil || !bytes.Equal(resp, []byte{sshAgentSuccess}) {
				t.Fatalf("current bind %x %v", resp, err)
			}
			userBlob := marshalEd25519Pub(currentPub)
			body := signMessage(userBlob, userauthPreimage(sid, user, userBlob, hostBlob), 0)
			if resp, err := staleStream.roundTrip(body); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
				t.Fatal("stale grant signed")
			}
			resp, err := currentStream.roundTrip(body)
			if err != nil || resp[0] != sshAgentSignResponse {
				t.Fatalf("current sign %x %v", resp, err)
			}
			raw := signatureRaw(t, resp)
			if !ed25519.Verify(currentPub, userauthPreimage(sid, user, userBlob, hostBlob), raw) || ed25519.Verify(stalePub, userauthPreimage(sid, user, userBlob, hostBlob), raw) {
				t.Fatal("signature key")
			}
			if err := s.RevokeGrant(current.ID); err != nil {
				t.Fatal(err)
			}
			if resp, err := currentStream.roundTrip(body); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
				t.Fatal("revoked grant was rescued")
			}
			s.Lock()
			opened, err := Unlock(path, pass, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Lock()
			p, err = opened.Agent(agent.ID)
			if err != nil {
				t.Fatal(err)
			}
			again, err := p.SSHUserAuth(current.ID)
			if err != nil {
				t.Fatal(err)
			}
			before := len(mustAudit(t, path))
			if resp, err := again.roundTrip(body); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
				t.Fatalf("reopen sign %x %v", resp, err)
			}
			rows := mustAudit(t, path)[before:]
			if len(rows) == 0 || rows[0].GrantID != current.ID || rows[0].Result != resultDeniedRevoked {
				t.Fatalf("reopen moved the adapter onto another grant: %+v", rows)
			}
		})
	}
}

func TestSSHUserAuthMalformed(t *testing.T) {
	env := newSSHEnv(t)
	sid := env.sessionID(32)
	env.mustBind(t, sid)
	sentinel := []byte("SSH-ADD-SENTINEL-" + randHex(t, 24))
	body := append([]byte{17}, sentinel...)
	resp, err := env.stream.roundTrip(body)
	if err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
		t.Fatalf("add %x %v", resp, err)
	}
	for _, op := range []byte{1, 9, 18, 19, 20, 21, 22, 23, 25, 26} {
		resp, err = env.stream.roundTrip(append([]byte{op}, sentinel...))
		if err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
			t.Fatalf("opcode %d %x %v", op, resp, err)
		}
	}
	if resp, err = env.stream.roundTrip(append([]byte{sshAgentExtension}, appendSSHString(nil, []byte("query"))...)); err != nil || !bytes.Equal(resp, []byte{sshAgentExtensionFailure}) {
		t.Fatalf("query %x %v", resp, err)
	}
	env.assertClean(t, sentinel, sid, nil)

	huge := make([]byte, 0, 4+len(sentinel))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], 0xffffffff)
	huge = append(huge, n[:]...)
	huge = append(huge, sentinel...)
	got, err := readSSHFrame(bytes.NewReader(huge))
	if got != nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize %x %v", got, err)
	}
	rest, _ := io.ReadAll(bytes.NewReader(huge[4:]))
	if !bytes.Equal(rest, sentinel) {
		t.Fatal("oversize frame consumed the payload")
	}
	short := bytes.NewReader([]byte{0, 0, 0, 10, 1, 2})
	if _, err := readSSHFrame(short); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := readSSHFrame(bytes.NewReader([]byte{0, 0, 0, 4})); !errors.Is(err, ErrInvalid) {
		t.Fatalf("length then EOF: %v", err)
	}
	if _, err := readSSHFrame(bytes.NewReader(nil)); err != io.EOF {
		t.Fatalf("clean EOF: %v", err)
	}
	lengths := []uint32{0, 1 << 20, 1 << 31, 0xfffffffe}
	for _, ln := range lengths {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], ln)
		if _, err := readSSHFrame(bytes.NewReader(hdr[:])); !errors.Is(err, ErrInvalid) {
			t.Fatalf("length %d %v", ln, err)
		}
	}
	inner := []byte{sshAgentSignRequest, 0x7f, 0xff, 0xff, 0xff}
	if _, _, _, ok := parseSignBody(inner); ok {
		t.Fatal("inner length allocated")
	}

	var input bytes.Buffer
	input.Write(frameSSH(env.bindBody(sid, env.hostBlob, env.hostSig(env.hostPriv, sid), 0)))
	input.Write(frameSSH([]byte{sshAgentRequestIdentities}))
	input.Write(frameSSH(env.signBody(env.userBlob, env.preimage(sid, env.user, env.userBlob, env.hostBlob), 0)))
	var output bytes.Buffer
	fresh, err := env.principal.SSHUserAuth(env.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Serve(struct {
		io.Reader
		io.Writer
	}{&input, &output}); err != nil {
		t.Fatal(err)
	}
	frames := splitFrames(t, output.Bytes())
	if len(frames) != 3 || frames[2][0] != sshAgentSignResponse {
		t.Fatalf("frames %d", len(frames))
	}

	fail := &failWriter{failOn: 2, secret: "writer-sentinel-" + randHex(t, 8)}
	var again bytes.Buffer
	again.Write(frameSSH(env.bindBody(sid, env.hostBlob, env.hostSig(env.hostPriv, sid), 0)))
	again.Write(frameSSH(env.signBody(env.userBlob, env.preimage(sid, env.user, env.userBlob, env.hostBlob), 0)))
	stream, err := env.principal.SSHUserAuth(env.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = stream.Serve(struct {
		io.Reader
		io.Writer
	}{&again, fail})
	if !errors.Is(err, errSSHTransport) || strings.Contains(err.Error(), fail.secret) {
		t.Fatal(err)
	}
	if bytes.Contains(fail.got.Bytes(), []byte(sshAlgoEd25519)) {
		t.Fatal("transport failure delivered a signature")
	}
	if sshCount(t, env.path, resultCompleted) == 0 {
		t.Fatal("transport failure rewrote a completed release")
	}
	if bytes.Contains(readAll(t, env.path), []byte(fail.secret)) {
		t.Fatal("writer error stored")
	}
}

func TestSSHUserAuthBindAuditAndTruncatedFrame(t *testing.T) {
	env := newSSHEnv(t)
	sid := env.sessionID(16)
	allowed := sshCount(t, env.path, resultAllowed)
	env.mustBind(t, sid)
	if sshCount(t, env.path, resultAllowed) != allowed+1 || sshCount(t, env.path, resultCompleted) != 0 {
		t.Fatalf("bind audit allowed %d completed %d", sshCount(t, env.path, resultAllowed), sshCount(t, env.path, resultCompleted))
	}
	env.assertClean(t, nil, sid, nil)

	stream := env.secondStream(t)
	env.session.commitFault = func() error { return errors.New("induced " + env.user) }
	resp, err := stream.roundTrip(env.bindBody(sid, env.hostBlob, env.hostSig(env.hostPriv, sid), 0))
	env.session.commitFault = nil
	if resp != nil || !errors.Is(err, ErrAudit) || stream.bound || strings.Contains(err.Error(), env.user) {
		t.Fatalf("bind audit failure resp %x bound %v err %v", resp, stream.bound, err)
	}
	if sshCount(t, env.path, resultAllowed) != allowed+1 {
		t.Fatal("failed bind wrote allowed")
	}

	denied := sshCount(t, env.path, resultDenied)
	fresh, err := env.principal.SSHUserAuth(env.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Serve(bytes.NewBuffer(nil)); err != nil {
		t.Fatalf("clean EOF %v", err)
	}
	if sshCount(t, env.path, resultDenied) != denied {
		t.Fatal("clean EOF recorded a denial")
	}

	var truncated bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 4)
	truncated.Write(hdr[:])
	cut, err := env.principal.SSHUserAuth(env.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = cut.Serve(&truncated)
	if !errors.Is(err, ErrInvalid) || err.Error() != ErrInvalid.Error() {
		t.Fatalf("truncated body %v", err)
	}
	if sshCount(t, env.path, resultDenied) != denied+1 {
		t.Fatal("truncated frame was not denied")
	}

	var partial bytes.Buffer
	partial.Write([]byte{0, 0})
	mid, err := env.principal.SSHUserAuth(env.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := mid.Serve(&partial); !errors.Is(err, ErrInvalid) {
		t.Fatalf("partial header %v", err)
	}

	sentinel := "STREAM-SENTINEL-" + randHex(t, 16)
	leak := &sentinelStream{text: sentinel}
	noisy, err := env.principal.SSHUserAuth(env.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = noisy.Serve(leak)
	if !errors.Is(err, errSSHTransport) || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("reader error %v", err)
	}
	env.assertClean(t, []byte(sentinel), sid, nil)
}

type sentinelStream struct {
	text string
}

func (s *sentinelStream) Read([]byte) (int, error) {
	return 0, errors.New(s.text)
}

func (s *sentinelStream) Write([]byte) (int, error) {
	return 0, errors.New(s.text)
}

func TestSSHUserAuthAuditBoundaries(t *testing.T) {
	var logs bytes.Buffer
	env := newSSHEnvLog(t, &logs)
	sid := env.sessionID(32)
	env.mustBind(t, sid)
	body := env.signBody(env.userBlob, env.preimage(sid, env.user, env.userBlob, env.hostBlob), 0)
	allowed := sshCount(t, env.path, resultAllowed)
	completed := sshCount(t, env.path, resultCompleted)
	env.session.commitFault = func() error { return errors.New("induced " + env.user) }
	resp, err := env.stream.roundTrip(body)
	env.session.commitFault = nil
	if resp != nil || !errors.Is(err, ErrAudit) || sshCount(t, env.path, resultAllowed) != allowed || sshCount(t, env.path, resultCompleted) != completed {
		t.Fatalf("allowed audit failure resp %x err %v", resp, err)
	}
	var n int
	env.session.commitFault = func() error {
		n++
		if n == 1 {
			return nil
		}
		return errors.New("induced")
	}
	resp, err = env.stream.roundTrip(body)
	env.session.commitFault = nil
	if resp != nil || !errors.Is(err, ErrAudit) || sshCount(t, env.path, resultAllowed) != allowed+1 || sshCount(t, env.path, resultCompleted) != completed {
		t.Fatalf("completed audit failure resp %x allowed %d completed %d err %v", resp, sshCount(t, env.path, resultAllowed), sshCount(t, env.path, resultCompleted), err)
	}
	env.session.sshFault = func() error { return errors.New("fault " + env.user) }
	resp, err = env.stream.roundTrip(body)
	env.session.sshFault = nil
	if err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) || sshCount(t, env.path, resultFailed) == 0 || sshCount(t, env.path, resultCompleted) != completed {
		t.Fatalf("fault %x %v", resp, err)
	}
	raw := env.mustSign(t, sid)
	if !ed25519.Verify(env.userPub, env.preimage(sid, env.user, env.userBlob, env.hostBlob), raw) {
		t.Fatal("later sign failed")
	}

	agentID := strings.Repeat("ab", 16)
	var chain []auditEvent
	for i := 0; i < detectionThreshold-1; i++ {
		chain = append(chain, auditEvent{Seq: uint64(len(chain) + 1), Action: actionBroker, Result: resultDeniedMissing, AgentID: agentID})
	}
	for i := 0; i < 8; i++ {
		chain = append(chain, auditEvent{Seq: uint64(len(chain) + 1), Action: actionSSHUserAuth, Result: resultDenied, AgentID: agentID})
	}
	if got := classify(chain, chain[len(chain)-1]); got.Class != ClassExpectedDenial {
		t.Fatalf("ssh denials promoted %+v", got)
	}
	chain = append(chain, auditEvent{Seq: uint64(len(chain) + 1), Action: actionBroker, Result: resultDeniedMissing, AgentID: agentID})
	if got := classify(chain, chain[len(chain)-1]); got.Class != ClassRepeatedDenial {
		t.Fatalf("broker threshold moved %+v", got)
	}

	sink := &MemoryNotifier{}
	if err := env.session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if err := env.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	if err := env.session.RevokeGrant(env.grant.ID); err != nil {
		t.Fatal(err)
	}
	if resp, err = env.stream.roundTrip(body); err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
		t.Fatal(err)
	}
	notes := sink.Snapshot()
	if len(notes) != 1 || notes[0].Class != ClassReplay || notes[0].Action != actionSSHUserAuth || notes[0].Result != resultDeniedRevoked {
		t.Fatalf("notice %+v", notes)
	}
	encoded, _ := json.Marshal(notes)
	env.assertClean(t, append(encoded, logs.Bytes()...), sid, raw)
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatal(err)
	}
}

func TestSSHUserAuthAuditTamper(t *testing.T) {
	env := newSSHEnv(t)
	sid := env.sessionID(8)
	env.mustBind(t, sid)
	env.mustSign(t, sid)
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatal(err)
	}
	tamper := env.path + ".tamper"
	copyFile(t, env.path, tamper)
	mutateDB(t, tamper, func(db *sql.DB) {
		if _, err := db.Exec(`UPDATE audit SET result = ? WHERE action = ? AND result = ?`, resultAllowed, actionSSHUserAuth, resultCompleted); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := VerifyAudit(tamper, env.pass); !errors.Is(err, ErrAudit) {
		t.Fatalf("tampered chain verified: %v", err)
	}
	ev := auditEvent{
		Action: actionSSHUserAuth, Result: resultCompleted, AgentID: env.agent.ID, GrantID: env.grant.ID,
		CredID: env.cred.ID, CredType: CredTypeEd25519, Operation: OpSSHUserAuth,
	}
	chain := mustAudit(t, env.path)
	next, err := nextAudit(chain[:1], chain[0].VaultID, ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(append(chain[:1], next)); err != nil {
		t.Fatal(err)
	}
	next.Operation = env.user
	if err := verifyChain(append(chain[:1], next)); !errors.Is(err, ErrAudit) {
		t.Fatal("username was accepted as an operation")
	}
}

func TestSSHUserAuthLocked(t *testing.T) {
	env := newSSHEnv(t)
	sid := env.sessionID(8)
	env.mustBind(t, sid)
	before := len(mustAudit(t, env.path))
	env.session.Lock()
	resp, err := env.stream.roundTrip(env.signBody(env.userBlob, env.preimage(sid, env.user, env.userBlob, env.hostBlob), 0))
	if resp != nil || !errors.Is(err, ErrUnauthenticated) || len(mustAudit(t, env.path)) != before {
		t.Fatalf("locked session %x %v rows %d", resp, err, len(mustAudit(t, env.path))-before)
	}
}

func TestSSHUserAuthDirectRelease(t *testing.T) {
	env := newSSHEnv(t)
	sid := env.sessionID(32)
	sig, err := env.session.sshRelease(env.agent.ID, env.grant.ID, nil, nil, nil, env.signBody(env.userBlob, []byte("raw"), 0))
	if sig != nil || err == nil {
		t.Fatal("direct release signed without a proof")
	}
	env.mustBind(t, sid)
	sig, err = env.session.sshRelease(env.agent.ID, env.grant.ID, env.stream.hostKey, env.stream.sessionID, env.stream.hostSig, env.signBody(env.userBlob, env.methodPreimage(sid, "publickey"), 0))
	if sig != nil || err == nil {
		t.Fatal("direct release signed ordinary publickey")
	}
}

type sshEnv struct {
	t         *testing.T
	path      string
	pass      []byte
	logs      *bytes.Buffer
	session   *Session
	userPub   ed25519.PublicKey
	userPriv  ed25519.PrivateKey
	hostPub   ed25519.PublicKey
	hostPriv  ed25519.PrivateKey
	userBlob  []byte
	hostBlob  []byte
	der       []byte
	cred      Credential
	agent     Agent
	principal *AgentPrincipal
	grant     Grant
	resource  string
	user      string
	stream    *SSHUserAuth
}

func newSSHEnv(t *testing.T) *sshEnv {
	t.Helper()
	return newSSHEnvLog(t, nil)
}

func newSSHEnvLog(t *testing.T, logs *bytes.Buffer) *sshEnv {
	t.Helper()
	var logger *log.Logger
	if logs != nil {
		logger = log.New(logs, "", 0)
	}
	path, pass, session := mustCreate(t, logger)
	userPub, userPriv := mustEd25519(t)
	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(userPriv)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := session.Put("ssh-user", CredTypeEd25519, der, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := session.CreateAgent("ssh-worker")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	env := &sshEnv{
		t: t, path: path, pass: pass, logs: logs, session: session,
		userPub: userPub, userPriv: userPriv, hostPub: hostPub, hostPriv: hostPriv,
		userBlob: marshalEd25519Pub(userPub), hostBlob: marshalEd25519Pub(hostPub), der: der,
		cred: cred, agent: agent, principal: principal,
		resource: "label-" + randHex(t, 12), user: "user-" + randHex(t, 12),
	}
	env.grant, err = session.IssueGrant(GrantSpec{
		AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpSSHUserAuth},
		Resource: env.resource, ExpiresAt: time.Now().Add(time.Hour).UTC(),
		SSHUsername: env.user, SSHHostKey: env.hostBlob,
	})
	if err != nil || env.grant.KeyID != hex.EncodeToString(userPub) || !bytes.Equal(env.grant.SSHHostKey, env.hostBlob) || env.grant.SSHUsername != env.user {
		t.Fatalf("grant %+v %v", env.grant, err)
	}
	env.stream, err = principal.SSHUserAuth(env.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := principal.SSHUserAuth(env.grant.ID + "00"); !errors.Is(err, ErrGrantNotFound) && !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	return env
}

func (e *sshEnv) sessionID(n int) []byte {
	e.t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		e.t.Fatal(err)
	}
	return buf
}

func (e *sshEnv) hostSig(priv ed25519.PrivateKey, sessionID []byte) []byte {
	return marshalEd25519Sig(ed25519.Sign(priv, sessionID))
}

func (e *sshEnv) bindContents(sessionID []byte, forwarding bool) []byte {
	flag := byte(0)
	if forwarding {
		flag = 1
	}
	body := appendSSHString(nil, e.hostBlob)
	body = appendSSHString(body, sessionID)
	body = appendSSHString(body, e.hostSig(e.hostPriv, sessionID))
	return append(body, flag)
}

func (e *sshEnv) bindBody(sessionID, host, sig []byte, flag byte) []byte {
	body := append([]byte{sshAgentExtension}, appendSSHString(nil, []byte(sshExtSessionBind))...)
	body = appendSSHString(body, host)
	body = appendSSHString(body, sessionID)
	body = appendSSHString(body, sig)
	return append(body, flag)
}

func (e *sshEnv) preimage(sessionID []byte, user string, userBlob, hostBlob []byte) []byte {
	return userauthPreimage(sessionID, user, userBlob, hostBlob)
}

func (e *sshEnv) signBody(key, data []byte, flags uint32) []byte {
	return signMessage(key, data, flags)
}

func (e *sshEnv) methodPreimage(sessionID []byte, method string) []byte {
	return e.swapPreimage(sessionID, method, sshServiceConnection, sshAlgoEd25519, 1)
}

func (e *sshEnv) algoPreimage(sessionID []byte, algo string) []byte {
	return e.swapPreimage(sessionID, sshUserAuthMethod, sshServiceConnection, algo, 1)
}

func (e *sshEnv) servicePreimage(sessionID []byte, service string) []byte {
	return e.swapPreimage(sessionID, sshUserAuthMethod, service, sshAlgoEd25519, 1)
}

func (e *sshEnv) boolPreimage(sessionID []byte, flag byte) []byte {
	return e.swapPreimage(sessionID, sshUserAuthMethod, sshServiceConnection, sshAlgoEd25519, flag)
}

func (e *sshEnv) swapPreimage(sessionID []byte, method, service, algo string, flag byte) []byte {
	body := appendSSHString(nil, sessionID)
	body = append(body, sshMsgUserAuthRequest)
	body = appendSSHString(body, []byte(e.user))
	body = appendSSHString(body, []byte(service))
	body = appendSSHString(body, []byte(method))
	body = append(body, flag)
	body = appendSSHString(body, []byte(algo))
	body = appendSSHString(body, e.userBlob)
	body = appendSSHString(body, e.hostBlob)
	return body
}

func (e *sshEnv) mustBind(t *testing.T, sessionID []byte) {
	t.Helper()
	resp, err := e.stream.roundTrip(e.bindBody(sessionID, e.hostBlob, e.hostSig(e.hostPriv, sessionID), 0))
	if err != nil || !bytes.Equal(resp, []byte{sshAgentSuccess}) {
		t.Fatalf("bind %x %v", resp, err)
	}
}

func (e *sshEnv) mustSign(t *testing.T, sessionID []byte) []byte {
	t.Helper()
	resp, err := e.stream.roundTrip(e.signBody(e.userBlob, e.preimage(sessionID, e.user, e.userBlob, e.hostBlob), 0))
	if err != nil {
		t.Fatal(err)
	}
	return signatureRaw(t, resp)
}

func (e *sshEnv) secondStream(t *testing.T) *SSHUserAuth {
	t.Helper()
	s, err := e.principal.SSHUserAuth(e.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *sshEnv) assertClean(t *testing.T, extra []byte, sessionID, sig []byte) {
	t.Helper()
	secrets := [][]byte{e.der, e.userPriv.Seed(), append([]byte(nil), e.userPriv...), e.hostPriv.Seed(), sessionID, sig, []byte(e.user), []byte(e.resource), e.hostBlob, extra}
	if e.logs != nil {
		assertNoSecrets(t, e.logs.Bytes(), secrets)
	}
	assertNoSecrets(t, readAll(t, e.path), secrets)
	for _, ev := range mustAudit(t, e.path) {
		fields := strings.Join([]string{ev.Action, ev.VaultID, ev.CredID, ev.CredType, ev.Result, ev.AgentID, ev.GrantID, ev.Operation, ev.Class, ev.Time, ev.Reasons, ev.Prev, ev.Hash}, "\n")
		assertNoSecrets(t, []byte(fields), secrets)
	}
}

func peerSign(env *sshEnv, sessionID []byte) ([]byte, error) {
	resp, err := env.stream.roundTrip(env.signBody(env.userBlob, env.preimage(sessionID, env.user, env.userBlob, env.hostBlob), 0))
	if err != nil {
		return nil, err
	}
	if resp[0] != sshAgentSignResponse {
		return nil, errors.New("not a signature")
	}
	return resp, nil
}

func userauthPreimage(sessionID []byte, user string, userBlob, hostBlob []byte) []byte {
	body := appendSSHString(nil, sessionID)
	body = append(body, sshMsgUserAuthRequest)
	body = appendSSHString(body, []byte(user))
	body = appendSSHString(body, []byte(sshServiceConnection))
	body = appendSSHString(body, []byte(sshUserAuthMethod))
	body = append(body, 1)
	body = appendSSHString(body, []byte(sshAlgoEd25519))
	body = appendSSHString(body, userBlob)
	return appendSSHString(body, hostBlob)
}

func signMessage(key, data []byte, flags uint32) []byte {
	body := append([]byte{sshAgentSignRequest}, appendSSHString(nil, key)...)
	body = appendSSHString(body, data)
	var f [4]byte
	binary.BigEndian.PutUint32(f[:], flags)
	return append(body, f[:]...)
}

func bindMessage(host, sessionID, sig []byte, flag byte) []byte {
	body := append([]byte{sshAgentExtension}, appendSSHString(nil, []byte(sshExtSessionBind))...)
	body = appendSSHString(body, host)
	body = appendSSHString(body, sessionID)
	body = appendSSHString(body, sig)
	return append(body, flag)
}

func signatureRaw(t *testing.T, resp []byte) []byte {
	t.Helper()
	if len(resp) < 1 || resp[0] != sshAgentSignResponse {
		t.Fatalf("response %x", resp)
	}
	blob, rest, ok := takeSSHBytes(resp[1:], sshEd25519SigLen)
	if !ok || len(rest) != 0 {
		t.Fatalf("signature frame %x", resp)
	}
	raw, ok := parseEd25519Sig(blob)
	if !ok {
		t.Fatal("signature blob")
	}
	return raw
}

func splitFrames(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatal("short frame")
		}
		n := binary.BigEndian.Uint32(b[:4])
		if len(b) < 4+int(n) {
			t.Fatal("truncated frame")
		}
		out = append(out, b[4:4+n])
		b = b[4+n:]
	}
	return out
}

func sshCount(t *testing.T, path, result string) int {
	t.Helper()
	n := 0
	for _, ev := range mustAudit(t, path) {
		if ev.Action == actionSSHUserAuth && ev.Result == result {
			n++
		}
	}
	return n
}

func sshFixture(t *testing.T, now time.Time, agent, cred string, g grantRecord) error {
	t.Helper()
	doc := document{
		Credentials: []credential{{
			ID: cred, Label: "key", Type: CredTypeEd25519, Secret: []byte("x"),
			Lifecycle: lifecycle{State: StateActive, CreatedAt: now, UpdatedAt: now},
		}},
		Agents: []agentRecord{{
			ID: agent, Label: "agent", Kind: principalAgent, State: agentStateActive, CreatedAt: now,
		}},
		Grants: []grantRecord{g},
	}
	return validateAgentsAndGrants(doc)
}

type failWriter struct {
	got    bytes.Buffer
	failOn int
	n      int
	secret string
}

func (f *failWriter) Write(p []byte) (int, error) {
	f.n++
	if f.n >= f.failOn {
		return 0, errors.New(f.secret)
	}
	return f.got.Write(p)
}

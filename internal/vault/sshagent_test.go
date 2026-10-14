package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// recordingConn keeps every byte this agent wrote to its peer, so a test can
// scan the actual wire output for key material.
type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	out bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.out.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordingConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.out.Bytes()...)
}

// serveSSHAgent runs one conversation against the official agent client and
// returns the client plus the bytes this side wrote.
func serveSSHAgent(t *testing.T, env *sshEnv) (agent.ExtendedAgent, *recordingConn) {
	t.Helper()
	conversation, err := env.principal.SSHAgent()
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	recorder := &recordingConn{Conn: server}
	done := make(chan struct{})
	go func() {
		conversation.Serve(recorder)
		close(done)
	}()
	t.Cleanup(func() {
		client.Close()
		server.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop after transport close")
		}
		conversation.Close()
	})
	if err := client.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return agent.NewClient(client), recorder
}

// TestSSHAgentConversation is the socket-facing acceptance path: one agent
// principal, the official SSH agent client, a host binding, the granted
// identity, one verified signature, and a refusal for everything else.
func TestSSHAgentConversation(t *testing.T) {
	logs := &bytes.Buffer{}
	env := newSSHEnvLog(t, logs)
	peer, recorder := serveSSHAgent(t, env)
	sessionID := env.sessionID(32)
	preimage := env.preimage(sessionID, env.user, env.userBlob, env.hostBlob)
	sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(env.userPub))
	if err != nil {
		t.Fatal(err)
	}

	// An unbound conversation discloses no identity and signs nothing: the
	// ssh-agent protocol never carries the host key, so without a verified
	// session-bind there is no destination to authorize against.
	if keys, err := peer.List(); err != nil || len(keys) != 0 {
		t.Fatalf("unbound list %+v %v", keys, err)
	}
	if _, err := peer.Sign(sshPub, preimage); err == nil {
		t.Fatal("signed without a session binding")
	}

	// A binding by a key that is not the pinned host key is refused, and
	// leaves the conversation unbound.
	otherHostPub, otherHostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherBind := appendSSHString(nil, marshalEd25519Pub(otherHostPub))
	otherBind = appendSSHString(otherBind, sessionID)
	otherBind = appendSSHString(otherBind, env.hostSig(otherHostPriv, sessionID))
	if _, err := peer.Extension(sshExtSessionBind, append(otherBind, 0)); err == nil {
		t.Fatal("bound to a host key the grant does not pin")
	}
	if keys, err := peer.List(); err != nil || len(keys) != 0 {
		t.Fatalf("list after a refused binding %+v %v", keys, err)
	}

	if _, err := peer.Extension(sshExtSessionBind, env.bindContents(sessionID, false)); err != nil {
		t.Fatal(err)
	}
	keys, err := peer.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "" || !bytes.Equal(keys[0].Blob, env.userBlob) {
		t.Fatalf("list %+v %v", keys, err)
	}
	signature, err := peer.Sign(sshPub, preimage)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ssh.ParsePublicKey(env.userBlob)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(preimage, signature); err != nil {
		t.Fatal(err)
	}

	// Scope: the username and the host key in the preimage are the grant's,
	// and the data must be a host-bound userauth request.
	refused := map[string][]byte{
		"another username":   userauthPreimage(sessionID, "root", env.userBlob, env.hostBlob),
		"another host key":   userauthPreimage(sessionID, env.user, env.userBlob, marshalEd25519Pub(otherHostPub)),
		"another session":    userauthPreimage(env.sessionID(32), env.user, env.userBlob, env.hostBlob),
		"ordinary publickey": env.methodPreimage(sessionID, "publickey"),
		"not userauth data":  []byte("sign this arbitrary payload for me"),
	}
	for name, data := range refused {
		if _, err := peer.Sign(sshPub, data); err == nil {
			t.Fatalf("signed %s", name)
		}
	}

	// Key management, locking and unknown extensions are not served at all.
	sentinelSeed := bytes.Repeat([]byte{0xa7}, ed25519.SeedSize)
	sentinel := ed25519.NewKeyFromSeed(sentinelSeed)
	if err := peer.Add(agent.AddedKey{PrivateKey: &sentinel, Comment: "intruder"}); err == nil {
		t.Fatal("added an identity")
	}
	if err := peer.Remove(sshPub); err == nil {
		t.Fatal("removed an identity")
	}
	if err := peer.RemoveAll(); err == nil {
		t.Fatal("removed all identities")
	}
	if err := peer.Lock([]byte("passphrase")); err == nil {
		t.Fatal("locked the agent")
	}
	if err := peer.Unlock([]byte("passphrase")); err == nil {
		t.Fatal("unlocked the agent")
	}
	if _, err := peer.Extension("query", nil); err == nil {
		t.Fatal("answered an unknown extension")
	}
	if keys, err := peer.List(); err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Blob, env.userBlob) {
		t.Fatalf("list after refusals %+v %v", keys, err)
	}

	// Revocation stops the next signature on an already bound conversation.
	if err := env.session.RevokeGrant(env.grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Sign(sshPub, preimage); err == nil {
		t.Fatal("signed with a revoked grant")
	}
	if keys, err := peer.List(); err != nil || len(keys) != 0 {
		t.Fatalf("revoked grant still listed an identity %+v %v", keys, err)
	}

	if sshCount(t, env.path, resultCompleted) != 1 {
		t.Fatal("exactly one signature release should be recorded")
	}
	if sshCount(t, env.path, resultDenied) < len(refused) {
		t.Fatal("every refused signing attempt should be audited")
	}
	if sshCount(t, env.path, resultDeniedRevoked) < 1 {
		t.Fatal("the revoked attempt should be audited")
	}
	env.assertClean(t, sentinelSeed, sessionID, signature.Blob, logs.Bytes())
	// The wire carries the signature and the granted public key by design.
	// It must never carry private key material, including the key offered on
	// the add frame this codec refuses without parsing.
	assertNoSecrets(t, recorder.written(), [][]byte{
		env.der, env.userPriv.Seed(), append([]byte(nil), env.userPriv...),
		env.hostPriv.Seed(), sentinelSeed, env.pass,
	})
}

// TestSSHAgentGrantsStaySeparate gives one principal two SSH grants with
// different users, keys and pinned hosts. A conversation bound to one host
// discloses and signs for that grant only.
func TestSSHAgentGrantsStaySeparate(t *testing.T) {
	env := newSSHEnv(t)
	secondPub, secondPriv := mustEd25519(t)
	der, err := x509.MarshalPKCS8PrivateKey(secondPriv)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := env.session.Put("ssh-user-2", CredTypeEd25519, der, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secondHostPub, secondHostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondUser := "user-" + randHex(t, 12)
	secondHostBlob := marshalEd25519Pub(secondHostPub)
	secondBlob := marshalEd25519Pub(secondPub)
	if _, err := env.session.IssueGrant(GrantSpec{
		AgentID: env.agent.ID, CredentialID: cred.ID, Operations: []string{OpSSHUserAuth},
		Resource: "label-" + randHex(t, 12), ExpiresAt: time.Now().Add(time.Hour).UTC(),
		SSHUsername: secondUser, SSHHostKey: secondHostBlob,
	}); err != nil {
		t.Fatal(err)
	}

	peer, _ := serveSSHAgent(t, env)
	sessionID := env.sessionID(32)
	if _, err := peer.Extension(sshExtSessionBind, env.bindContents(sessionID, false)); err != nil {
		t.Fatal(err)
	}
	keys, err := peer.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Blob, env.userBlob) {
		t.Fatalf("a binding for one host disclosed %+v %v", keys, err)
	}
	secondSSHPub, err := ssh.NewPublicKey(ed25519.PublicKey(secondPub))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Sign(secondSSHPub, userauthPreimage(sessionID, secondUser, secondBlob, secondHostBlob)); err == nil {
		t.Fatal("signed for a grant whose host was never proved")
	}

	// A fresh conversation bound to the other host serves the other grant.
	second, _ := serveSSHAgent(t, env)
	bind := appendSSHString(nil, secondHostBlob)
	bind = appendSSHString(bind, sessionID)
	bind = appendSSHString(bind, env.hostSig(secondHostPriv, sessionID))
	if _, err := second.Extension(sshExtSessionBind, append(bind, 0)); err != nil {
		t.Fatal(err)
	}
	keys, err = second.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Blob, secondBlob) {
		t.Fatalf("second binding disclosed %+v %v", keys, err)
	}
	signature, err := second.Sign(secondSSHPub, userauthPreimage(sessionID, secondUser, secondBlob, secondHostBlob))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(secondPub, userauthPreimage(sessionID, secondUser, secondBlob, secondHostBlob), signature.Blob) {
		t.Fatal("second grant signature did not verify")
	}
	if _, err := second.Sign(secondSSHPub, userauthPreimage(sessionID, env.user, secondBlob, secondHostBlob)); err == nil {
		t.Fatal("signed the other grant's username with this grant's key")
	}
	if hex.EncodeToString(secondPub) == env.grant.KeyID {
		t.Fatal("the two grants should not share a key")
	}
}

// TestSSHAgentSignWithoutStreamIsAudited covers the conversation that owns no
// stream, because the principal holds no ssh_userauth grant or because its
// only grant is revoked. The sign request is still an attempted credential
// operation and owes exactly one denial row (invariant 4), with no signature.
// Listing identities is not an attempt and is not recorded.
func TestSSHAgentSignWithoutStreamIsAudited(t *testing.T) {
	env := newSSHEnv(t)
	preimage := env.preimage(env.sessionID(32), env.user, env.userBlob, env.hostBlob)
	signOnce := func(t *testing.T, principal *AgentPrincipal) {
		t.Helper()
		conversation, err := principal.SSHAgent()
		if err != nil {
			t.Fatal(err)
		}
		defer conversation.Close()
		before := len(mustAudit(t, env.path))
		resp, err := conversation.dispatch([]byte{sshAgentRequestIdentities})
		if err != nil || !bytes.Equal(resp, sshEmptyIdentities()) {
			t.Fatalf("list %x %v", resp, err)
		}
		if n := len(mustAudit(t, env.path)); n != before {
			t.Fatalf("listing identities recorded %d rows", n-before)
		}
		resp, err = conversation.dispatch(env.signBody(env.userBlob, preimage, 0))
		if err != nil || !bytes.Equal(resp, []byte{sshAgentFailure}) {
			t.Fatalf("sign returned %x, %v", resp, err)
		}
		rows := mustAudit(t, env.path)[before:]
		if len(rows) != 1 {
			t.Fatalf("sign attempt recorded %d rows, want 1", len(rows))
		}
		row := rows[0]
		if row.Action != actionSSHUserAuth || row.Operation != OpSSHUserAuth ||
			row.Result != resultDenied || row.AgentID != principal.id ||
			row.GrantID != "" || row.CredID != "" || row.CredType != "" {
			t.Fatalf("unsafe no-grant denial: %+v", row)
		}
	}

	bare, err := env.session.CreateAgent("no-ssh-worker")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := env.session.Agent(bare.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("no grant", func(t *testing.T) { signOnce(t, principal) })

	t.Run("audit failure", func(t *testing.T) {
		conversation, err := principal.SSHAgent()
		if err != nil {
			t.Fatal(err)
		}
		defer conversation.Close()
		before := len(mustAudit(t, env.path))
		env.session.commitFault = func() error { return errors.New("induced audit failure") }
		resp, err := conversation.dispatch(env.signBody(env.userBlob, preimage, 0))
		env.session.commitFault = nil
		if resp != nil || !errors.Is(err, ErrAudit) || len(mustAudit(t, env.path)) != before {
			t.Fatalf("audit failure returned %x, %v", resp, err)
		}
	})

	if err := env.session.RevokeGrant(env.grant.ID); err != nil {
		t.Fatal(err)
	}
	t.Run("revoked grant", func(t *testing.T) { signOnce(t, env.principal) })

	if sshCount(t, env.path, resultCompleted) != 0 {
		t.Fatal("no signature should have been released")
	}
}

// TestSSHAgentWithoutGrantsDisclosesNothing covers an agent principal that
// holds no SSH authority at all.
func TestSSHAgentWithoutGrantsDisclosesNothing(t *testing.T) {
	env := newSSHEnv(t)
	bare, err := env.session.CreateAgent("no-ssh-worker")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := env.session.Agent(bare.ID)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := principal.SSHAgent()
	if err != nil {
		t.Fatal(err)
	}
	defer conversation.Close()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		conversation.Serve(server)
		close(done)
	}()
	defer func() {
		client.Close()
		server.Close()
		<-done
	}()
	peer := agent.NewClient(client)
	if keys, err := peer.List(); err != nil || len(keys) != 0 {
		t.Fatalf("list %+v %v", keys, err)
	}
	sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(env.userPub))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Sign(sshPub, env.preimage(env.sessionID(32), env.user, env.userBlob, env.hostBlob)); err == nil {
		t.Fatal("an agent with no SSH grant signed")
	}
}

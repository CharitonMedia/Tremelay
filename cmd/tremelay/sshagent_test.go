//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

// sshAgentFixture is one unlocked daemon holding one ssh_userauth grant, plus
// the `tremelay ssh-agent` socket an SSH client connects to. The user private
// key exists only inside the vault: this fixture keeps the public half.
type sshAgentFixture struct {
	*daemonFixture
	dir        string
	tokenFile  string
	socket     string
	username   string
	grantID    string
	userPub    ed25519.PublicKey
	userBlob   []byte
	hostSigner ssh.Signer
	hostKey    ed25519.PrivateKey
	hostBlob   []byte
	agentOut   *daemonOutput
	agentErr   *daemonOutput
	agentExit  chan int
	agentOnce  sync.Once
	agentCode  int
	stopAgent  context.CancelFunc
}

// waitAgent joins the ssh-agent process once, so a test and the cleanup can
// both observe it.
func (f *sshAgentFixture) waitAgent(t *testing.T) int {
	t.Helper()
	f.agentOnce.Do(func() {
		select {
		case f.agentCode = <-f.agentExit:
		case <-time.After(15 * time.Second):
			f.agentCode = -1
			t.Error("ssh-agent did not exit")
		}
	})
	return f.agentCode
}

func startSSHAgent(t *testing.T) *sshAgentFixture {
	t.Helper()
	dir := t.TempDir()
	f := &sshAgentFixture{
		daemonFixture: &daemonFixture{
			t:      t,
			path:   filepath.Join(dir, "vault.db"),
			pass:   randHex(t, 16),
			stdout: &daemonOutput{},
			stderr: &daemonOutput{},
			exit:   make(chan int, 1),
		},
		dir:       dir,
		tokenFile: filepath.Join(dir, "ssh.token"),
		socket:    filepath.Join(socketDir(t), "agent.sock"),
		agentOut:  &daemonOutput{},
		agentErr:  &daemonOutput{},
		agentExit: make(chan int, 1),
	}
	f.env = map[string]string{"TREMELAY_PASSPHRASE": f.pass, "XDG_RUNTIME_DIR": socketDir(t)}

	// The username must be this account: the real OpenSSH acceptance test
	// below logs in as the user running the suite.
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	f.username = current.Username

	userPub, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.userPub, f.userBlob = userPub, sshBlob(t, userPub)
	der, err := x509.MarshalPKCS8PrivateKey(userPriv)
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(dir, "ssh-user.der")
	if err := os.WriteFile(secretPath, der, 0o600); err != nil {
		t.Fatal(err)
	}
	vault.Wipe(der)
	vault.Wipe(userPriv)

	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.hostKey, f.hostBlob = hostPriv, sshBlob(t, hostPub)
	if f.hostSigner, err = ssh.NewSignerFromKey(hostPriv); err != nil {
		t.Fatal(err)
	}

	f.cli(t, "vault", "create", "--path", f.path)
	credID := f.cli(t, "credential", "put", "--path", f.path, "--label", "ssh key",
		"--type", "ed25519", "--secret-file", secretPath)
	created := strings.Split(f.cli(t, "agent", "create", "--path", f.path,
		"--label", "ssh worker", "--token-file", f.tokenFile), "\n")
	if len(created) != 2 {
		t.Fatalf("agent create reported %q", created)
	}
	f.agents = []daemonAgent{{id: created[0], resource: "git-push", tokenFile: f.tokenFile}}
	f.grantID = f.cli(t, "grant", "create", "--path", f.path, "--agent", created[0],
		"--credential", credID, "--operation", vault.OpSSHUserAuth, "--resource", "git-push",
		"--ssh-user", f.username, "--ssh-host-key", hex.EncodeToString(f.hostBlob),
		"--expires", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))

	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	f.cancel = cancelDaemon
	go func() {
		f.exit <- serveDaemon(daemonCtx, f.path, time.Hour, envGet(f.env), strings.NewReader(""), f.stdout, f.stderr)
	}()
	t.Cleanup(func() { cancelDaemon(); f.wait(t, 15*time.Second) })
	f.endpoint = awaitLine(t, f.stdout, f.stderr, "daemon endpoint")

	agentCtx, cancelAgent := context.WithCancel(context.Background())
	f.stopAgent = cancelAgent
	go func() {
		f.agentExit <- serveSSHAgentSocket(agentCtx, envGet(f.env), f.tokenFile, f.socket, f.agentOut, f.agentErr)
	}()
	t.Cleanup(func() { cancelAgent(); f.waitAgent(t) })
	if got := awaitLine(t, f.agentOut, f.agentErr, "ssh-agent socket"); got != f.socket {
		t.Fatalf("ssh-agent reported %q, want %q", got, f.socket)
	}
	return f
}

func awaitLine(t *testing.T, out, errs *daemonOutput, what string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if line, ok := strings.CutSuffix(out.String(), "\n"); ok {
			return line
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s was reported: %q", what, errs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sshBlob(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key.Marshal()
}

// connect speaks the SSH agent protocol over the published socket.
func (f *sshAgentFixture) connect(t *testing.T) agent.ExtendedAgent {
	t.Helper()
	conn, err := net.Dial("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return agent.NewClient(conn)
}

// bind presents the pinned host key's signature over a session identifier,
// which is what OpenSSH sends as session-bind@openssh.com.
func (f *sshAgentFixture) bind(t *testing.T, peer agent.ExtendedAgent, sessionID []byte) error {
	t.Helper()
	signature, err := f.hostSigner.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	contents := ssh.Marshal(struct {
		HostKey      []byte
		SessionID    []byte
		Signature    []byte
		IsForwarding bool
	}{f.hostBlob, sessionID, ssh.Marshal(signature), false})
	_, err = peer.Extension("session-bind@openssh.com", contents)
	return err
}

func hostboundPreimage(sessionID []byte, username string, userBlob, hostBlob []byte) []byte {
	return ssh.Marshal(struct {
		SessionID []byte
		Type      byte
		User      string
		Service   string
		Method    string
		Signed    bool
		Algorithm string
		PublicKey []byte
		HostKey   []byte
	}{sessionID, 50, username, "ssh-connection", "publickey-hostbound-v00@openssh.com",
		true, "ssh-ed25519", userBlob, hostBlob})
}

func randSessionID(t *testing.T) []byte {
	t.Helper()
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestSSHAgentSocketServesGrant drives the published socket the way an SSH
// client does: bind to the pinned host, list the granted identity, obtain one
// verifiable host-bound signature, and get refused for anything else.
func TestSSHAgentSocketServesGrant(t *testing.T) {
	f := startSSHAgent(t)
	info, err := os.Lstat(f.socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", info.Mode(), err)
	}

	peer := f.connect(t)
	sessionID := randSessionID(t)
	if keys, err := peer.List(); err != nil || len(keys) != 0 {
		t.Fatalf("unbound list %+v %v", keys, err)
	}
	userKey, err := ssh.NewPublicKey(f.userPub)
	if err != nil {
		t.Fatal(err)
	}
	preimage := hostboundPreimage(sessionID, f.username, f.userBlob, f.hostBlob)
	if _, err := peer.Sign(userKey, preimage); err == nil {
		t.Fatal("the socket signed without a session binding")
	}
	if err := f.bind(t, peer, sessionID); err != nil {
		t.Fatal(err)
	}
	keys, err := peer.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Blob, f.userBlob) {
		t.Fatalf("list %+v %v", keys, err)
	}
	signature, err := peer.Sign(userKey, preimage)
	if err != nil {
		t.Fatal(err)
	}
	if err := userKey.Verify(preimage, signature); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Sign(userKey, hostboundPreimage(sessionID, "root", f.userBlob, f.hostBlob)); err == nil {
		t.Fatal("the socket signed for another username")
	}
	if err := peer.Lock([]byte("x")); err == nil {
		t.Fatal("the socket answered a lock request")
	}

	// A second connection starts unbound: a binding is not shared.
	fresh := f.connect(t)
	if keys, err := fresh.List(); err != nil || len(keys) != 0 {
		t.Fatalf("a new connection inherited a binding %+v %v", keys, err)
	}

	token := f.token(t, f.agents[0])
	observed := f.agentOut.String() + f.agentErr.String() + f.stdout.String() + f.stderr.String()
	if strings.Contains(observed, token) || strings.Contains(observed, f.pass) {
		t.Fatal("agent or daemon output disclosed the token or passphrase")
	}
	if f.agentErr.String() != "" {
		t.Fatalf("the relay wrote a diagnostic during successful use: %q", f.agentErr.String())
	}

	// An SSH client keeps its agent connection for the whole session, so
	// shutdown must close those connections instead of waiting for them.
	f.stopAgent()
	if code := f.waitAgent(t); code != 0 {
		t.Fatalf("ssh-agent exited %d with clients connected: %q", code, f.agentErr.String())
	}
	f.assertSigned(t, 1)
}

// auditCounts stops the daemon, reopens the vault, and counts the SSH rows.
func (f *sshAgentFixture) auditCounts(t *testing.T) (completed, denied int) {
	t.Helper()
	f.cancel()
	f.wait(t, 15*time.Second)
	session, err := vault.Unlock(f.path, []byte(f.pass), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Lock()
	rows, err := session.AuditHistory(vault.AuditFilter{Action: vault.OpSSHUserAuth, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		switch row.Result {
		case "completed":
			completed++
		case "allowed":
		default:
			denied++
		}
	}
	if _, err := vault.VerifyAudit(f.path, []byte(f.pass)); err != nil {
		t.Fatalf("audit chain invalid: %v", err)
	}
	return completed, denied
}

// assertSigned requires exactly want released signatures and at least one
// audited refusal.
func (f *sshAgentFixture) assertSigned(t *testing.T, want int) {
	t.Helper()
	completed, denied := f.auditCounts(t)
	if completed != want {
		t.Fatalf("%d signatures released, want %d", completed, want)
	}
	if denied == 0 {
		t.Fatal("refused attempts were not audited")
	}
}

// TestSSHAgentRevokedGrantStopsSigning is the second half of the V1 item 5
// acceptance line: revoking the grant stops the socket from signing.
func TestSSHAgentRevokedGrantStopsSigning(t *testing.T) {
	f := startSSHAgent(t)
	peer := f.connect(t)
	sessionID := randSessionID(t)
	userKey, err := ssh.NewPublicKey(f.userPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.bind(t, peer, sessionID); err != nil {
		t.Fatal(err)
	}
	preimage := hostboundPreimage(sessionID, f.username, f.userBlob, f.hostBlob)
	if _, err := peer.Sign(userKey, preimage); err != nil {
		t.Fatal(err)
	}

	f.cli(t, "grant", "revoke", "--path", f.path, "--id", f.grantID)

	// The daemon adopts that commit and keeps serving (ADR 0024, item 3d), so
	// the refusal has to come from the grant itself rather than from a dead
	// daemon: the socket still answers, lists nothing, and signs nothing.
	after := f.connect(t)
	if keys, err := after.List(); err != nil || len(keys) != 0 {
		t.Fatalf("revoked grant was still listed: %v, %d keys", err, len(keys))
	}
	if err := f.bind(t, after, sessionID); err == nil {
		if _, err := after.Sign(userKey, preimage); err == nil {
			t.Fatal("a revoked grant still signed")
		}
	}
	if f.exited() {
		t.Fatalf("daemon exited on an ordinary revocation: %q", f.stderr.String())
	}
	if _, err := vault.VerifyAudit(f.path, []byte(f.pass)); err != nil {
		t.Fatalf("audit chain invalid: %v", err)
	}
}

// TestSSHAgentEndpointCustody covers the refusals that protect the socket and
// the token file before any protocol byte is read.
func TestSSHAgentEndpointCustody(t *testing.T) {
	f := startSSHAgent(t)
	out, errs := &daemonOutput{}, &daemonOutput{}

	// A live endpoint is never replaced.
	if code := serveSSHAgentSocket(context.Background(), envGet(f.env), f.tokenFile, f.socket, out, errs); code != 1 ||
		!strings.Contains(errs.String(), errDaemonRunning.Error()) {
		t.Fatalf("second agent on a live socket exited %d: %q", code, errs.String())
	}

	// A directory any other user can enter is refused.
	open := filepath.Join(socketDir(t), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	errs = &daemonOutput{}
	if code := serveSSHAgentSocket(context.Background(), envGet(f.env), f.tokenFile, filepath.Join(open, "a.sock"), out, errs); code != 1 ||
		!strings.Contains(errs.String(), errDaemonEndpoint.Error()) {
		t.Fatalf("agent in a group-readable directory exited %d: %q", code, errs.String())
	}

	// A token file anyone can read is refused.
	loose := filepath.Join(f.dir, "loose.token")
	raw, err := os.ReadFile(f.tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loose, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	errs = &daemonOutput{}
	if code := serveSSHAgentSocket(context.Background(), envGet(f.env), loose, filepath.Join(socketDir(t), "b.sock"), out, errs); code != 1 ||
		!strings.Contains(errs.String(), errAgentToken.Error()) {
		t.Fatalf("agent with a world-readable token exited %d: %q", code, errs.String())
	}

	// With no daemon holding the vault there is nothing to serve.
	f.cancel()
	f.wait(t, 15*time.Second)
	errs = &daemonOutput{}
	if code := serveSSHAgentSocket(context.Background(), envGet(f.env), f.tokenFile, filepath.Join(socketDir(t), "c.sock"), out, errs); code != 1 ||
		!strings.Contains(errs.String(), errDaemonReach.Error()) {
		t.Fatalf("agent without a daemon exited %d: %q", code, errs.String())
	}
}

//go:build linux || darwin || windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

type daemonOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *daemonOutput) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(b)
}

func (w *daemonOutput) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// daemonAgent is one registered agent and the token file it authenticates with.
type daemonAgent struct {
	id, resource, tokenFile string
}

type daemonFixture struct {
	t              *testing.T
	env            map[string]string
	path, pass     string
	credID         string
	agents         []daemonAgent
	endpoint       string
	stdout, stderr *daemonOutput
	exit           chan int
	once           sync.Once
	code           int
	cancel         context.CancelFunc
}

// wait joins the daemon once, so a test and the cleanup can both observe it.
func (f *daemonFixture) wait(t *testing.T, timeout time.Duration) int {
	t.Helper()
	f.once.Do(func() {
		select {
		case f.code = <-f.exit:
		case <-time.After(timeout):
			f.code = -1
			t.Error("daemon did not exit")
		}
	})
	return f.code
}

// exited reports whether the daemon has already stopped. A test that requires
// the daemon to keep serving asserts this rather than waiting for a timeout.
func (f *daemonFixture) exited() bool {
	select {
	case code := <-f.exit:
		f.once.Do(func() { f.code = code })
		return true
	default:
		return false
	}
}

// startDaemon builds a synthetic vault through the human CLI, then unlocks it
// once in the daemon. No prompt, helper, or display is involved afterwards.
func startDaemon(t *testing.T, idle time.Duration) *daemonFixture {
	t.Helper()
	dir := t.TempDir()
	f := &daemonFixture{
		t:      t,
		path:   filepath.Join(dir, "vault.db"),
		pass:   randHex(t, 16),
		stdout: &daemonOutput{},
		stderr: &daemonOutput{},
		exit:   make(chan int, 1),
	}
	// daemonTestEnv gives each test its own endpoint, exactly as the platform
	// makes one available to a user running more than one daemon.
	f.env = daemonTestEnv(t)
	f.env["TREMELAY_PASSPHRASE"] = f.pass

	seed := randBytes(t, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	vault.Wipe(seed)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	vault.Wipe(key)
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(dir, "signing.der")
	if err := os.WriteFile(secretPath, der, 0o600); err != nil {
		t.Fatal(err)
	}
	vault.Wipe(der)

	f.cli(t, "vault", "create", "--path", f.path)
	credID := f.cli(t, "credential", "put", "--path", f.path, "--label", "daemon key", "--type", "ed25519", "--secret-file", secretPath)
	f.credID = credID
	// Two agents share one credential through separate grants, so a call can
	// be checked for the resource it holds and for the one it must not see.
	for i := range 2 {
		a := daemonAgent{
			resource:  fmt.Sprintf("synthetic-daemon-%d-%s", i, randHex(t, 6)),
			tokenFile: filepath.Join(dir, fmt.Sprintf("agent-%d.token", i)),
		}
		created := strings.Split(f.cli(t, "agent", "create", "--path", f.path,
			"--label", fmt.Sprintf("daemon worker %d", i), "--token-file", a.tokenFile), "\n")
		if len(created) != 2 || created[1] != a.tokenFile {
			t.Fatalf("agent create did not report exactly the agent id and token path: %q", created)
		}
		a.id = created[0]
		f.cli(t, "grant", "create", "--path", f.path, "--agent", a.id, "--credential", credID,
			"--operation", vault.OpLocalArtifactAttest, "--resource", a.resource,
			"--expires", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		f.agents = append(f.agents, a)
	}

	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	go func() {
		f.exit <- serveDaemon(ctx, f.path, idle, envGet(f.env), strings.NewReader(""), f.stdout, f.stderr)
	}()
	t.Cleanup(func() { cancel(); f.wait(t, 15*time.Second) })
	deadline := time.Now().Add(20 * time.Second)
	for f.endpoint == "" {
		if line, ok := strings.CutSuffix(f.stdout.String(), "\n"); ok {
			f.endpoint = line
		} else if time.Now().After(deadline) {
			t.Fatalf("daemon did not report an endpoint: %q", f.stderr.String())
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return f
}

// cli runs one human control-plane command and returns its trimmed stdout.
func (f *daemonFixture) cli(t *testing.T, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run(args, envGet(f.env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("%v exited %d: %s", args, code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), f.pass) {
		t.Fatalf("%v disclosed the passphrase", args)
	}
	return strings.TrimSpace(stdout.String())
}

// cliRetryStale runs a control-plane command that may lose its compare-and-swap
// to a daemon committing audit rows at the same moment. Nothing of a lost
// attempt is written, and re-running it is what an operator does by hand.
func (f *daemonFixture) cliRetryStale(t *testing.T, args ...string) string {
	t.Helper()
	for range 50 {
		var stdout, stderr bytes.Buffer
		code := run(args, envGet(f.env), strings.NewReader(""), &stdout, &stderr)
		if code == 0 {
			return strings.TrimSpace(stdout.String())
		}
		if !strings.Contains(stderr.String(), vault.ErrStale.Error()) {
			t.Fatalf("%v exited %d: %s", args, code, stderr.String())
		}
	}
	t.Fatalf("%v never won its race with the daemon", args)
	return ""
}

func (f *daemonFixture) token(t *testing.T, a daemonAgent) string {
	t.Helper()
	raw, err := os.ReadFile(a.tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// agentRelay drives `tremelay mcp --daemon` the way an MCP client does.
type agentRelay struct {
	in     *io.PipeWriter
	out    *bufio.Reader
	stderr *daemonOutput
	exit   chan int
}

func (f *daemonFixture) relay(t *testing.T, tokenFile string) *agentRelay {
	t.Helper()
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	r := &agentRelay{in: stdinW, out: bufio.NewReader(stdoutR), stderr: &daemonOutput{}, exit: make(chan int, 1)}
	go func() {
		code := run([]string{"mcp", "--daemon", "--token-file", tokenFile}, envGet(f.env), stdinR, stdoutW, r.stderr)
		stdoutW.Close()
		stdinR.Close()
		r.exit <- code
	}()
	t.Cleanup(func() { stdinW.Close(); stdoutR.Close() })
	return r
}

func (r *agentRelay) send(t *testing.T, frame string) {
	t.Helper()
	if _, err := io.WriteString(r.in, frame+"\n"); err != nil {
		t.Fatalf("send %s: %v", frame, err)
	}
}

func (r *agentRelay) receive(t *testing.T) string {
	t.Helper()
	line := make(chan string, 1)
	fail := make(chan error, 1)
	go func() {
		got, err := r.out.ReadString('\n')
		if err != nil {
			fail <- err
			return
		}
		line <- got
	}()
	select {
	case got := <-line:
		return got
	case err := <-fail:
		t.Fatalf("no MCP response: %v; relay said %q", err, r.stderr.String())
	case <-time.After(15 * time.Second):
		t.Fatalf("MCP response timed out; relay said %q", r.stderr.String())
	}
	return ""
}

func (r *agentRelay) finish(t *testing.T) int {
	t.Helper()
	r.in.Close()
	select {
	case code := <-r.exit:
		return code
	case <-time.After(15 * time.Second):
		t.Fatal("relay did not exit")
	}
	return -1
}

const (
	initializeFrame  = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"synthetic-daemon-client","version":"1"}}}`
	initializedFrame = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
)

// daemonCapEntry is the part of one list_capabilities entry these tests read.
type daemonCapEntry struct {
	Handle   string `json:"handle"`
	Resource string `json:"resource"`
	Status   string `json:"status"`
}

// capabilityEntries parses the entries out of a list_capabilities response.
func capabilityEntries(t *testing.T, frame string) []daemonCapEntry {
	t.Helper()
	var resp struct {
		Result struct {
			Structured struct {
				Entries []daemonCapEntry `json:"entries"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(frame), &resp); err != nil {
		t.Fatalf("capability frame %q: %v", frame, err)
	}
	return resp.Result.Structured.Entries
}

// callList asks an already-initialized relay to list capabilities again, which
// is how a long-lived agent connection observes a control-plane change.
func (r *agentRelay) callList(t *testing.T, id int) string {
	t.Helper()
	r.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"list_capabilities","arguments":{}}}`, id))
	listed := r.receive(t)
	if !strings.Contains(listed, fmt.Sprintf(`"id":%d`, id)) {
		t.Fatalf("capability call response %q", listed)
	}
	return listed
}

// attest invokes one local_artifact_attest capability and returns the raw
// response frame together with whether a signature was released.
func (r *agentRelay) attest(t *testing.T, id int, handle string) (string, bool) {
	t.Helper()
	payload := base64.StdEncoding.EncodeToString([]byte("item-3d-reload-probe"))
	r.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"invoke_capability","arguments":{"handle":%q,"payload":%q}}}`, id, handle, payload))
	got := r.receive(t)
	if !strings.Contains(got, fmt.Sprintf(`"id":%d`, id)) {
		t.Fatalf("invoke response %q", got)
	}
	return got, strings.Contains(got, `"signature"`)
}

// TestDaemonUnlockedAgentCall is the ADR 0024 acceptance path: one unlock, then
// an agent capability call with no prompt, then lock-and-exit, after which the
// next call fails closed. A wrong token is refused without stopping service.
func TestDaemonUnlockedAgentCall(t *testing.T) {
	f := startDaemon(t, time.Hour)
	worker := f.agents[0]
	token := f.token(t, worker)

	wrongFile := filepath.Join(t.TempDir(), "wrong.token")
	if err := writeAgentToken(wrongFile, randBytes(t, vault.AgentTokenLen)); err != nil {
		t.Fatal(err)
	}
	wrong := f.relay(t, wrongFile)
	if code := wrong.finish(t); code != 1 || !strings.Contains(wrong.stderr.String(), errDaemonRefused.Error()) {
		t.Fatalf("wrong token exited %d: %q", code, wrong.stderr.String())
	}

	agent := f.relay(t, worker.tokenFile)
	listed := agent.capabilities(t)
	if !strings.Contains(listed, worker.resource) {
		t.Fatalf("capability call response %q", listed)
	}
	if strings.Contains(listed, token) || strings.Contains(listed, f.pass) {
		t.Fatal("MCP output disclosed the agent token or passphrase")
	}
	if agent.stderr.String() != "" {
		t.Fatalf("relay wrote a diagnostic during a successful call: %q", agent.stderr.String())
	}

	var lockOut, lockErr bytes.Buffer
	if code := run([]string{"lock"}, envGet(f.env), strings.NewReader(""), &lockOut, &lockErr); code != 0 {
		t.Fatalf("lock exited %d: %q", code, lockErr.String())
	}
	if strings.TrimSpace(lockOut.String()) != "locked" {
		t.Fatalf("lock reported %q", lockOut.String())
	}
	if code := f.wait(t, 15*time.Second); code != 0 {
		t.Fatalf("locked daemon exited %d: %q", code, f.stderr.String())
	}
	// The in-flight session ends without a response; the next call fails closed.
	agent.finish(t)
	if conn, err := daemonDial(envGet(f.env)); err == nil {
		conn.Close()
		t.Fatal("locked daemon left its endpoint reachable")
	}
	after := f.relay(t, worker.tokenFile)
	if code := after.finish(t); code != 1 || !strings.Contains(after.stderr.String(), errDaemonReach.Error()) {
		t.Fatalf("call after lock exited %d: %q", code, after.stderr.String())
	}

	f.assertAudit(t, map[string]int{worker.id: 1}, 1)
	if strings.Contains(f.stdout.String()+f.stderr.String(), token) ||
		strings.Contains(f.stdout.String()+f.stderr.String(), f.pass) {
		t.Fatal("daemon output disclosed the agent token or passphrase")
	}
}

// assertAudit reopens the locked vault and checks the daemon_auth rows:
// accepted attempts per agent id, and unattributed refusals.
func (f *daemonFixture) assertAudit(t *testing.T, allowed map[string]int, denied int) {
	t.Helper()
	session, err := vault.Unlock(f.path, []byte(f.pass), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Lock()
	rows, err := session.AuditHistory(vault.AuditFilter{Action: "daemon_auth", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	gotAllowed, gotDenied := map[string]int{}, 0
	for _, row := range rows {
		switch row.Result {
		case "allowed":
			gotAllowed[row.AgentID]++
		case "denied":
			gotDenied++
			if row.AgentID != "" {
				t.Fatal("unknown token was attributed to an agent")
			}
		default:
			t.Fatalf("unexpected daemon_auth result %q", row.Result)
		}
	}
	if gotDenied != denied || len(gotAllowed) != len(allowed) {
		t.Fatalf("daemon_auth rows: %v allowed, %d denied", gotAllowed, gotDenied)
	}
	for id, count := range allowed {
		if gotAllowed[id] != count {
			t.Fatalf("agent %s has %d accepted attempts, want %d", id, gotAllowed[id], count)
		}
	}
	if _, err := vault.VerifyAudit(f.path, []byte(f.pass)); err != nil {
		t.Fatalf("audit chain invalid: %v", err)
	}
}

// capabilities runs the initialize handshake and one capability call, and
// returns the raw tools/call response frame.
func (r *agentRelay) capabilities(t *testing.T) string {
	t.Helper()
	r.send(t, initializeFrame)
	if got := r.receive(t); !strings.Contains(got, `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("initialize response %q", got)
	}
	r.send(t, initializedFrame)
	return r.callList(t, 2)
}

// TestDaemonConcurrentAgentsStayIsolated holds two agent sessions open on the
// one unlocked Session at the same time. Each principal comes only from its
// own token, so neither call can see the other agent's grant.
func TestDaemonConcurrentAgentsStayIsolated(t *testing.T) {
	f := startDaemon(t, time.Hour)
	relays := make([]*agentRelay, len(f.agents))
	for i, a := range f.agents {
		relays[i] = f.relay(t, a.tokenFile)
	}
	listed := make([]string, len(relays))
	var wg sync.WaitGroup
	for i, r := range relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			listed[i] = r.capabilities(t)
		}()
	}
	wg.Wait()
	expected := map[string]int{}
	for i, a := range f.agents {
		other := f.agents[(i+1)%len(f.agents)]
		if !strings.Contains(listed[i], a.resource) {
			t.Fatalf("agent %d did not receive its own grant: %q", i, listed[i])
		}
		if strings.Contains(listed[i], other.resource) {
			t.Fatalf("agent %d received another agent's grant: %q", i, listed[i])
		}
		expected[a.id] = 1
	}
	for _, r := range relays {
		r.finish(t)
	}
	f.cancel()
	f.wait(t, 15*time.Second)
	f.assertAudit(t, expected, 0)
}

// TestDaemonIdleTimeoutFailsClosed proves the idle deadline zeroises the
// session and that a later agent call cannot reach it.
func TestDaemonIdleTimeoutFailsClosed(t *testing.T) {
	f := startDaemon(t, 150*time.Millisecond)
	if code := f.wait(t, 15*time.Second); code != 0 {
		t.Fatalf("idle daemon exited %d: %q", code, f.stderr.String())
	}
	relay := f.relay(t, f.agents[0].tokenFile)
	if code := relay.finish(t); code != 1 || !strings.Contains(relay.stderr.String(), errDaemonReach.Error()) {
		t.Fatalf("call after idle timeout exited %d: %q", code, relay.stderr.String())
	}
	f.assertAudit(t, nil, 0)
}

// grantIDFor returns the grant id the human control plane reports for one of
// this agent's resources.
func (f *daemonFixture) grantIDFor(t *testing.T, agentID, resource string) string {
	t.Helper()
	listed := f.cli(t, "capability", "list", "--path", f.path, "--agent", agentID)
	for _, line := range strings.Split(listed, "\n") {
		var entry struct {
			GrantID  string `json:"grant_id"`
			Resource string `json:"resource"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("capability line %q: %v", line, err)
		}
		if entry.Resource == resource {
			return entry.GrantID
		}
	}
	t.Fatalf("no grant for %q in %q", resource, listed)
	return ""
}

// TestDaemonReloadsOnControlPlaneChange is the V1.md item 3d acceptance path.
// With the daemon unlocked, `grant create` makes a capability usable and
// `grant revoke` makes it refused, on the agent connection that is already
// open, with no restart and no second passphrase entry.
func TestDaemonReloadsOnControlPlaneChange(t *testing.T) {
	f := startDaemon(t, time.Hour)
	worker := f.agents[0]
	agent := f.relay(t, worker.tokenFile)
	before := capabilityEntries(t, agent.capabilities(t))
	if len(before) != 1 || before[0].Resource != worker.resource || before[0].Status != vault.GrantActive {
		t.Fatalf("capabilities before the control-plane change: %+v", before)
	}

	// A grant issued while the daemon serves is usable on the next call.
	added := "synthetic-reload-" + randHex(t, 6)
	f.cli(t, "grant", "create", "--path", f.path, "--agent", worker.id, "--credential", f.credID,
		"--operation", vault.OpLocalArtifactAttest, "--resource", added,
		"--expires", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	grown := capabilityEntries(t, agent.callList(t, 3))
	addedHandle := ""
	for _, entry := range grown {
		if entry.Resource == added && entry.Status == vault.GrantActive {
			addedHandle = entry.Handle
		}
	}
	if len(grown) != 2 || addedHandle == "" {
		t.Fatalf("grant created while the daemon served is not usable: %+v", grown)
	}
	if frame, signed := agent.attest(t, 4, addedHandle); !signed {
		t.Fatalf("new grant did not release a signature: %q", frame)
	}

	// Revoking the original grant refuses it on the next call, through the
	// handle the agent already holds.
	f.cli(t, "grant", "revoke", "--path", f.path, "--id", f.grantIDFor(t, worker.id, worker.resource))
	frame, signed := agent.attest(t, 5, before[0].Handle)
	if signed || !strings.Contains(frame, vault.GrantRevoked) {
		t.Fatalf("revoked grant was not refused: %q", frame)
	}
	// The other grant is untouched, so the refusal came from the revocation
	// and not from a daemon that stopped serving.
	if frame, signed := agent.attest(t, 6, addedHandle); !signed {
		t.Fatalf("surviving grant stopped working: %q", frame)
	}
	if f.exited() {
		t.Fatalf("daemon exited on an ordinary control-plane change: %q", f.stderr.String())
	}
	if strings.Contains(f.stderr.String(), errDaemonTerminal.Error()) {
		t.Fatalf("daemon reported a terminal session: %q", f.stderr.String())
	}

	agent.finish(t)
	f.cancel()
	f.wait(t, 15*time.Second)
	if _, err := vault.VerifyAudit(f.path, []byte(f.pass)); err != nil {
		t.Fatalf("audit chain invalid: %v", err)
	}
}

// TestDaemonLocksOnUnverifiableVault is the fail-closed half of item 3d. A
// reload that cannot be verified is never adopted: the daemon zeroises and
// exits rather than serve a document, a chain, or an audit head it cannot
// authenticate with the key it holds.
func TestDaemonLocksOnUnverifiableVault(t *testing.T) {
	for name, tamper := range map[string]func(*testing.T, *daemonFixture){
		// Each case first advances the durable sequence through an ordinary
		// command, which is what brings the daemon back to the file at all.
		"tampered document": func(t *testing.T, f *daemonFixture) {
			f.cli(t, "agent", "create", "--path", f.path, "--label", "tamper probe")
			f.execSQL(t, `UPDATE vault SET encrypted_document = randomblob(length(encrypted_document))`)
		},
		"broken chain": func(t *testing.T, f *daemonFixture) {
			f.cli(t, "agent", "create", "--path", f.path, "--label", "tamper probe")
			f.execSQL(t, `UPDATE audit SET result = 'denied' WHERE seq = 2`)
		},
		"rolled back audit head": func(t *testing.T, f *daemonFixture) {
			f.execSQL(t, `UPDATE vault SET audit_seq = audit_seq - 1`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := startDaemon(t, time.Hour)
			tamper(t, f)
			// Any agent call reaches the vault, so authentication is enough.
			refused := f.relay(t, f.agents[0].tokenFile)
			if code := refused.finish(t); code != 1 {
				t.Fatalf("call against an unverifiable vault exited %d: %q", code, refused.stderr.String())
			}
			if code := f.wait(t, 15*time.Second); code != 0 {
				t.Fatalf("daemon exited %d: %q", code, f.stderr.String())
			}
			if !strings.Contains(f.stderr.String(), errDaemonTerminal.Error()) {
				t.Fatalf("missing fail-closed diagnostic: %q", f.stderr.String())
			}
			if _, err := os.Lstat(f.endpoint); err == nil {
				t.Fatal("locked daemon left its endpoint in place")
			}
		})
	}
}

// execSQL edits the vault file directly, which is the only way to produce the
// tampering an attacker with filesystem access would.
func (f *daemonFixture) execSQL(t *testing.T, stmt string) {
	t.Helper()
	db, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatal(err)
	}
}

// TestDaemonConcurrentCallsDuringReload keeps both agents calling the daemon
// across a run of control-plane commits, so each reload swap is taken by
// several connections at once. Under -race this is the check that the session
// mutex keeps every one of them off half-swapped state.
func TestDaemonConcurrentCallsDuringReload(t *testing.T) {
	f := startDaemon(t, time.Hour)
	relays := make([]*agentRelay, len(f.agents))
	for i, a := range f.agents {
		relays[i] = f.relay(t, a.tokenFile)
		relays[i].capabilities(t)
	}
	stop := make(chan struct{})
	var callers sync.WaitGroup
	// A caller goroutine must be joined before this test can fail, or its
	// next frame goes to a closed pipe and panics the run.
	halt := sync.OnceFunc(func() { close(stop); callers.Wait() })
	defer halt()
	// Every agent call commits an audit row of its own, and a commit is
	// optimistic, so a human command racing a continuous stream of them can
	// lose indefinitely; see the ceiling noted on updateVault. The gate gives
	// the control plane the writes that are in flight, not the agents that
	// follow it: callers resume together and reach the reload at once.
	var gate sync.RWMutex
	for i, r := range relays {
		callers.Add(1)
		go func() {
			defer callers.Done()
			for id := 100; ; id++ {
				select {
				case <-stop:
					return
				default:
				}
				gate.RLock()
				// Each agent must keep seeing its own grant and only its own,
				// whichever side of a reload the call lands on.
				listed := r.callList(t, id)
				gate.RUnlock()
				if !strings.Contains(listed, f.agents[i].resource) ||
					strings.Contains(listed, f.agents[(i+1)%len(f.agents)].resource) {
					t.Errorf("agent %d saw the wrong grants during a reload: %q", i, listed)
					return
				}
			}
		}()
	}
	for range 3 {
		gate.Lock()
		f.cliRetryStale(t, "grant", "create", "--path", f.path, "--agent", f.agents[0].id, "--credential", f.credID,
			"--operation", vault.OpLocalArtifactAttest, "--resource", "churn-"+randHex(t, 6),
			"--expires", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		gate.Unlock()
		// Let the callers back in long enough to cross the reload together.
		time.Sleep(50 * time.Millisecond)
	}
	halt()
	if f.exited() {
		t.Fatalf("daemon exited while serving concurrent calls: %q", f.stderr.String())
	}
	for _, r := range relays {
		r.finish(t)
	}
	f.cancel()
	f.wait(t, 15*time.Second)
	if _, err := vault.VerifyAudit(f.path, []byte(f.pass)); err != nil {
		t.Fatalf("audit chain invalid: %v", err)
	}
}

func TestAgentTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.token")
	token := randBytes(t, vault.AgentTokenLen)
	if err := writeAgentToken(path, token); err != nil {
		t.Fatal(err)
	}
	if err := userOnlyFile(path); err != nil {
		t.Fatalf("a token file this command wrote is not user-only: %v", err)
	}
	if err := writeAgentToken(path, token); err != errAgentToken {
		t.Fatalf("existing token file was replaced: %v", err)
	}
	got, err := readAgentToken(path)
	if err != nil || !bytes.Equal(got, token) {
		t.Fatalf("token round trip: %v", err)
	}
	for name, content := range map[string]string{
		"empty":        "",
		"short":        hex.EncodeToString(token[:16]),
		"not hex":      strings.Repeat("z", 64),
		"oversized":    hex.EncodeToString(token) + hex.EncodeToString(token),
		"with padding": " " + hex.EncodeToString(token),
	} {
		bad := filepath.Join(dir, "bad-"+strings.ReplaceAll(name, " ", "-"))
		writeUserOnlyFile(t, bad, content)
		if _, err := readAgentToken(bad); err != errAgentToken {
			t.Fatalf("%s token file accepted: %v", name, err)
		}
	}
	if _, err := readAgentToken(dir); err != errAgentToken {
		t.Fatalf("directory accepted as a token file: %v", err)
	}
}

// writeUserOnlyFile puts exact content in a file only this user can read, so
// that a refusal is about the content and not about the permissions.
func writeUserOnlyFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := createUserOnlyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(f, content)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestDaemonHandshakeBounds(t *testing.T) {
	token := randBytes(t, vault.AgentTokenLen)
	encoded := hex.EncodeToString(token)
	for name, line := range map[string]string{
		"empty":            "\n",
		"no magic":         "AUTH " + encoded + "\n",
		"wrong magic":      "TREMELAY/2 AUTH " + encoded + "\n",
		"unknown verb":     daemonHello + "UNLOCK\n",
		"lock with suffix": daemonHello + daemonVerbLock + " now\n",
		"short token":      daemonHello + daemonVerbAuth + encoded[:32] + "\n",
		"not hex":          daemonHello + daemonVerbAuth + strings.Repeat("z", 64) + "\n",
		"no newline":       daemonHello + daemonVerbAuth + encoded,
		"oversized":        daemonHello + daemonVerbAuth + strings.Repeat("a", maxDaemonHello) + "\n",
		"mcp frame":        initializeFrame + "\n",
	} {
		if _, _, err := readDaemonHello(handshakePeer(t, line)); err != errDaemonRefused {
			t.Fatalf("%s handshake accepted: %v", name, err)
		}
	}
	verb, got, err := readDaemonHello(handshakePeer(t, daemonHello+daemonVerbAuth+encoded+"\n"))
	if err != nil || verb != daemonVerbAuth || !bytes.Equal(got, token) {
		t.Fatalf("valid handshake: %v, %q", err, verb)
	}
	if verb, _, err := readDaemonHello(handshakePeer(t, daemonHello+daemonVerbLock+"\n")); err != nil || verb != daemonVerbLock {
		t.Fatalf("lock handshake: %v, %q", err, verb)
	}
}

// handshakePeer returns the daemon side of a connection already holding line.
// The handshake parser is transport-independent, so this needs no endpoint.
func handshakePeer(t *testing.T, line string) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	go func() {
		_, _ = io.WriteString(client, line)
		client.Close()
	}()
	if err := server.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return server
}

func TestDaemonAndLockUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{
		{"daemon"},
		{"daemon", "--vault", "/tmp/x", "--idle-timeout", "0s"},
		{"daemon", "--vault", "/tmp/x", "--idle-timeout", "48h"},
		{"daemon", "--vault", "/tmp/x", "extra"},
		{"lock", "--now"},
		{"mcp", "--daemon"},
		{"mcp", "--token-file", "/tmp/t"},
		{"mcp"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(args, envGet(nil), strings.NewReader(""), &stdout, &stderr); code != 2 {
			t.Fatalf("%v exited %d", args, code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("%v wrote to stdout: %q", args, stdout.String())
		}
	}
}

// assertEndpointRefusesPassphrase checks that a daemon which cannot hold its
// endpoint never reaches the passphrase. The unusable endpoint is whatever
// the platform's env gives it.
func assertEndpointRefusesPassphrase(t *testing.T, env map[string]string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	env["TREMELAY_PASSPHRASE"] = randHex(t, 16)
	if code := run([]string{"daemon", "--vault", filepath.Join(t.TempDir(), "absent.db")}, envGet(env),
		strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("daemon on an unusable endpoint exited %d: %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), errDaemonEndpoint.Error()) {
		t.Fatalf("unexpected endpoint diagnostic: %q", stderr.String())
	}
}

//go:build linux || darwin

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/mcpstdio"
)

// TestMCPSyntheticCredentialFixture is an explicitly selected test-binary host,
// never compiled into tremelay. It exposes the real stdio MCP adapter while a
// test-only transport routes already-authorized requests to a disposable TLS
// service. Production public-IP, TLS and pinentry behavior is not demonstrated
// by this fixture. Tokens and unlock material are never supplied by the client.
func TestMCPSyntheticCredentialFixture(t *testing.T) {
	if os.Getenv("TREMELAY_MCP_SYNTHETIC_FIXTURE") != "1" {
		return
	}
	// Exit explicitly: the Go test harness must not append PASS to MCP stdout.
	if runMCPCredentialFixture() != nil {
		_, _ = fmt.Fprintln(os.Stderr, "synthetic credential fixture failed")
		os.Exit(1)
	}
	os.Exit(0)
}

type credentialFixtureEvidence struct {
	Version                   int                       `json:"version"`
	Fixture                   string                    `json:"fixture"`
	AuditVerified             bool                      `json:"audit_verified"`
	AuditRows                 int                       `json:"audit_rows"`
	AuditHead                 string                    `json:"audit_head"`
	BrokerResults             map[string]map[string]int `json:"broker_results"`
	ProtocolDenials           int                       `json:"protocol_denials"`
	AuthenticatedRequests     int64                     `json:"authenticated_requests"`
	UnauthenticatedSelfChecks int64                     `json:"unauthenticated_self_checks"`
	AllowedBeforeRequest      bool                      `json:"allowed_before_request"`
	UnexpectedRequests        int64                     `json:"unexpected_requests"`
	OwnOutputSecretAbsent     bool                      `json:"own_output_secret_absent"`
	VaultSecretAbsent         bool                      `json:"vault_secret_absent"`
	ObservationsComplete      bool                      `json:"observations_complete"`
	ObservationFiles          int                       `json:"observation_files"`
	ObservedSecretAbsent      bool                      `json:"observed_secret_absent"`
	ServeClean                bool                      `json:"serve_clean"`
	ShutdownReason            string                    `json:"shutdown_reason"`
	ShutdownSignal            string                    `json:"shutdown_signal,omitempty"`
	ShutdownAccepted          bool                      `json:"shutdown_accepted"`
}

func runMCPCredentialFixture() error {
	evidencePath := os.Getenv("TREMELAY_MCP_FIXTURE_EVIDENCE")
	if !filepath.IsAbs(evidencePath) {
		return ErrInvalid
	}
	parent := filepath.Dir(evidencePath)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return ErrInvalid
	}
	if _, err := os.Lstat(evidencePath); !errors.Is(err, os.ErrNotExist) {
		return ErrInvalid
	}
	marker, err := os.OpenFile(evidencePath+".launch.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	markerData, _ := json.Marshal(struct {
		PID int `json:"pid"`
	}{os.Getpid()})
	_, markerWrite := marker.Write(append(markerData, '\n'))
	markerClose := marker.Close()
	if markerWrite != nil {
		return markerWrite
	}
	if markerClose != nil {
		return markerClose
	}
	dir, err := os.MkdirTemp(parent, ".tremelay-credential-fixture-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	fresh := func() ([]byte, error) {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, err
		}
		return []byte(hex.EncodeToString(raw[:])), nil
	}
	secret, err := fresh()
	if err != nil {
		return err
	}
	defer wipe(secret)
	pass, err := fresh()
	if err != nil {
		return err
	}
	defer wipe(pass)
	vaultPath := filepath.Join(dir, "vault.db")
	s, err := Create(vaultPath, pass, nil)
	if err != nil {
		return err
	}
	defer s.Lock()
	cred, err := s.Put("synthetic-only", "api_key", secret, PutOptions{})
	if err != nil {
		return err
	}
	agent, err := s.CreateAgent("synthetic-client")
	if err != nil {
		return err
	}
	const (
		githubHost     = "api.github.com"
		brokerResource = "https://" + githubHost + "/repos/octocat/Hello-World"
		brokerPath     = "/repos/octocat/Hello-World/issues/17"
	)
	// grantForRequest maps the canonical upstream request to the grant that
	// must already be audited as allowed when that request is made.
	grantForRequest := map[string]string{}
	for _, spec := range []struct {
		op, resource, request string
		revoked               bool
	}{
		{OpHTTPRequest, "GET https://protected.example/v1/ping", "GET https://protected.example/v1/ping", false},
		{OpHTTPBroker, brokerResource, "GET https://" + githubHost + brokerPath, false},
		{OpHTTPRequest, "GET https://protected.example/v1/denied", "GET https://protected.example/v1/denied", true},
	} {
		grantSpec := GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{spec.op}, Resource: spec.resource, ExpiresAt: time.Now().Add(time.Hour)}
		if spec.op == OpHTTPBroker {
			grantSpec.HTTPMethods = []string{http.MethodGet}
			grantSpec.HTTPInject = InjectBearer
		}
		g, err := s.IssueGrant(grantSpec)
		if err != nil {
			return err
		}
		grantForRequest[spec.request] = g.ID
		if spec.revoked {
			if err := s.RevokeGrant(g.ID); err != nil {
				return err
			}
		}
	}
	var authenticated, rejected, unexpected atomic.Int64
	// The fixture service echoes every spelling of the credential it was sent,
	// in the body and in an allowlisted response header.
	reflection := strings.Join(secretForms(secret), " ")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), append([]byte("Bearer "), secret...)) != 1 {
			rejected.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || (r.URL.Path != "/v1/ping" && r.URL.Path != brokerPath) || r.URL.RawQuery != "" {
			unexpected.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		authenticated.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", reflection)
		w.Header().Set("Set-Cookie", "session="+reflection)
		_, _ = io.WriteString(w, "state=open echo="+reflection)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = brokerTimeout
	client.CheckRedirect = refuseRedirect
	defer client.CloseIdleConnections()
	// Prove the fixture service really requires the token. Neither check knows
	// or sends the protected credential, and neither is an MCP broker attempt.
	for _, auth := range []string{"", "Bearer synthetic-wrong-credential"} {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/ping", nil)
		if err != nil {
			return err
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			return ErrInvalid
		}
	}
	fixtureURL, err := url.Parse(server.URL)
	if err != nil {
		return err
	}
	s.resolve = func(_ context.Context, host string) ([]net.IP, error) {
		if host != "protected.example" && host != githubHost {
			return nil, ErrDeniedDestination
		}
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	var allowedBefore atomic.Bool
	allowedBefore.Store(true)
	s.httpDo = func(req *http.Request) (*http.Response, error) {
		op := OpHTTPRequest
		if req.URL.Host == githubHost {
			op = OpHTTPBroker
		}
		resource := req.Method + " " + req.URL.String()
		expectedGrant, known := grantForRequest[resource]
		var last auditEvent
		for _, row := range mcpAuditSnapshot(s) {
			if row.Action == actionBroker {
				last = row
			}
		}
		found := known && last.Result == resultAllowed && last.Operation == op && last.AgentID == agent.ID && last.CredID == cred.ID && last.GrantID == expectedGrant
		if !found {
			allowedBefore.Store(false)
			return nil, ErrAudit
		}
		// This is the sole test-only origin replacement. It is unreachable from
		// shipping code or tool arguments and uses the fixture's trusted cert.
		copyReq := req.Clone(req.Context())
		copyReq.URL.Scheme, copyReq.URL.Host = fixtureURL.Scheme, fixtureURL.Host
		copyReq.Host = fixtureURL.Host
		return client.Do(copyReq)
	}
	principal, err := s.Agent(agent.ID)
	if err != nil {
		return err
	}
	cap, err := BindAgentCapability(principal)
	if err != nil {
		return err
	}
	ep, err := BindStdioMCPEndpoint(cap)
	if err != nil {
		return err
	}
	in, ownedOut, err := fixtureStdio()
	if err != nil {
		return err
	}
	defer in.Close()
	defer ownedOut.Close()
	out := &fixtureOutput{WriteCloser: ownedOut}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	type signalState struct {
		name      string
		idle      bool
		auditRows int
	}
	caught := make(chan signalState, 1)
	signalDone := make(chan struct{})
	go func() {
		defer close(signalDone)
		select {
		case sig := <-signals:
			ep.mu.Lock()
			idle := !ep.inCall && ep.active == nil && ep.pending == nil && ep.auditErr == nil
			ep.mu.Unlock()
			n := -1
			if idle {
				n = len(mcpAuditSnapshot(s))
			}
			caught <- signalState{name: sig.String(), idle: idle, auditRows: n}
			cancel()
		case <-ctx.Done():
		}
	}()
	serveErr := ep.Serve(ctx, in, out)
	cancel()
	<-signalDone
	rows := mcpAuditSnapshot(s)
	shutdownReason, shutdownSignal := "eof", ""
	shutdownAccepted := serveErr == nil
	if serveErr != nil {
		shutdownReason = "error"
		if errors.Is(serveErr, context.DeadlineExceeded) {
			shutdownReason = "timeout"
		}
	}
	select {
	case observed := <-caught:
		shutdownSignal = observed.name
		shutdownReason = "signal"
		// Expected host signal cancellation is distinct from clean EOF. Pending
		// work or an extra shutdown denial cannot be relabeled as completed.
		shutdownAccepted = errors.Is(serveErr, context.Canceled) && observed.idle && observed.auditRows == len(rows)
	default:
	}
	verifyErr := verifyChain(rows)
	if verifyErr == nil {
		_, verifyErr = VerifyAudit(vaultPath, pass)
	}
	evidence := credentialFixtureEvidence{Version: 1, Fixture: "synthetic-tls-protected-service", AuditVerified: verifyErr == nil, AuditRows: len(rows), BrokerResults: map[string]map[string]int{}, AuthenticatedRequests: authenticated.Load(), UnauthenticatedSelfChecks: rejected.Load(), UnexpectedRequests: unexpected.Load(), AllowedBeforeRequest: allowedBefore.Load(), ServeClean: serveErr == nil, ShutdownReason: shutdownReason, ShutdownSignal: shutdownSignal, ShutdownAccepted: shutdownAccepted}
	if len(rows) > 0 {
		evidence.AuditHead = rows[len(rows)-1].Hash
	}
	for _, row := range rows {
		if row.Action == actionBroker {
			if evidence.BrokerResults[row.Operation] == nil {
				evidence.BrokerResults[row.Operation] = map[string]int{}
			}
			evidence.BrokerResults[row.Operation][row.Result]++
		}
		if row.Action == actionAgentCap && row.Result == resultDenied {
			evidence.ProtocolDenials++
		}
	}
	forms := append(secretForms(secret), secretForms(pass)...)
	encodedRows, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	evidence.OwnOutputSecretAbsent = !out.overflow && !containsForm(out.buf.String(), forms) && !containsForm(string(encodedRows), forms)
	db, err := os.ReadFile(vaultPath)
	if err != nil {
		return err
	}
	evidence.VaultSecretAbsent = !containsForm(string(db), forms)
	observe := os.Getenv("TREMELAY_MCP_FIXTURE_OBSERVE_DIR")
	if observe != "" {
		evidence.ObservationFiles, evidence.ObservedSecretAbsent, err = scanFixtureObservations(observe, evidencePath, dir, forms)
		evidence.ObservationsComplete = err == nil
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || containsForm(string(encoded), forms) {
		return ErrInvalid
	}
	f, err := os.OpenFile(evidencePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(encoded, '\n'))
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	// Success means the full named-client script exercised both operations and
	// a revoked handle once. An empty/replayed/reconnected session is not proof.
	exact := len(evidence.BrokerResults) == 2
	for op, want := range map[string]map[string]int{
		OpHTTPRequest: {resultAllowed: 1, resultCompleted: 1, resultDeniedRevoked: 1},
		OpHTTPBroker:  {resultAllowed: 1, resultCompleted: 1},
	} {
		got := evidence.BrokerResults[op]
		if len(got) != len(want) {
			exact = false
		}
		for result, count := range want {
			if got[result] != count {
				exact = false
			}
		}
	}
	if !exact || evidence.AuthenticatedRequests != 2 || evidence.UnauthenticatedSelfChecks != 2 || !evidence.AllowedBeforeRequest {
		return ErrInvalid
	}
	if !evidence.AuditVerified || !evidence.OwnOutputSecretAbsent || !evidence.VaultSecretAbsent || !evidence.ShutdownAccepted || evidence.UnexpectedRequests != 0 || (observe != "" && (!evidence.ObservationsComplete || !evidence.ObservedSecretAbsent)) {
		return ErrInvalid
	}
	return nil
}

// Match the shipping CLI's Linux/macOS ownership sequence. Inherited os.Stdin
// and os.Stdout are not guaranteed to be pollable: duplicate first, enable
// O_NONBLOCK before os.NewFile, then require deadline support. These owned
// files satisfy Serve's close-interruptible read/write precondition.
func fixtureStdio() (*os.File, *os.File, error) {
	duplicate := func(source *os.File) (*os.File, error) {
		raw, err := source.SyscallConn()
		if err != nil {
			return nil, ErrInvalid
		}
		fd := -1
		var dupErr error
		err = raw.Control(func(sourceFD uintptr) { fd, dupErr = unix.FcntlInt(sourceFD, unix.F_DUPFD_CLOEXEC, 3) })
		if err != nil || dupErr != nil || fd < 0 {
			return nil, ErrInvalid
		}
		if !mcpstdio.ValidInheritedStream(fd) {
			_ = unix.Close(fd)
			return nil, ErrInvalid
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			_ = unix.Close(fd)
			return nil, ErrInvalid
		}
		return os.NewFile(uintptr(fd), "synthetic-mcp-pipe"), nil
	}
	in, err := duplicate(os.Stdin)
	if err != nil {
		return nil, nil, err
	}
	out, err := duplicate(os.Stdout)
	if err != nil {
		_ = in.Close()
		return nil, nil, err
	}
	if in.SetReadDeadline(time.Time{}) != nil || out.SetWriteDeadline(time.Time{}) != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, nil, ErrInvalid
	}
	return in, out, nil
}

type fixtureOutput struct {
	io.WriteCloser
	buf      bytes.Buffer
	overflow bool
}

func (w *fixtureOutput) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) <= 2<<20 {
		_, _ = w.buf.Write(p)
	} else {
		w.overflow = true
	}
	return w.WriteCloser.Write(p)
}

// Only caller-designated regular text files in this isolated root are read.
// Symlinks, excessive nesting and budget overflow make the evidence incomplete.
func scanFixtureObservations(root, evidence, vaultDir string, forms []string) (int, bool, error) {
	if !filepath.IsAbs(root) {
		return 0, false, ErrInvalid
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil || real != root {
		return 0, false, ErrInvalid
	}
	var count, total int
	absent := true
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, visitErr error) error {
		if visitErr != nil {
			return visitErr
		}
		if path == vaultDir {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.Count(rel, string(os.PathSeparator)) > 4 {
			return ErrInvalid
		}
		if d.IsDir() {
			return nil
		}
		if path == evidence {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json", ".jsonl", ".log", ".txt", ".toml", ".yaml", ".yml":
		default:
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return ErrInvalid
		}
		count++
		if count > 64 || total+int(info.Size()) > 16<<20 {
			return ErrInvalid
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		opened, statErr := f.Stat()
		if statErr != nil || !os.SameFile(info, opened) {
			_ = f.Close()
			return ErrInvalid
		}
		data, readErr := io.ReadAll(io.LimitReader(f, (4<<20)+1))
		_ = f.Close()
		if readErr != nil || len(data) > 4<<20 {
			return ErrInvalid
		}
		total += len(data)
		if total > 16<<20 {
			return ErrInvalid
		}
		if containsForm(string(data), forms) {
			absent = false
		}
		return nil
	})
	return count, absent, err
}

// This is the fixture's ordinary-EOF acceptance check: actual subprocess,
// official SDK, fully drained responses, no observer or blocked-output probe.
func TestMCPCredentialFixtureProcess(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(root, "evidence.json")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestMCPSyntheticCredentialFixture$")
	cmd.Env = []string{"TREMELAY_MCP_SYNTHETIC_FIXTURE=1", "TREMELAY_MCP_FIXTURE_EVIDENCE=" + evidencePath, "TREMELAY_MCP_FIXTURE_OBSERVE_DIR=" + root}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		_ = output.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "tremelay-fixture-check", Version: "1"}, &mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	cs, err := client.Connect(ctx, &mcp.IOTransport{Reader: output, Writer: input, MaxLineLength: maxMCPFrame + 1}, &mcp.ClientSessionOptions{ProtocolVersion: mcpStdio20251125})
	if err != nil {
		t.Fatal("fixture initialization failed")
	}
	defer cs.Close()
	call := func(name string, args map[string]any) *mcp.CallToolResult {
		t.Helper()
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal("fixture tool call failed")
		}
		return result
	}
	entries := entriesOf(t, call(toolList, map[string]any{}))
	if len(entries) != 3 {
		t.Fatal("fixture did not expose exactly three grants")
	}
	var observations []any
	observations = append(observations, entries)
	for _, entry := range entries {
		described := call(toolDescribe, map[string]any{"handle": entry["handle"]})
		args := map[string]any{"handle": entry["handle"]}
		if entry["operation"] == OpHTTPBroker {
			args["method"] = http.MethodGet
			args["path"] = "/repos/octocat/Hello-World/issues/17"
		}
		result := call(toolInvoke, args)
		switch {
		case entry["status"] == GrantRevoked:
			if !result.IsError || toolObject(t, result)["code"] != capDeniedRevoked {
				t.Fatal("fixture revoked operation was not denied")
			}
		case entry["operation"] == OpHTTPBroker:
			out := toolObject(t, result)
			headers, _ := out["headers"].(map[string]any)
			body, _ := out["body"].(string)
			formCount := len(secretForms(nil))
			redactedForms := strings.TrimSpace(strings.Repeat(redacted+" ", formCount))
			if result.IsError || out["status_code"] != float64(200) || out["truncated"] != false || len(out) != 4 {
				t.Fatal("fixture broker response violated its closed projection")
			}
			if headers["Set-Cookie"] != nil || headers["Content-Type"] != "text/plain" || headers["Etag"] != redactedForms {
				t.Fatal("fixture broker response disclosed a cookie or an unredacted header")
			}
			if !strings.HasPrefix(body, "state=open echo=") || strings.Count(body, redacted) != formCount {
				t.Fatal("fixture broker body was not fully redacted")
			}
		default:
			if result.IsError || !reflect.DeepEqual(toolObject(t, result), map[string]any{"status_code": float64(200)}) {
				t.Fatal("fixture http_request response violated its status-only projection")
			}
		}
		observations = append(observations, described, result)
	}
	data, err := json.Marshal(observations)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "observations.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = cs.Close()
	_ = input.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal("fixture did not exit successfully after EOF")
	}
	if stderr.Len() != 0 {
		t.Fatal("fixture wrote unexpected diagnostics")
	}
	data, err = os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal("fixture did not finalize evidence")
	}
	var evidence credentialFixtureEvidence
	if json.Unmarshal(data, &evidence) != nil || !evidence.AuditVerified || !evidence.ServeClean || evidence.ShutdownReason != "eof" || !evidence.ShutdownAccepted || evidence.ShutdownSignal != "" || evidence.AuthenticatedRequests != 2 || evidence.UnauthenticatedSelfChecks != 2 || !evidence.AllowedBeforeRequest || !evidence.OwnOutputSecretAbsent || !evidence.VaultSecretAbsent || !evidence.ObservationsComplete || !evidence.ObservedSecretAbsent || evidence.ObservationFiles < 1 {
		t.Fatal("fixture evidence did not establish protected-use and clean EOF")
	}
}

//go:build linux || darwin

package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// TestMCPSyntheticSSHFixture is an explicitly selected test-binary host. It
// never opens a network service or remote SSH connection and is not in the CLI.
// Only this trusted fixture holds fresh private keys and unlock material.
func TestMCPSyntheticSSHFixture(t *testing.T) {
	if os.Getenv("TREMELAY_MCP_SYNTHETIC_SSH_FIXTURE") != "1" {
		return
	}
	if runMCPSSHFixture() != nil {
		_, _ = fmt.Fprintln(os.Stderr, "synthetic SSH fixture failed")
		os.Exit(1)
	}
	os.Exit(0)
}

type sshFixtureEvidence struct {
	Version               int                       `json:"version"`
	Fixture               string                    `json:"fixture"`
	AuditVerified         bool                      `json:"audit_verified"`
	AuditRows             int                       `json:"audit_rows"`
	SSHResults            map[string]map[string]int `json:"ssh_results"`
	ProtocolDenials       int                       `json:"protocol_denials"`
	ExactAuthority        bool                      `json:"exact_authority"`
	OwnOutputSecretAbsent bool                      `json:"own_output_secret_absent"`
	VaultSecretAbsent     bool                      `json:"vault_secret_absent"`
	ObservationsComplete  bool                      `json:"observations_complete"`
	ObservationFiles      int                       `json:"observation_files"`
	ObservedSecretAbsent  bool                      `json:"observed_secret_absent"`
	AuditContextAbsent    bool                      `json:"audit_context_absent"`
	ServeClean            bool                      `json:"serve_clean"`
	ShutdownReason        string                    `json:"shutdown_reason"`
	ShutdownSignal        string                    `json:"shutdown_signal,omitempty"`
	ShutdownAccepted      bool                      `json:"shutdown_accepted"`
}

func runMCPSSHFixture() error {
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
	pass, err := fresh()
	if err != nil {
		return err
	}
	defer wipe(pass)
	userPub, userPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer wipe(userPrivate)
	der, err := x509.MarshalPKCS8PrivateKey(userPrivate)
	if err != nil {
		return err
	}
	defer wipe(der)
	hostPub, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer wipe(hostPrivate)
	sessionID := make([]byte, 32)
	if _, err = rand.Read(sessionID); err != nil {
		return err
	}
	const resource = "synthetic-ssh-account"
	const username = "synthetic-ssh-user"
	hostBlob := marshalEd25519Pub(hostPub)
	bind := append([]byte{sshAgentExtension}, appendSSHString(nil, []byte(sshExtSessionBind))...)
	bind = appendSSHString(bind, hostBlob)
	bind = appendSSHString(bind, sessionID)
	bind = appendSSHString(bind, marshalEd25519Sig(ed25519.Sign(hostPrivate, sessionID)))
	bind = append(bind, 0)
	forms := append(secretForms(pass), secretForms(der)...)
	forms = append(forms, secretForms(userPrivate)...)
	forms = append(forms, secretForms(userPrivate[:ed25519.SeedSize])...)
	forms = append(forms, secretForms(hostPrivate)...)
	forms = append(forms, secretForms(hostPrivate[:ed25519.SeedSize])...)
	vaultPath := filepath.Join(dir, "vault.db")
	s, err := Create(vaultPath, pass, nil)
	if err != nil {
		return err
	}
	defer s.Lock()
	cred, err := s.Put("synthetic-only", "ed25519", der, PutOptions{})
	if err != nil {
		return err
	}
	// All use of the user private key is through the vault after ingest.
	wipe(userPrivate)
	wipe(der)
	wipe(hostPrivate)
	agent, err := s.CreateAgent("synthetic-ssh-client")
	if err != nil {
		return err
	}
	grants := map[string]string{}
	for _, label := range []string{"active", "revoked"} {
		g, err := s.IssueGrant(GrantSpec{AgentID: agent.ID, CredentialID: cred.ID,
			Operations: []string{OpSSHUserAuth}, Resource: resource,
			ExpiresAt: time.Now().Add(time.Hour), SSHUsername: username, SSHHostKey: hostBlob})
		if err != nil {
			return err
		}
		grants[g.ID] = label
		if label == "revoked" {
			if err := s.RevokeGrant(g.ID); err != nil {
				return err
			}
		}
	}
	current, ok := s.credByID(cred.ID)
	if !ok {
		return ErrInvalid
	}
	generation := current.Gen
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
	observe := os.Getenv("TREMELAY_MCP_FIXTURE_OBSERVE_DIR")
	if !filepath.IsAbs(observe) || filepath.Dir(observe) != parent {
		return ErrInvalid
	}
	realObserve, err := filepath.EvalSymlinks(observe)
	if err != nil || realObserve != observe {
		return ErrInvalid
	}
	// The challenge contains public SSH host proof only. The client must obtain
	// the user public key from the post-bind identity response.
	challenge := struct {
		Resource string `json:"resource"`
		Username string `json:"username"`
		Host     []byte `json:"host_blob"`
		Session  []byte `json:"session_id"`
		Bind     []byte `json:"bind_message"`
	}{resource, username, hostBlob, sessionID, bind}
	if err := writeSSHFixtureJSON(filepath.Join(observe, "public-challenge.json"), challenge, forms); err != nil {
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
	evidence := sshFixtureEvidence{Version: 1, Fixture: "synthetic-hostbound-ssh",
		AuditVerified: verifyErr == nil, AuditRows: len(rows),
		SSHResults:     map[string]map[string]int{"active": {}, "revoked": {}},
		ExactAuthority: len(cap.byHandle) == 2, ServeClean: serveErr == nil,
		ShutdownReason: shutdownReason, ShutdownSignal: shutdownSignal, ShutdownAccepted: shutdownAccepted}
	for _, bound := range cap.byHandle {
		_, known := grants[bound.grantID]
		if !known || cap.agentID != agent.ID || bound.credID != cred.ID || bound.credGen != generation ||
			bound.keyID != hex.EncodeToString(userPub) || bound.operation != OpSSHUserAuth ||
			bound.resource != resource || bound.sshUser != username || bound.sshHost != string(hostBlob) {
			evidence.ExactAuthority = false
		}
	}
	for _, row := range rows {
		if row.Action == actionSSHUserAuth {
			label, known := grants[row.GrantID]
			if !known || row.AgentID != agent.ID || row.CredID != cred.ID || row.Operation != OpSSHUserAuth {
				evidence.ExactAuthority = false
			} else {
				evidence.SSHResults[label][row.Result]++
			}
		}
		if row.Action == actionAgentCap && row.Result == resultDenied {
			evidence.ProtocolDenials++
		}
	}
	encodedRows, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	evidence.OwnOutputSecretAbsent = !out.overflow && !containsForm(out.buf.String(), forms) && !containsForm(string(encodedRows), forms)
	contextForms := append(secretForms(hostBlob), secretForms(sessionID)...)
	contextForms = append(contextForms, username)
	evidence.AuditContextAbsent = !containsForm(string(encodedRows), contextForms)
	db, err := os.ReadFile(vaultPath)
	if err != nil {
		return err
	}
	evidence.VaultSecretAbsent = !containsForm(string(db), forms)
	evidence.ObservationFiles, evidence.ObservedSecretAbsent, err = scanFixtureObservations(observe, evidencePath, dir, forms)
	evidence.ObservationsComplete = err == nil
	if err := writeSSHFixtureJSON(evidencePath, evidence, forms); err != nil {
		return err
	}
	want := map[string]map[string]int{
		"active":  {resultAllowed: 3, resultCompleted: 1, resultDenied: 3},
		"revoked": {resultDeniedRevoked: 1},
	}
	if !reflect.DeepEqual(evidence.SSHResults, want) || !evidence.ExactAuthority ||
		!evidence.AuditVerified || !evidence.AuditContextAbsent || !evidence.OwnOutputSecretAbsent ||
		!evidence.VaultSecretAbsent || !evidence.ShutdownAccepted || !evidence.ObservationsComplete || !evidence.ObservedSecretAbsent {
		return ErrInvalid
	}
	return nil
}

func writeSSHFixtureJSON(path string, value any, forms []string) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil || containsForm(string(data), forms) {
		return ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(data, '\n'))
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

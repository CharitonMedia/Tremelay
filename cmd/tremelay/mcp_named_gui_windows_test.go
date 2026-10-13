//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
	"golang.org/x/sys/windows"
)

// This opt-in controller never substitutes the Go SDK for a named runtime.
// The default suite's GUI/SDK fixture is separate. A selected lane fails when
// any prerequisite, native control request, GUI operation or receipt is absent.
func TestWindowsNamedClientShippingGUI(t *testing.T) {
	client := os.Getenv("TREMELAY_TEST_WINDOWS_NAMED_CLIENT")
	if client == "" {
		if os.Getenv("TREMELAY_TEST_WINDOWS_NAMED_REQUIRED") == "1" {
			t.Fatal("required Windows named client is missing")
		}
		t.Skip("native Windows named-client lane not selected; no named-client evidence")
	}
	if client != "codex" && client != "claude" && client != "hermes" {
		t.Fatal("unsupported Windows named client")
	}
	cli, helper := os.Getenv("TREMELAY_TEST_WINDOWS_CLI"), os.Getenv("TREMELAY_TEST_WINDOWS_PINENTRY")
	python, native := os.Getenv("TREMELAY_TEST_WINDOWS_PYTHON"), os.Getenv("TREMELAY_TEST_WINDOWS_NATIVE")
	driver := os.Getenv("TREMELAY_TEST_WINDOWS_NAMED_DRIVER")
	for _, path := range []string{cli, helper, python, native} {
		if !validPinentryExecutable(path) {
			t.Fatal("native executable must be an absolute local exe")
		}
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatal("native executable unavailable")
		}
	}
	if !filepath.IsAbs(driver) || filepath.Base(driver) != "mcp_windows_named_client.py" {
		t.Fatal("Windows named driver path is invalid")
	}
	if info, err := os.Stat(driver); err != nil || !info.Mode().IsRegular() {
		t.Fatal("Windows named driver is missing")
	}
	// Reject look-alike helpers and substituted known adjacent dependencies.
	for name, want := range map[string]string{
		"pinentry-basic.exe": "e498f66104a286544488fb2ac4aec72ccd1e6de2c0ec7b7e7ae9fc733c54775a",
		"libassuan-9.dll":    "479887bebb8929cc3e9cffaa4cc7140705fa2dcb57a3a5f3db90d949bf097052",
		"libgpg-error-0.dll": "dd0c8cd53fcc7745da4ee3f3227dc7e2a5257e9f1f7be490f88d9ff7a9353d2f",
	} {
		if !strings.EqualFold(filepath.Base(helper), "pinentry-basic.exe") || namedGUIHash(t, filepath.Join(filepath.Dir(helper), name)) != want {
			t.Fatal("official GUI helper package member differs from its pin")
		}
	}
	root := t.TempDir()
	random := randBytes(t, 24)
	pass := make([]byte, hex.EncodedLen(len(random)))
	hex.Encode(pass, random)
	vault.Wipe(random)
	defer vault.Wipe(pass)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("synthetic key generation failed")
	}
	defer vault.Wipe(private)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("synthetic key encoding failed")
	}
	defer vault.Wipe(der)
	path := filepath.Join(root, "synthetic.vault")
	session, err := vault.Create(path, pass, nil)
	if err != nil {
		t.Fatal("synthetic vault creation failed")
	}
	defer session.Lock()
	credential, err := session.Put("synthetic named-client key", vault.CredTypeEd25519, der, vault.PutOptions{})
	if err != nil {
		t.Fatal("synthetic credential creation failed")
	}
	agent, err := session.CreateAgent("synthetic-windows-named-client")
	if err != nil {
		t.Fatal("synthetic agent creation failed")
	}
	grants := map[string]string{}
	for _, resource := range []string{"gui-allowed", "gui-revoked"} {
		grant, err := session.IssueGrant(vault.GrantSpec{AgentID: agent.ID, CredentialID: credential.ID,
			Operations: []string{vault.OpLocalArtifactAttest}, Resource: resource, ExpiresAt: time.Now().Add(time.Hour).UTC()})
		if err != nil {
			t.Fatal("synthetic grant creation failed")
		}
		grants[resource] = grant.ID
	}
	if session.RevokeGrant(grants["gui-revoked"]) != nil {
		t.Fatal("synthetic grant revocation failed")
	}
	session.Lock()
	payload := []byte("public Windows named-client custody challenge")
	request := map[string]any{
		"client": client, "executable": native, "hermes_source": os.Getenv("TREMELAY_TEST_WINDOWS_HERMES_SOURCE"),
		"server": map[string]any{"command": cli, "args": []string{"mcp", "serve", "--path", path,
			"--agent", agent.ID, "--pinentry", helper, "--unlock-timeout", "30s"}, "env": map[string]string{}},
		"challenge": map[string]string{"key_id": hex.EncodeToString(public), "payload": base64.StdEncoding.EncodeToString(payload)},
	}
	writeNamedGUIJSON(t, filepath.Join(root, "request.json"), request)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	capture := guiCapture{data: make([]byte, 0, 256<<10)}
	defer capture.wipe()
	cmd := exec.CommandContext(ctx, python, driver, "--request", filepath.Join(root, "request.json"))
	cmd.Env = []string{"SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1"}
	cmd.Dir, cmd.Stdout, cmd.Stderr, cmd.WaitDelay = root, &capture, &capture, 2*time.Second
	if cmd.Start() != nil {
		t.Fatal("Windows named driver did not start")
	}
	driverHandle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("driver process custody could not be retained")
	}
	defer windows.CloseHandle(driverHandle)
	var nativeHandle, interpreterHandle, serverHandle, helperHandle windows.Handle
	joined := false
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cancel()
		_ = cmd.Process.Kill()
		if state, err := windows.WaitForSingleObject(driverHandle, 5000); err != nil || state != windows.WAIT_OBJECT_0 {
			t.Error("named driver did not terminate")
		}
		// Stop each retained parent before discovering/killing its direct child.
		// These are owned process handles, never a generic PID tree-kill.
		type processLink struct {
			parent windows.Handle
			child  *windows.Handle
			image  string
		}
		parents := []processLink{{driverHandle, &nativeHandle, native}}
		if client == "hermes" {
			parents = append(parents, processLink{nativeHandle, &interpreterHandle, python})
		}
		parents = append(parents, processLink{0, &serverHandle, cli}, processLink{serverHandle, &helperHandle, helper})
		for i := range parents {
			if i > 0 {
				parents[i].parent = *parents[i-1].child
			}
			entry := parents[i]
			if *entry.child == 0 && entry.parent != 0 {
				pid, e := windows.GetProcessId(entry.parent)
				if e == nil {
					*entry.child, _ = findGUIHelper(pid, entry.image)
				}
			}
			if *entry.child != 0 {
				state, _ := windows.WaitForSingleObject(*entry.child, 0)
				if state != windows.WAIT_OBJECT_0 {
					_ = windows.TerminateProcess(*entry.child, 1)
				}
				if state, e := windows.WaitForSingleObject(*entry.child, 5000); e != nil || state != windows.WAIT_OBJECT_0 {
					t.Error("owned named-client process did not terminate")
				}
			}
		}
		for _, handle := range []windows.Handle{helperHandle, serverHandle, interpreterHandle, nativeHandle} {
			if handle != 0 {
				windows.CloseHandle(handle)
			}
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("named driver cleanup did not join")
			}
		}
	}()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) && helperHandle == 0 {
		if nativeHandle == 0 {
			var launch struct{ PID uint32 }
			data, readErr := os.ReadFile(filepath.Join(root, "client-launch.json"))
			if readErr == nil && json.Unmarshal(data, &launch) == nil && launch.PID > 1 {
				nativeHandle, err = findGUIHelper(uint32(cmd.Process.Pid), native)
				if nativeHandle != 0 {
					pid, e := windows.GetProcessId(nativeHandle)
					if e != nil || pid != launch.PID {
						t.Fatal("native client launch identity differs")
					}
				}
			}
		}
		if nativeHandle != 0 && serverHandle == 0 {
			pid, e := windows.GetProcessId(nativeHandle)
			if e != nil {
				t.Fatal("native client identity unavailable")
			}
			// CPython's Windows venv executable is a known redirector. Pin and
			// retain its exact base-interpreter child instead of accepting an
			// arbitrary descendant tree or pretending the redirector is Hermes.
			if client == "hermes" {
				if interpreterHandle == 0 {
					interpreterHandle, err = findGUIHelper(pid, python)
				}
				if interpreterHandle != 0 {
					pid, e = windows.GetProcessId(interpreterHandle)
					if e != nil {
						t.Fatal("Hermes base interpreter identity unavailable")
					}
					serverHandle, err = findGUIHelper(pid, cli)
				}
			} else {
				serverHandle, err = findGUIHelper(pid, cli)
			}
		}
		if serverHandle != 0 {
			pid, e := windows.GetProcessId(serverHandle)
			if e != nil {
				t.Fatal("shipping server identity unavailable")
			}
			helperHandle, err = findGUIHelper(pid, helper)
		}
		if err != nil {
			t.Fatal("native client process ownership unavailable")
		}
		select {
		case <-done:
			joined = true
			t.Fatal("native driver exited before owned helper discovery")
		case <-time.After(25 * time.Millisecond):
		}
	}
	if helperHandle == 0 {
		t.Fatal("native client did not launch the shipping CLI and official helper")
	}
	helperPID, err := windows.GetProcessId(helperHandle)
	if err != nil {
		t.Fatal("official helper identity unavailable")
	}
	var dialog uintptr
	for time.Now().Before(deadline) {
		dialog = findGUIDialog(helperPID)
		if dialog != 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if dialog == 0 || enterGUI(dialog, helperHandle, pass, false) != nil {
		t.Fatal("official native-client pinentry GUI unavailable or failed")
	}
	if state, err := windows.WaitForSingleObject(helperHandle, 5000); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("official helper did not exit after unlock")
	}
	if state, err := windows.WaitForSingleObject(serverHandle, 60000); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("native client did not close its shipping server")
	}
	var serverExit uint32
	exitErr := windows.GetExitCodeProcess(serverHandle, &serverExit)
	if exitErr != nil || serverExit != 0 {
		// Expose only public process status and a fixed category. Never print
		// raw Codex/client stderr, MCP traffic, or any synthetic credential.
		_, statusErr := os.Stat(filepath.Join(root, "observations", "client-status.json"))
		_, resultErr := os.Stat(filepath.Join(root, "client-result.json"))
		t.Fatalf("shipping server did not exit successfully (exit=%d, status_seen=%t, result_seen=%t, client_log_category=%s)",
			serverExit, statusErr == nil, resultErr == nil, namedGUIClientLogCategory(root))
	}
	writeNamedGUIJSON(t, filepath.Join(root, "fixture-evidence.json"), map[string]bool{"shipping_server_exited": true})
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("native client control/capture acceptance failed")
		}
	case <-ctx.Done():
		t.Fatal("native client driver did not complete")
	}
	if state, err := windows.WaitForSingleObject(nativeHandle, 5000); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("native client process remained alive")
	}
	if interpreterHandle != 0 {
		if state, err := windows.WaitForSingleObject(interpreterHandle, 5000); err != nil || state != windows.WAIT_OBJECT_0 {
			t.Fatal("Hermes base interpreter remained alive")
		}
	}
	resultBytes := readNamedGUIBounded(t, filepath.Join(root, "client-result.json"))
	defer vault.Wipe(resultBytes)
	var resultFields map[string]json.RawMessage
	if json.Unmarshal(resultBytes, &resultFields) != nil {
		t.Fatal("native client result is malformed")
	}
	for _, key := range []string{"tool_calls", "credential_invocations", "driver_retries", "model_turns", "raw_client_output_capture_complete", "cleanup", "attestation"} {
		if len(resultFields[key]) == 0 || bytes.Equal(resultFields[key], []byte("null")) {
			t.Fatal("native client result omits required evidence")
		}
	}
	var result struct {
		ToolCalls                      int  `json:"tool_calls"`
		CredentialInvocations          int  `json:"credential_invocations"`
		DriverRetries                  int  `json:"driver_retries"`
		ModelTurns                     int  `json:"model_turns"`
		RawClientOutputCaptureComplete bool `json:"raw_client_output_capture_complete"`
		Cleanup                        struct {
			ExitCode          int  `json:"exit_code"`
			ShutdownEscalated bool `json:"shutdown_escalated"`
		} `json:"cleanup"`
		Attestation struct {
			Resource, Signature, Domain, Purpose string
			PublicKey                            string `json:"public_key"`
		}
	}
	if json.Unmarshal(resultBytes, &result) != nil || result.ToolCalls != 5 || result.CredentialInvocations != 2 || result.DriverRetries != 0 || result.ModelTurns != 0 || !result.RawClientOutputCaptureComplete || result.Cleanup.ExitCode != 0 || result.Cleanup.ShutdownEscalated {
		t.Fatal("native client result is incomplete")
	}
	message := []byte("TREMELAY1")
	for _, field := range [][]byte{[]byte("tremelay/local-artifact-attestation/v1"), []byte("local-artifact-attestation"), []byte("gui-allowed"), payload} {
		message = binary.BigEndian.AppendUint32(message, uint32(len(field)))
		message = append(message, field...)
	}
	attestation := result.Attestation
	signature, err := base64.StdEncoding.DecodeString(attestation.Signature)
	if err != nil || attestation.PublicKey != base64.StdEncoding.EncodeToString(public) || attestation.Resource != "gui-allowed" || attestation.Domain != "tremelay/local-artifact-attestation/v1" || attestation.Purpose != "local-artifact-attestation" || !ed25519.Verify(public, message, signature) {
		t.Fatal("native client public signature verification failed")
	}
	if _, err := vault.VerifyAudit(path, pass); err != nil {
		t.Fatal("native client audit integrity failed")
	}
	auditor, err := vault.Unlock(path, pass, nil)
	if err != nil {
		t.Fatal("native client audit inspection failed")
	}
	records, err := auditor.AuditHistory(vault.AuditFilter{Action: "local_attest", Limit: 100})
	auditor.Lock()
	if err != nil || len(records) != 3 {
		t.Fatal("native client operation audit count differs")
	}
	counts := map[string]int{}
	for _, record := range records {
		resource := "gui-allowed"
		if record.Result == "denied_revoked" {
			resource = "gui-revoked"
		}
		if record.AgentID != agent.ID || record.CredentialID != credential.ID || record.Operation != vault.OpLocalArtifactAttest || record.GrantID != grants[resource] {
			t.Fatal("native client operation audit attribution differs")
		}
		counts[record.Result]++
	}
	if counts["allowed"] != 1 || counts["completed"] != 1 || counts["denied_revoked"] != 1 {
		t.Fatal("native client operation audit results differ")
	}
	secrets := [][]byte{pass, der, private, private[:ed25519.SeedSize]}
	scan := func(data []byte) {
		defer vault.Wipe(data)
		for _, secret := range secrets {
			encoded, hexed := base64.StdEncoding.AppendEncode(nil, secret), hex.AppendEncode(nil, secret)
			leaked := bytes.Contains(data, secret) || bytes.Contains(data, encoded) || bytes.Contains(data, hexed)
			vault.Wipe(encoded)
			vault.Wipe(hexed)
			if leaked {
				t.Fatal("synthetic secret crossed the observed native-client boundary")
			}
		}
	}
	scan(capture.snapshot(t))
	scan([]byte(strings.Join(cmd.Args, "\x00") + strings.Join(cmd.Env, "\x00")))
	auditBytes, err := json.Marshal(records)
	if err != nil {
		t.Fatal("audit scan encoding failed")
	}
	scan(auditBytes)
	files := 0
	for _, name := range []string{"request.json", "client-result.json", "client-launch.json", "client-cleanup.json", "fixture-evidence.json", "synthetic.vault"} {
		scan(readNamedGUIBounded(t, filepath.Join(root, name)))
		files++
	}
	entries, err := os.ReadDir(filepath.Join(root, "observations"))
	if err != nil {
		t.Fatal("native client observations unavailable")
	}
	for _, entry := range entries {
		scan(readNamedGUIBounded(t, filepath.Join(root, "observations", entry.Name())))
		files++
	}
	// No raw captures, vault, private key or passphrase enter the allowlisted receipt.
	if os.Remove(path) != nil {
		t.Fatal("synthetic vault removal failed")
	}
	if destination := os.Getenv("TREMELAY_TEST_WINDOWS_NAMED_EVIDENCE"); destination != "" {
		if !filepath.IsAbs(destination) {
			t.Fatal("native evidence path must be absolute")
		}
		writeNamedGUIJSON(t, destination, map[string]any{"schema": 1, "client": client,
			"client_version": map[string]string{"codex": "0.159.2", "claude": "2.1.296", "hermes": "v0.21.7"}[client], "python_version": "3.14.8",
			"scope":      "native Windows shipping CLI, official GUI, synthetic attestation and revoked denial; no network broker evidence",
			"tool_calls": 5, "credential_invocations": 2, "model_turns": 0, "driver_retries": 0,
			"audit": counts, "audit_verified": true, "signature_verified": true,
			"client_exit": 0, "server_exit": serverExit, "helper_exited": true, "vault_removed": true,
			"scanned_files": files, "observed_secret_absent": true,
			"scan_scope":                      "completed manifest captures/configuration, controller output, selected audit, encrypted vault; excludes client home/cache/database files",
			"inherited_handle_modes_observed": false,
			"cli_sha256":                      namedGUIHash(t, cli), "helper_sha256": namedGUIHash(t, helper), "native_sha256": namedGUIHash(t, native), "driver_sha256": namedGUIHash(t, driver),
			"python_sha256": namedGUIHash(t, python), "control_driver_sha256": namedGUIHash(t, filepath.Join(filepath.Dir(driver), "mcp_named_client_smoke.py"))})
	}
}

// This diagnostic does not change the acceptance condition. It classifies
// known, fixed CLI diagnostic strings from a bounded, private synthetic client
// capture without disclosing any log bytes or a command-line argument.
func namedGUIClientLogCategory(root string) string {
	path := filepath.Join(root, "observations", "client-stderr.log")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return "unavailable"
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4<<20 {
		return "unavailable"
	}
	defer vault.Wipe(data)
	for _, candidate := range []struct {
		message  string
		category string
	}{
		{"mcp serve requires supported, close-interruptible stdin and stdout pipes", "stdio-rejected"},
		{"vault unlock failed", "vault-unlock-failed"},
		{"mcp agent binding failed", "agent-binding-failed"},
		{"mcp session cancelled", "session-cancelled"},
		{"mcp session failed; inspect the vault audit before retrying an operation", "session-failed"},
		{"pinentry", "pinentry-mentioned"},
	} {
		if bytes.Contains(data, []byte(candidate.message)) {
			return candidate.category
		}
	}
	if len(data) == 0 {
		return "empty"
	}
	return "other-private-log"
}

func namedGUIHash(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("native evidence binary unavailable")
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func writeNamedGUIJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("native public fixture encoding failed")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("native public fixture already exists or is unavailable")
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("native public fixture write failed")
	}
}

func readNamedGUIBounded(t *testing.T, path string) []byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		t.Fatal("native client scan file is unavailable or exceeds its bound")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4<<20 {
		t.Fatal("native client scan could not complete")
	}
	return data
}

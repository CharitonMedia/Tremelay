//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/CharitonMedia/Tremelay/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/windows"
)

// This ordinary Windows test launches the shipping CLI, not the test binary's
// run function or a pre-unlocked endpoint. Preparation is extraction-only; see
// scripts/prepare_windows_pinentry.ps1. No input is supplied to protocol stdin
// until the official GUI helper has exited after the synthetic unlock.
func TestWindowsMCPShippingCLIWithOfficialGUI(t *testing.T) {
	helper, cli := os.Getenv("TREMELAY_TEST_WINDOWS_PINENTRY"), os.Getenv("TREMELAY_TEST_WINDOWS_CLI")
	if helper == "" || cli == "" {
		if os.Getenv("TREMELAY_TEST_WINDOWS_GUI_REQUIRED") == "1" {
			t.Fatal("required official Windows GUI fixture is missing")
		}
		t.Skip("official Windows GUI fixture not prepared; no shipping GUI evidence")
	}
	if !validPinentryExecutable(helper) || !validPinentryExecutable(cli) {
		t.Fatal("official Windows GUI fixture paths are invalid")
	}
	for _, cancelPrompt := range []bool{false, true} {
		name := "attest-and-revoked-denial"
		if cancelPrompt {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) { exerciseWindowsShippingGUI(t, cli, helper, cancelPrompt) })
	}
}

type guiCapture struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (b *guiCapture) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := (256 << 10) - len(b.data)
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil // Always drain; an evidence bound must not block the child.
}

func (b *guiCapture) snapshot(t *testing.T) []byte {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		t.Fatal("shipping CLI evidence exceeded the capture bound")
	}
	return append([]byte(nil), b.data...)
}

func (b *guiCapture) wipe() {
	b.mu.Lock()
	defer b.mu.Unlock()
	vault.Wipe(b.data)
	b.data = nil
}

type guiReadCapture struct {
	io.ReadCloser
	capture *guiCapture
}

func (r guiReadCapture) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.capture.Write(p[:n])
	return n, err
}

type guiWriteCapture struct {
	io.WriteCloser
	capture *guiCapture
}

func (w guiWriteCapture) Write(p []byte) (int, error) {
	n, err := w.WriteCloser.Write(p)
	w.capture.Write(p[:n])
	return n, err
}

func exerciseWindowsShippingGUI(t *testing.T, cli, helper string, cancelPrompt bool) {
	t.Helper()
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
	path := filepath.Join(t.TempDir(), "synthetic.vault")
	session, err := vault.Create(path, pass, nil)
	if err != nil {
		t.Fatal("synthetic vault creation failed")
	}
	defer session.Lock()
	credential, err := session.Put("synthetic GUI key", vault.CredTypeEd25519, der, vault.PutOptions{})
	if err != nil {
		t.Fatal("synthetic credential creation failed")
	}
	agent, err := session.CreateAgent("synthetic-windows-gui")
	if err != nil {
		t.Fatal("synthetic agent creation failed")
	}
	grants := make(map[string]string)
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

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	in, clientWrite := windowsTestPipe(t)
	clientRead, out := windowsTestPipe(t)
	client, err := openMCPStdio(clientRead, clientWrite)
	if err != nil {
		t.Fatal("synthetic client pipe custody failed")
	}
	clientRead.Close()
	clientWrite.Close()
	defer client.close()
	stderr := guiCapture{data: make([]byte, 0, 256<<10)}
	wire := guiCapture{data: make([]byte, 0, 256<<10)}
	defer stderr.wipe()
	defer wire.wipe()
	cmd := exec.CommandContext(ctx, cli, "mcp", "serve", "--path", path, "--agent", agent.ID,
		"--pinentry", helper, "--unlock-timeout", "30s")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, &stderr
	// SYSTEMROOT is the sole inherited OS path. The helper gets its existing
	// still narrower production environment; no synthetic secret is in env.
	cmd.Env = []string{"SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "LANG=C"}
	cmd.Dir = filepath.Dir(path)
	cmd.WaitDelay = 2 * time.Second
	if cmd.Start() != nil {
		t.Fatal("shipping Windows CLI did not start")
	}
	in.Close()
	out.Close()
	// Open before Wait releases os.Process's handle. Retain the root process
	// object through final child discovery, including early-exit cleanup.
	root, rootErr := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	var ownedHelper windows.Handle
	if rootErr != nil {
		// No UI is entered on this failure. Keep os.Process's original handle
		// until after the one cleanup discovery; do not look up a released PID.
		_ = cmd.Process.Kill()
		ownedHelper, _ = findGUIHelper(uint32(cmd.Process.Pid), helper)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	joined := false
	defer func() {
		cancel()
		_ = cmd.Process.Kill()
		if root != 0 {
			defer windows.CloseHandle(root)
			// A terminated root cannot launch another helper after the scan.
			if state, err := windows.WaitForSingleObject(root, 5000); err != nil || state != windows.WAIT_OBJECT_0 {
				t.Error("shipping CLI root did not terminate")
			}
		}
		if ownedHelper == 0 && root != 0 {
			ownedHelper, _ = findGUIHelper(uint32(cmd.Process.Pid), helper)
		}
		if ownedHelper != 0 {
			state, _ := windows.WaitForSingleObject(ownedHelper, 0)
			if state != windows.WAIT_OBJECT_0 {
				_ = windows.TerminateProcess(ownedHelper, 1)
			}
			state, err := windows.WaitForSingleObject(ownedHelper, 5000)
			if err != nil || state != windows.WAIT_OBJECT_0 {
				t.Error("owned official helper did not terminate")
			}
			windows.CloseHandle(ownedHelper)
		}
		client.close()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("shipping CLI cleanup did not join")
			}
		}
	}()
	if rootErr != nil {
		t.Fatal("shipping CLI root custody could not be retained")
	}

	var dialog uintptr
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if ownedHelper == 0 {
			ownedHelper, err = findGUIHelper(uint32(cmd.Process.Pid), helper)
			if err != nil {
				t.Fatal("official helper ownership could not be verified")
			}
		}
		if ownedHelper != 0 {
			pid, err := windows.GetProcessId(ownedHelper)
			if err != nil {
				t.Fatal("official helper identity was lost")
			}
			dialog = findGUIDialog(pid)
			if dialog != 0 {
				break
			}
		}
		select {
		case <-done:
			joined = true
			t.Fatal("shipping CLI exited before the official GUI appeared")
		case <-time.After(25 * time.Millisecond):
		}
	}
	if dialog == 0 {
		t.Fatal("official pinentry GUI unavailable on this Windows desktop")
	}
	if err := enterGUI(dialog, ownedHelper, pass, cancelPrompt); err != nil {
		t.Fatal("official pinentry GUI interaction failed")
	}
	if state, err := windows.WaitForSingleObject(ownedHelper, 5000); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("official pinentry did not exit after the GUI result")
	}
	if cancelPrompt {
		select {
		case err := <-done:
			joined = true
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatal("GUI cancellation did not fail the shipping CLI closed")
			}
		case <-ctx.Done():
			t.Fatal("shipping CLI did not join after GUI cancellation")
		}
		_, _ = io.Copy(&wire, client.in)
		captured, diagnostic := wire.snapshot(t), stderr.snapshot(t)
		defer vault.Wipe(captured)
		defer vault.Wipe(diagnostic)
		if len(captured) != 0 || !bytes.Equal(diagnostic, []byte(errPinentryCancelled.Error()+"\n")) {
			t.Fatal("GUI cancellation was not protocol-silent with a fixed diagnostic")
		}
		return
	}

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "windows-gui-custody", Version: "1"}, &mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	peer, err := mcpClient.Connect(ctx, &mcp.IOTransport{Reader: guiReadCapture{client.in, &wire}, Writer: guiWriteCapture{client.out, &wire}}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatal("shipping CLI initialization after GUI unlock failed")
	}
	defer func() { cancel(); peer.Close() }()
	listed, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "list_capabilities", Arguments: map[string]any{}})
	if err != nil || listed.IsError {
		t.Fatal("shipping CLI capability discovery failed")
	}
	var catalogue struct {
		Entries []struct{ Handle, Operation, Resource, Status string }
	}
	decodeGUIResult(t, listed, &catalogue)
	if len(catalogue.Entries) != 2 {
		t.Fatal("shipping CLI did not expose the exact synthetic grants")
	}
	entries := make(map[string]string)
	for _, entry := range catalogue.Entries {
		wantStatus := vault.GrantActive
		if entry.Resource == "gui-revoked" {
			wantStatus = vault.GrantRevoked
		}
		if grants[entry.Resource] == "" || entry.Operation != vault.OpLocalArtifactAttest || entry.Status != wantStatus || entry.Handle == "" {
			t.Fatal("shipping CLI changed a synthetic grant binding")
		}
		entries[entry.Resource] = entry.Handle
	}
	payload := []byte("public Windows GUI custody challenge")
	allowed, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_capability", Arguments: map[string]any{
		"handle": entries["gui-allowed"], "payload": base64.StdEncoding.EncodeToString(payload)}})
	if err != nil || allowed.IsError {
		t.Fatal("shipping CLI authorized attestation failed")
	}
	var attestation struct {
		Resource, Signature, Domain, Purpose string
		PublicKey                            string `json:"public_key"`
	}
	decodeGUIResult(t, allowed, &attestation)
	signature, err := base64.StdEncoding.DecodeString(attestation.Signature)
	// Rebuild the documented public encoding independently of vault's signer
	// and verifier, then use the standard Ed25519 verifier with the fixture key.
	message := []byte("TREMELAY1")
	for _, field := range [][]byte{[]byte("tremelay/local-artifact-attestation/v1"), []byte("local-artifact-attestation"), []byte("gui-allowed"), payload} {
		message = binary.BigEndian.AppendUint32(message, uint32(len(field)))
		message = append(message, field...)
	}
	if err != nil || attestation.PublicKey != base64.StdEncoding.EncodeToString(public) || attestation.Domain != "tremelay/local-artifact-attestation/v1" || attestation.Purpose != "local-artifact-attestation" || attestation.Resource != "gui-allowed" || !ed25519.Verify(public, message, signature) {
		t.Fatal("shipping CLI public signature verification failed")
	}
	denied, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_capability", Arguments: map[string]any{
		"handle": entries["gui-revoked"], "payload": base64.StdEncoding.EncodeToString(payload)}})
	if err != nil || !denied.IsError || len(denied.Content) != 1 {
		t.Fatal("shipping CLI revoked operation was not denied")
	}
	text, ok := denied.Content[0].(*mcp.TextContent)
	var denial struct{ Code string }
	if !ok || json.Unmarshal([]byte(text.Text), &denial) != nil || denial.Code != "denied_revoked" {
		t.Fatal("shipping CLI revoked denial changed its fixed result")
	}
	if peer.Close() != nil {
		t.Fatal("ordinary MCP client close failed")
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("shipping CLI did not exit cleanly after ordinary EOF")
		}
	case <-ctx.Done():
		t.Fatal("shipping CLI did not join after ordinary EOF")
	}
	captured, diagnostic := wire.snapshot(t), stderr.snapshot(t)
	defer vault.Wipe(captured)
	defer vault.Wipe(diagnostic)
	if len(diagnostic) != 0 {
		t.Fatal("successful shipping CLI emitted a diagnostic")
	}
	for _, secret := range [][]byte{pass, der, private, private[:ed25519.SeedSize]} {
		base64Secret := base64.StdEncoding.AppendEncode(nil, secret)
		hexSecret := hex.AppendEncode(nil, secret)
		for _, boundary := range [][]byte{captured, diagnostic, []byte(strings.Join(cmd.Args, "\x00")), []byte(strings.Join(cmd.Env, "\x00"))} {
			if bytes.Contains(boundary, secret) || bytes.Contains(boundary, base64Secret) || bytes.Contains(boundary, hexSecret) {
				vault.Wipe(base64Secret)
				vault.Wipe(hexSecret)
				t.Fatal("synthetic secret crossed the client or launch boundary")
			}
		}
		vault.Wipe(base64Secret)
		vault.Wipe(hexSecret)
	}
	if _, err := vault.VerifyAudit(path, pass); err != nil {
		t.Fatal("shipping CLI audit integrity failed")
	}
	auditor, err := vault.Unlock(path, pass, nil)
	if err != nil {
		t.Fatal("synthetic audit inspection failed")
	}
	defer auditor.Lock()
	records, err := auditor.AuditHistory(vault.AuditFilter{Action: "local_attest", Limit: 100})
	if err != nil || len(records) != 3 {
		t.Fatal("shipping CLI attestation audit count differs")
	}
	counts := map[string]int{}
	for _, record := range records {
		if record.AgentID != agent.ID || record.CredentialID != credential.ID || record.Operation != vault.OpLocalArtifactAttest {
			t.Fatal("shipping CLI audit attribution differs")
		}
		if record.Result == "denied_revoked" {
			if record.GrantID != grants["gui-revoked"] {
				t.Fatal("revoked audit selected another grant")
			}
		} else if record.GrantID != grants["gui-allowed"] {
			t.Fatal("allowed audit selected another grant")
		}
		counts[record.Result]++
	}
	if counts["allowed"] != 1 || counts["completed"] != 1 || counts["denied_revoked"] != 1 {
		t.Fatal("shipping CLI audit result counts differ")
	}
}

func decodeGUIResult(t *testing.T, result *mcp.CallToolResult, target any) {
	t.Helper()
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil || json.Unmarshal(encoded, target) != nil {
		t.Fatal("shipping CLI public result is malformed")
	}
}

// Hold a process handle after checking both direct parent PID and exact image.
// A handle, unlike a later PID lookup, still identifies the same exited child.
func findGUIHelper(parent uint32, image string) (windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ParentProcessID != parent {
			continue
		}
		handle, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, entry.ProcessID)
		if e != nil {
			continue
		}
		var path [32768]uint16
		length := uint32(len(path))
		e = windows.QueryFullProcessImageName(handle, 0, &path[0], &length)
		if e == nil && strings.EqualFold(filepath.Clean(windows.UTF16ToString(path[:length])), filepath.Clean(image)) {
			return handle, nil
		}
		windows.CloseHandle(handle)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return 0, err
	}
	return 0, nil
}

var guiUser32 = windows.NewLazySystemDLL("user32.dll")
var guiEnumWindows = guiUser32.NewProc("EnumWindows")
var guiWindowPID = guiUser32.NewProc("GetWindowThreadProcessId")
var guiGetDlgItem = guiUser32.NewProc("GetDlgItem")
var guiVisible = guiUser32.NewProc("IsWindowVisible")
var guiEnabled = guiUser32.NewProc("IsWindowEnabled")
var guiSendTimeout = guiUser32.NewProc("SendMessageTimeoutW")

type guiWindowSearch struct {
	pid    uint32
	dialog uintptr
}

var guiSearchMu sync.Mutex
var guiSearch atomic.Pointer[guiWindowSearch]

// Register once, not on every polling pass: Windows callbacks cannot be freed.
var guiEnumCallback = windows.NewCallback(func(hwnd, parameter uintptr) uintptr {
	search := guiSearch.Load()
	if search == nil {
		return 0
	}
	var pid uint32
	guiWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	visible, _, _ := guiVisible.Call(hwnd)
	edit, _, _ := guiGetDlgItem.Call(hwnd, 292)
	if pid == search.pid && visible != 0 && edit != 0 {
		search.dialog = hwnd
		return 0
	}
	return 1
})

func findGUIDialog(pid uint32) uintptr {
	guiSearchMu.Lock()
	defer guiSearchMu.Unlock()
	search := guiWindowSearch{pid: pid}
	guiSearch.Store(&search)
	defer guiSearch.Store(nil)
	guiEnumWindows.Call(guiEnumCallback, 0)
	return search.dialog
}

func guiMessage(hwnd, message, wparam, lparam uintptr) (uintptr, error) {
	var result uintptr
	ok, _, _ := guiSendTimeout.Call(hwnd, message, wparam, lparam, 0x0002|0x0020, 1000, uintptr(unsafe.Pointer(&result)))
	if ok == 0 {
		return 0, errors.New("bounded GUI message failed")
	}
	return result, nil
}

func guiFixedText(hwnd uintptr, expected string) bool {
	var text [128]uint16
	var pinned runtime.Pinner
	pinned.Pin(&text[0])
	defer pinned.Unpin()
	n, err := guiMessage(hwnd, 0x000D, uintptr(len(text)), uintptr(unsafe.Pointer(&text[0]))) // WM_GETTEXT
	return err == nil && n < uintptr(len(text)) && windows.UTF16ToString(text[:]) == expected
}

func guiOwnedWindow(hwnd uintptr, expectedPID uint32) bool {
	var pid uint32
	guiWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	return hwnd != 0 && pid == expectedPID
}

func enterGUI(dialog uintptr, helper windows.Handle, pass []byte, cancel bool) error {
	pid, err := windows.GetProcessId(helper)
	if err != nil {
		return err
	}
	if !guiOwnedWindow(dialog, pid) {
		return errors.New("GUI owner differs")
	}
	edit, _, _ := guiGetDlgItem.Call(dialog, 292)
	description, _, _ := guiGetDlgItem.Call(dialog, 1000)
	prompt, _, _ := guiGetDlgItem.Call(dialog, 1002)
	buttonID := uintptr(1)
	if cancel {
		buttonID = 2
	}
	button, _, _ := guiGetDlgItem.Call(dialog, buttonID)
	for _, control := range []uintptr{edit, description, prompt, button} {
		if !guiOwnedWindow(control, pid) {
			return errors.New("GUI control owner differs")
		}
	}
	enabled, _, _ := guiEnabled.Call(edit)
	mask, err := guiMessage(edit, 0x00D2, 0, 0) // EM_GETPASSWORDCHAR
	if edit == 0 || button == 0 || enabled == 0 || err != nil || mask == 0 ||
		!guiFixedText(description, "Unlock the local vault for this MCP session.") || !guiFixedText(prompt, "Vault passphrase:") {
		return errors.New("official GUI controls differ")
	}
	if !cancel {
		// The synthetic passphrase is ASCII; avoid a persistent Go string copy.
		text := make([]uint16, len(pass)+1)
		for i, b := range pass {
			text[i] = uint16(b)
		}
		defer func() {
			for i := range text {
				text[i] = 0
			}
		}()
		var pinned runtime.Pinner
		pinned.Pin(&text[0])
		if !guiOwnedWindow(edit, pid) {
			pinned.Unpin()
			return errors.New("GUI input owner changed")
		}
		result, err := guiMessage(edit, 0x000C, 0, uintptr(unsafe.Pointer(&text[0]))) // WM_SETTEXT
		pinned.Unpin()
		if err != nil || result == 0 {
			return errors.New("synthetic GUI input failed")
		}
	}
	if !guiOwnedWindow(button, pid) {
		return errors.New("GUI button owner changed")
	}
	_, err = guiMessage(button, 0x00F5, 0, 0) // BM_CLICK through the normal button.
	return err
}

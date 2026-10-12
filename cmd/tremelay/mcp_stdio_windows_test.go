//go:build windows

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/CharitonMedia/Tremelay/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/windows"
)

func windowsTestPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal("cannot create synthetic pipe")
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}

func TestWindowsMCPOwnedHandles(t *testing.T) {
	r, w := windowsTestPipe(t)
	p, err := duplicateWindowsPipe(r)
	if err != nil {
		t.Fatal("pipe duplication failed")
	}
	if p.handle == windows.Handle(r.Fd()) {
		t.Fatal("transport reused the caller's handle")
	}
	var flags uint32
	getFlags := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")
	result, _, _ := getFlags.Call(uintptr(p.handle), uintptr(unsafe.Pointer(&flags)))
	if result == 0 || flags&windows.HANDLE_FLAG_INHERIT != 0 {
		t.Fatal("owned handle is inheritable or flags could not be checked")
	}
	if err := p.Close(); err != nil {
		t.Fatal("owned handle close failed")
	}
	if err := p.Close(); err != nil {
		t.Fatal("owned close is not idempotent")
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal("owned close closed caller's reader")
	}
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil || b[0] != 'x' {
		t.Fatal("caller-owned pipe no longer works")
	}
	file, err := os.CreateTemp(t.TempDir(), "ordinary-file")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := duplicateWindowsPipe(file); !errors.Is(err, errMCPStdio) {
		t.Fatal("ordinary file admitted")
	}
	if _, err := duplicateWindowsPipe(nil); !errors.Is(err, errMCPStdio) {
		t.Fatal("nil handle admitted")
	}
	if _, err := openMCPStdio(strings.NewReader(""), io.Discard); !errors.Is(err, errMCPStdio) {
		t.Fatal("non-file streams admitted")
	}
}

// This exercises the ownership reservation state machine, without a protocol
// response, a full pipe, or a blocked output operation.
func TestWindowsMCPReservationClose(t *testing.T) {
	r, _ := windowsTestPipe(t)
	p, err := duplicateWindowsPipe(r)
	if err != nil {
		t.Fatal(errMCPStdio)
	}
	if err := p.begin(); err != nil {
		t.Fatal("reservation failed")
	}
	if err := p.begin(); err == nil {
		t.Fatal("concurrent reservation accepted")
	}
	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	deadline := time.After(2 * time.Second)
	for {
		p.mu.Lock()
		closed, released := p.closed, p.released
		p.mu.Unlock()
		if released {
			t.Fatal("native handle released before reservation joined")
		}
		if closed {
			break
		}
		select {
		case <-deadline:
			t.Fatal("close did not stop admission")
		case <-time.After(time.Millisecond):
		}
	}
	if err := p.begin(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("post-close reservation admitted")
	}
	p.end()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("reservation cleanup failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reservation cleanup did not join")
	}
}

func TestWindowsMCPReadCancellation(t *testing.T) {
	r, _ := windowsTestPipe(t)
	p, err := duplicateWindowsPipe(r)
	if err != nil {
		t.Fatal(errMCPStdio)
	}
	done := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := p.Read(b[:])
		done <- err
	}()
	// Observe the reservation so the test cannot pass solely because Close
	// won admission before Read started. This forces reserved-before-syscall
	// or pending-read interruption, without a protocol response or output.
	deadline := time.After(2 * time.Second)
	for {
		p.mu.Lock()
		busy := p.busy
		p.mu.Unlock()
		if busy {
			break
		}
		select {
		case <-deadline:
			t.Fatal("reader did not reserve its operation")
		case <-time.After(time.Millisecond):
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal("reader close failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader close did not join")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed empty reader succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not join after close")
	}
}

func TestWindowsMCPPromptDisconnect(t *testing.T) {
	for _, inputClosed := range []bool{true, false} {
		for _, buffered := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{true: "input", false: "output"}[inputClosed], map[bool]string{true: "buffered", false: "empty"}[buffered]}, "/"), func(t *testing.T) {
				in, clientWrite := windowsTestPipe(t)
				clientRead, out := windowsTestPipe(t)
				s, err := openMCPStdio(in, out)
				if err != nil {
					t.Fatal(errMCPStdio)
				}
				defer s.close()
				const pending = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n"
				if buffered {
					if _, err := io.WriteString(clientWrite, pending); err != nil {
						t.Fatal("cannot stage bounded synthetic input")
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				stop := s.watchDisconnect(cancel)
				defer stop()
				select {
				case <-ctx.Done():
					stop()
					logWindowsPipeSnapshot(t, "input", s.in)
					logWindowsPipeSnapshot(t, "output", s.out)
					t.Fatal("open native pipes were rejected or misclassified")
				case <-time.After(150 * time.Millisecond):
				}
				if inputClosed {
					clientWrite.Close()
				} else {
					clientRead.Close()
				}
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
					t.Fatal("prompt disconnect was not observed")
				}
				stop()
				if buffered {
					b := make([]byte, len(pending))
					if _, err := io.ReadFull(s.in, b); err != nil || string(b) != pending {
						t.Fatal("watcher consumed or changed protocol input")
					}
				}
			})
		}
	}
}

// Failure-only diagnostics for the synthetic prompt fixture. Do not log
// native error strings, handles, paths, quotas, or protocol/passphrase bytes.
func logWindowsPipeSnapshot(t *testing.T, direction string, p *windowsPipe) {
	t.Helper()
	if p.begin() != nil {
		t.Logf("pipe %s diagnostic reservation unavailable", direction)
		return
	}
	defer p.end()
	var info windowsPipeLocalInformation
	iosb := windows.IO_STATUS_BLOCK{Status: windows.STATUS_PENDING}
	err := windows.NtQueryInformationFile(p.handle, &iosb, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), 24)
	var status windows.NTStatus
	known := true
	if err != nil {
		status, known = err.(windows.NTStatus)
	}
	t.Logf("pipe %s nt=%08x known=%t iosb=%08x length=%d alignment_mod8=%d type=%d configuration=%d state=%d end=%d",
		direction, uint32(status), known, uint32(iosb.Status), iosb.Information,
		uintptr(unsafe.Pointer(&info))%8, info.pipeType, info.configuration, info.state, info.end)
}

func TestWindowsPinentryPrivateHelper(t *testing.T) {
	t.Setenv("TREMELAY_PASSPHRASE", randHex(t, 24))
	t.Setenv("TREMELAY_TEST_PRIVATE", randHex(t, 24))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal("cannot read test executable")
	}
	for _, tc := range []struct {
		mode string
		want error
	}{
		{"success", nil}, {"cancel", errPinentryCancelled},
		{"malformed", errPinentryFailed}, {"hang", errPinentryTimeout},
		{"exit1", errPinentryFailed}, {"eof", errPinentryFailed},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tremelay-pinentry-test-"+tc.mode+".exe")
			if err := os.WriteFile(path, binary, 0700); err != nil {
				t.Fatal("cannot copy synthetic helper")
			}
			timeout := 10 * time.Second
			if tc.mode == "hang" {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			pass, err := readPinentry(ctx, pinentryOptions{path: path})
			defer vault.Wipe(pass)
			if !errors.Is(err, tc.want) || (err == nil && len(pass) != 24) || (err != nil && pass != nil) {
				t.Fatal("unexpected synthetic helper result")
			}
			// A running Windows image cannot be replaced this way. The parent
			// must have waited for the helper before reporting its result.
			if err := os.WriteFile(path, []byte("retired synthetic helper"), 0700); err != nil {
				t.Fatal("helper executable remained in use after return")
			}
		})
	}
}

func TestWindowsPinentryScope(t *testing.T) {
	for _, path := range []string{"helper.exe", `C:helper.exe`, `\\server\share\helper.exe`, `\\?\C:\helper.exe`, `C:\helper.cmd`, `C:\helper.exe:stream`} {
		if validPinentryExecutable(path) {
			t.Fatal("unsupported helper path accepted")
		}
	}
	if restore, _, err := pinentryTerminal(`C:\terminal`); err == nil || restore != nil {
		t.Fatal("unsupported terminal selection accepted")
	}
	cmd := exec.Command(filepath.Join(t.TempDir(), "helper.exe"))
	configurePinentry(cmd)
	if cmd.Dir != filepath.Dir(cmd.Path) || cmd.SysProcAttr == nil || cmd.SysProcAttr.CreationFlags != windows.CREATE_NO_WINDOW {
		t.Fatal("helper working directory or window policy changed")
	}
	for _, entry := range cmd.Env {
		key, _, _ := strings.Cut(entry, "=")
		if key != "LANG" && key != "LC_CTYPE" && key != "LC_MESSAGES" {
			t.Fatal("unexpected helper environment")
		}
	}
}

func TestWindowsPinentryConsoleRestoration(t *testing.T) {
	if os.Getenv("TREMELAY_TEST_WINDOWS_CONSOLE") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestWindowsPinentryConsoleRestoration$")
		cmd.Env = append(os.Environ(), "TREMELAY_TEST_WINDOWS_CONSOLE=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
		if err := cmd.Run(); err != nil {
			t.Fatal("isolated synthetic console restoration failed")
		}
		return
	}
	restore, tty, err := pinentryTerminal("")
	if err != nil || tty != "" {
		t.Fatal("console capture failed")
	}
	defer restore()
	p, _ := windows.UTF16PtrFromString("CONIN$")
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal("isolated console unavailable")
	}
	defer windows.CloseHandle(h)
	var before, after uint32
	if windows.GetConsoleMode(h, &before) != nil || windows.SetConsoleMode(h, before^windows.ENABLE_ECHO_INPUT) != nil {
		t.Fatal("cannot change synthetic console mode")
	}
	if restore() != nil || windows.GetConsoleMode(h, &after) != nil || after != before {
		t.Fatal("console mode was not restored")
	}
}

// Real Windows anonymous pipes carry an ordinary official-SDK session. This
// is transport coverage, not a claim of subprocess unlock or named-client UI
// integration. Credential authorization/audit stay in the existing endpoint.
func TestWindowsMCPNativeTransportFlow(t *testing.T) {
	pass := randBytes(t, 24)
	defer vault.Wipe(pass)
	session, err := vault.Create(filepath.Join(t.TempDir(), "vault.db"), pass, nil)
	if err != nil {
		t.Fatal("synthetic vault create failed")
	}
	defer session.Lock()
	agent, err := session.CreateAgent("synthetic-windows-transport")
	if err != nil {
		t.Fatal("synthetic agent create failed")
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal("synthetic principal bind failed")
	}
	capability, err := vault.BindAgentCapability(principal)
	if err != nil {
		t.Fatal("synthetic capability bind failed")
	}
	endpoint, err := vault.BindStdioMCPEndpoint(capability)
	if err != nil {
		t.Fatal("synthetic endpoint bind failed")
	}
	in, clientWrite := windowsTestPipe(t)
	clientRead, out := windowsTestPipe(t)
	server, err := openMCPStdio(in, out)
	if err != nil {
		t.Fatal(errMCPStdio)
	}
	clientPipes, err := openMCPStdio(clientRead, clientWrite)
	if err != nil {
		server.close()
		t.Fatal(errMCPStdio)
	}
	// The fixture owns the originals. Remove aliases so ordinary client
	// closure really is EOF, not a close hidden by another fixture handle.
	in.Close()
	out.Close()
	clientRead.Close()
	clientWrite.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	joined := false
	go func() { done <- endpoint.Serve(ctx, server.in, server.out) }()
	defer func() {
		cancel()
		clientPipes.close()
		server.close()
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("normal native transport did not join")
			}
		}
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "synthetic-windows-client", Version: "1"}, &mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	peer, err := client.Connect(ctx, &mcp.IOTransport{Reader: clientPipes.in, Writer: clientPipes.out}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatal("official client initialization failed")
	}
	defer peer.Close()
	list, err := peer.ListTools(ctx, nil)
	if err != nil {
		t.Fatal("official client discovery failed")
	}
	foundCatalogue := false
	for _, tool := range list.Tools {
		if tool.Name == "list_capabilities" {
			foundCatalogue = true
		}
	}
	if !foundCatalogue {
		t.Fatal("official client did not discover the catalogue")
	}
	result, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "list_capabilities", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatal("official client catalogue request failed")
	}
	if err := peer.Close(); err != nil {
		t.Fatal("official client close failed")
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("normal client close failed at server")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("normal client close did not stop server")
	}
}

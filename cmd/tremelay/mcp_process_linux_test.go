//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
	"golang.org/x/sys/unix"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestMCPProcessHelper(t *testing.T) {
	if os.Getenv("TREMELAY_TEST_MCP_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			args := os.Args[i+1:]
			// Only this test binary selects the optional record, and only for
			// the exact command/flag layout used by the cancellation fixture.
			if os.Getenv("TREMELAY_TEST_MCP_OBSERVE") == "1" && len(args) == 12 &&
				args[0] == "mcp" && args[1] == "serve" && args[2] == "--path" &&
				args[4] == "--agent" && args[6] == "--pinentry" && args[7] == "/usr/bin/pinentry-curses" &&
				args[8] == "--pinentry-tty" && args[10] == "--unlock-timeout" {
				var observation pinentryObservation
				code := cmdMCPObserved(args[1:], os.Stdin, os.Stdout, os.Stderr, &observation)
				// cmdMCP cleanup has finished. Numeric enum metadata cannot
				// contain or satisfy any expected public error diagnostic.
				fmt.Fprintf(os.Stderr, "MCP_OBSERVATION phase=%d outcome=%d classification=%d after_watch=%d reap=%d kill_attempted=%t restore=%d\n",
					observation.phase, observation.outcome, observation.classification, observation.afterWatch,
					observation.reap, observation.killAttempted, observation.restore)
				os.Exit(code)
			}
			os.Exit(run(args, func(string) string { panic("MCP consulted getenv") }, os.Stdin, os.Stdout, os.Stderr))
		}
	}
	os.Exit(99)
}

type mcpProcess struct {
	cmd                          *exec.Cmd
	input, output, master, slave *os.File
	initial                      *unix.Termios
	diag, ui                     *lifecycleOutput
	done                         chan struct{}
	uiDone                       chan struct{}
	path, pass                   string
}

func startMCPProcess(t *testing.T, timeout string, blockedOutput bool) *mcpProcess {
	t.Helper()
	return startMCPProcessWithGrants(t, timeout, blockedOutput, 0)
}

func startMCPProcessWithGrants(t *testing.T, timeout string, blockedOutput bool, grants int) *mcpProcess {
	return startMCPProcessWithObservation(t, timeout, blockedOutput, grants, false)
}

func startMCPProcessWithObservation(t *testing.T, timeout string, blockedOutput bool, grants int, observe bool) *mcpProcess {
	t.Helper()
	const pinentry = "/usr/bin/pinentry-curses"
	if _, err := os.Stat(pinentry); err != nil {
		t.Skip("official pinentry-curses not installed; Linux PTY process check unavailable")
	}
	path, pass := filepath.Join(t.TempDir(), "vault.db"), randHex(t, 24)
	session, err := vault.Create(path, []byte(pass), nil)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := session.CreateAgent("synthetic-mcp-process")
	if err != nil {
		t.Fatal(err)
	}
	if grants > 0 {
		seed := randBytes(t, ed25519.SeedSize)
		key := ed25519.NewKeyFromSeed(seed)
		vault.Wipe(seed)
		der, err := x509.MarshalPKCS8PrivateKey(key)
		vault.Wipe(key)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.Put("synthetic process key", "ed25519", der, vault.PutOptions{})
		vault.Wipe(der)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < grants; i++ {
			_, err := session.IssueGrant(vault.GrantSpec{
				AgentID: agent.ID, CredentialID: credential.ID,
				Operations: []string{vault.OpLocalArtifactAttest},
				Resource:   fmt.Sprintf("synthetic-blocked-output-capability-%04d", i),
				ExpiresAt:  time.Now().Add(time.Hour).UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	session.Lock()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "mcp-pty-master")
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	tty := fmt.Sprintf("/dev/pts/%d", n)
	slave, err := os.OpenFile(tty, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	initial, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	serverInput, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close() })
	output, serverOutput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { output.Close() })
	if grants > 0 {
		// The catalogue response is much larger than this pipe. Observing a
		// response prefix then an unconsumed full page proves Write has begun
		// but cannot return, without sleeping to guess SDK dispatch timing.
		raw, err := serverOutput.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var size int
		var resizeErr error
		if err := raw.Control(func(fd uintptr) { size, resizeErr = unix.FcntlInt(fd, unix.F_SETPIPE_SZ, 4096) }); err != nil || resizeErr != nil || size != 4096 {
			t.Fatalf("set bounded stdout capacity: %v, %v", err, resizeErr)
		}
	}
	if blockedOutput {
		// Fill the actual inherited stdout pipe, without a Go writer wrapper.
		// The endpoint's first response must block until Close interrupts it.
		raw, err := serverOutput.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		if err := raw.Control(func(fd uintptr) {
			for {
				_, e := unix.Write(int(fd), make([]byte, 4096))
				if e == unix.EAGAIN {
					return
				}
				if e != nil {
					t.Errorf("fill stdout pipe: %v", e)
					return
				}
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	args := []string{"-test.run=^TestMCPProcessHelper$", "--", "mcp", "serve", "--path", path, "--agent", agent.ID, "--pinentry", pinentry, "--pinentry-tty", tty, "--unlock-timeout", timeout}
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TREMELAY_PASSPHRASE=") && !strings.HasPrefix(entry, "TREMELAY_TEST_MCP_PROCESS=") &&
			!strings.HasPrefix(entry, "TREMELAY_TEST_MCP_OBSERVE=") && !strings.HasPrefix(entry, "TERM=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "TREMELAY_TEST_MCP_PROCESS=1", "TERM=xterm")
	if observe {
		cmd.Env = append(cmd.Env, "TREMELAY_TEST_MCP_OBSERVE=1")
	}
	diag, ui := &lifecycleOutput{}, &lifecycleOutput{}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = serverInput, serverOutput, diag
	// A real foreground terminal delivers Ctrl-C to the process group. Keep
	// MCP on fd 0/1 while this synthetic controlling terminal is child fd 3.
	cmd.ExtraFiles = []*os.File{slave}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	serverInput.Close()
	serverOutput.Close()
	p := &mcpProcess{cmd: cmd, input: input, output: output, master: master, slave: slave, initial: initial, diag: diag, ui: ui, done: make(chan struct{}), uiDone: make(chan struct{}), path: path, pass: pass}
	go func() { _ = cmd.Wait(); close(p.done) }()
	go func() { defer close(p.uiDone); _, _ = io.Copy(ui, master) }()
	t.Cleanup(func() { master.Close(); <-p.uiDone })
	t.Cleanup(func() {
		select {
		case <-p.done:
			return
		default:
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

func (p *mcpProcess) prompt(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		state, err := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if state.Lflag&unix.ECHO == 0 && strings.Contains(p.ui.String(), "Vault passphrase") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pinentry did not display a no-echo prompt")
}

func (p *mcpProcess) unlock(t *testing.T) {
	t.Helper()
	p.prompt(t)
	if _, err := p.master.Write([]byte(p.pass + "\r")); err != nil {
		t.Fatal(err)
	}
}

func (p *mcpProcess) finish(t *testing.T, want int, message string) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		t.Fatal("MCP child failed to settle")
	}
	if p.cmd.ProcessState.ExitCode() != want || (message != "" && !strings.Contains(p.diag.String(), message)) {
		t.Fatalf("MCP child exit %d: %s", p.cmd.ProcessState.ExitCode(), p.diag.String())
	}
	state, err := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
	if err != nil || !reflect.DeepEqual(state, p.initial) {
		t.Fatalf("pinentry terminal state not restored: %v", err)
	}
	if strings.Contains(p.diag.String()+p.ui.String(), p.pass) {
		t.Fatal("pinentry disclosed synthetic passphrase")
	}
	if _, err := vault.VerifyAudit(p.path, []byte(p.pass)); err != nil {
		t.Fatalf("audit not valid after process cleanup: %v", err)
	}
}

func TestMCPProcessPromptCancellation(t *testing.T) {
	version, versionState := mcpPinentryVersionObservation()
	t.Logf("MCP_OBSERVATION version_state=%d version=%s", versionState, version)
	for _, reason := range []string{"SIGINT", "SIGTERM", "ctrl-c", "EOF", "output-closed", "timeout"} {
		t.Run(reason, func(t *testing.T) {
			timeout := "10s"
			if reason == "timeout" {
				timeout = "1s"
			}
			p := startMCPProcessWithObservation(t, timeout, false, 0, true)
			p.prompt(t)
			before, err := os.ReadFile(p.path)
			if err != nil {
				t.Fatal(err)
			}
			message := "pinentry cancelled"
			switch reason {
			case "SIGINT":
				err = p.cmd.Process.Signal(syscall.SIGINT)
			case "SIGTERM":
				err = p.cmd.Process.Signal(syscall.SIGTERM)
			case "ctrl-c":
				state, stateErr := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
				// The parent does not own the slave as its controlling tty.
				// Query through the PTY master, preserving its pollable mode.
				var foreground int
				var foregroundErr error
				raw, rawErr := p.master.SyscallConn()
				if rawErr == nil {
					rawErr = raw.Control(func(fd uintptr) {
						foreground, foregroundErr = unix.IoctlGetInt(int(fd), unix.TIOCGPGRP)
					})
				}
				foregroundRead := rawErr == nil && foregroundErr == nil
				group, groupErr := unix.Getpgid(p.cmd.Process.Pid)
				t.Logf("MCP_OBSERVATION termios_read=%t isig=%t vintr_three=%t foreground_read=%t process_group_read=%t foreground_matches=%t",
					stateErr == nil, stateErr == nil && state.Lflag&unix.ISIG != 0, stateErr == nil && state.Cc[unix.VINTR] == 3,
					foregroundRead, groupErr == nil, foregroundRead && groupErr == nil && foreground == group)
				_, err = p.master.Write([]byte{3})
			case "EOF":
				err = p.input.Close()
			case "output-closed":
				err = p.output.Close()
			case "timeout":
				message = "pinentry unlock timed out"
			}
			if err != nil {
				t.Fatal(err)
			}
			p.finish(t, 1, "")
			after, err := os.ReadFile(p.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("prompt cancellation changed vault")
			}
			// Assert only the public diagnostic line, independently of the
			// numeric observation appended by the test subprocess after cleanup.
			publicDiagnostic, _, _ := strings.Cut(p.diag.String(), "\n")
			if publicDiagnostic != message {
				t.Fatalf("unexpected prompt diagnostic: %s", p.diag.String())
			}
		})
	}
}

// Read only the fixed official helper's version. Raw output is bounded, wiped,
// and never logged; the caller sees a numeric version or a fixed state enum.
// States: 1 valid, 2 timeout, 3 process failure, 4 output limit, 5 invalid format.
func mcpPinentryVersionObservation() (string, uint8) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var output mcpVersionOutput
	defer vault.Wipe(output.data[:])
	cmd := exec.CommandContext(ctx, "/usr/bin/pinentry-curses", "--version")
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	cmd.WaitDelay = 100 * time.Millisecond
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", 2
	}
	if output.overflow {
		return "", 4
	}
	if err != nil {
		return "", 3
	}
	line, _, _ := bytes.Cut(output.data[:output.used], []byte{'\n'})
	version, ok := bytes.CutPrefix(line, []byte("pinentry-curses (pinentry) "))
	if !ok || len(version) == 0 || len(version) > 32 {
		return "", 5
	}
	dots, digits := 0, 0
	for _, ch := range version {
		if ch == '.' && digits > 0 {
			dots++
			digits = 0
		} else if ch >= '0' && ch <= '9' {
			digits++
		} else {
			return "", 5
		}
	}
	if dots != 2 || digits == 0 {
		return "", 5
	}
	return string(version), 1
}

type mcpVersionOutput struct {
	data     [1024]byte
	used     int
	overflow bool
}

func (w *mcpVersionOutput) Write(p []byte) (int, error) {
	n := copy(w.data[w.used:], p)
	w.used += n
	if n != len(p) {
		w.overflow = true
		return n, io.ErrShortBuffer
	}
	return n, nil
}

func TestMCPProcessEOFAndBrokenOutput(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("broken=%t", broken), func(t *testing.T) {
			p := startMCPProcess(t, "10s", false)
			p.unlock(t)
			if _, err := io.WriteString(p.input, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}}`+"\n"); err != nil {
				t.Fatal(err)
			}
			if err := p.output.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(p.output).ReadBytes('\n')
			if err != nil {
				t.Fatalf("initialize response missing: %v", err)
			}
			if bytes.Contains(line, []byte(p.pass)) {
				t.Fatal("MCP output disclosed synthetic passphrase")
			}
			var envelope struct {
				Result struct {
					ProtocolVersion string `json:"protocolVersion"`
				} `json:"result"`
			}
			if json.Unmarshal(line, &envelope) != nil || envelope.Result.ProtocolVersion != "2025-11-25" {
				t.Fatal("unexpected MCP initialize response")
			}
			if broken {
				p.output.Close()
				// Rejected invocation still requires an audit before its failed
				// output. SIGPIPE must not kill the process before that cleanup.
				_, _ = io.WriteString(p.input, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"invoke_capability","arguments":{}}}`+"\n")
				p.finish(t, 1, "mcp session failed")
			} else {
				p.input.Close()
				select {
				case <-p.done:
				case <-time.After(10 * time.Second):
					t.Fatal("abrupt EOF did not settle the MCP child")
				}
				code := p.cmd.ProcessState.ExitCode()
				wantDiagnostic := ""
				if code == 1 {
					wantDiagnostic = "mcp session failed; inspect the vault audit before retrying an operation\n"
				} else if code != 0 {
					t.Fatalf("abrupt EOF did not exit normally: %d", code)
				}
				if p.diag.String() != wantDiagnostic {
					t.Fatal("abrupt EOF returned an unexpected diagnostic")
				}
				p.finish(t, code, "")
			}
		})
	}
}

func TestMCPProcessWrongPassphrase(t *testing.T) {
	p := startMCPProcess(t, "10s", false)
	p.prompt(t)
	wrong := randHex(t, 24)
	if _, err := p.master.Write([]byte(wrong + "\r")); err != nil {
		t.Fatal(err)
	}
	p.finish(t, 1, "vault unlock failed")
	output, err := io.ReadAll(p.output)
	if err != nil || len(output) != 0 || strings.Contains(p.diag.String()+p.ui.String(), wrong) {
		t.Fatal("failed unlock produced output or disclosed the entered value")
	}
	db, err := sql.Open("sqlite", p.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var denied int
	if err := db.QueryRow(`SELECT count(*) FROM audit WHERE action='vault_unlock' AND result='denied'`).Scan(&denied); err != nil || denied != 1 {
		t.Fatalf("wrong passphrase denial not audited: count %d, error %v", denied, err)
	}
}

func TestMCPProcessBlockedOutputCancellation(t *testing.T) {
	p := startMCPProcess(t, "10s", true)
	p.unlock(t)
	_, err := io.WriteString(p.input, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"invoke_capability","arguments":{}}}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	observer, err := openMCPAuditObserver(p.path)
	if err != nil {
		t.Fatal(err)
	}
	err = waitMCPDeniedAudit(context.Background(), observer)
	closeErr := observer.Close() // Release every observer connection before SIGTERM.
	if err != nil || closeErr != nil {
		t.Fatalf("observe committed blocked-output denial: %v; close: %v", err, closeErr)
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	p.finish(t, 1, "mcp session cancelled")
	// The live observer never retries an operation. One submitted malformed
	// invocation must still leave exactly one denial after process cleanup.
	observer, err = openMCPAuditObserver(p.path)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var denied int
	if err := observer.QueryRowContext(ctx, mcpDeniedAuditQuery).Scan(&denied); err != nil || denied != 1 {
		t.Fatalf("post-exit denial count %d, error %v", denied, err)
	}
}

const mcpDeniedAuditQuery = `SELECT count(*) FROM audit WHERE action='local_attest' AND result='denied'`

// This test observer must not create a vault, mutate it, or hold an unbounded
// read while the child commits an audit row in SQLite's DELETE journal mode.
func openMCPAuditObserver(path string) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	q := url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(50)", "query_only(ON)"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func waitMCPDeniedAudit(parent context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var denied int
		err := db.QueryRowContext(ctx, mcpDeniedAuditQuery).Scan(&denied)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			if denied == 1 {
				return nil
			}
			if denied != 0 {
				return errors.New("denial audit count is not exactly one")
			}
		} else {
			var driverErr *sqlite.Error
			// Only primary SQLITE_BUSY (including its extended codes) is a
			// transient reader/writer conflict. Do not hide LOCKED or other errors.
			if !errors.As(err, &driverErr) || driverErr.Code()&0xff != sqlite3.SQLITE_BUSY {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func TestMCPAuditObserverLockBounds(t *testing.T) {
	for _, release := range []bool{true, false} {
		t.Run(fmt.Sprintf("release=%t", release), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observer.db")
			writer, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			writer.SetMaxOpenConns(1)
			if _, err := writer.Exec(`CREATE TABLE audit(action TEXT, result TEXT); INSERT INTO audit VALUES('local_attest','denied')`); err != nil {
				t.Fatal(err)
			}
			observer, err := openMCPAuditObserver(path)
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close()
			var queryOnly, busyTimeout int
			if err := observer.QueryRow(`PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly != 1 {
				t.Fatalf("query-only observer: %d, %v", queryOnly, err)
			}
			if err := observer.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil || busyTimeout != 50 || observer.Stats().MaxOpenConnections != 1 {
				t.Fatalf("bounded single observer: timeout %d, %v", busyTimeout, err)
			}
			if _, err := writer.Exec(`BEGIN EXCLUSIVE`); err != nil {
				t.Fatal(err)
			}
			defer writer.Exec(`ROLLBACK`)
			// Establish an actual BUSY read against the held exclusive lock,
			// rather than relying only on timing to guess a lock was observed.
			var count int
			err = observer.QueryRow(mcpDeniedAuditQuery).Scan(&count)
			var driverErr *sqlite.Error
			if !errors.As(err, &driverErr) || driverErr.Code()&0xff != sqlite3.SQLITE_BUSY {
				t.Fatalf("fixture did not produce SQLITE_BUSY: %v", err)
			}
			timeout := 200 * time.Millisecond
			if release {
				timeout = 2 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- waitMCPDeniedAudit(ctx, observer) }()
			if release {
				select {
				case err := <-done:
					t.Fatalf("observer finished while writer lock was held: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
				if _, err := writer.Exec(`ROLLBACK`); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if (release && err != nil) || (!release && !errors.Is(err, context.DeadlineExceeded)) {
					t.Fatalf("unexpected bounded observer result: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("observer outlived its context deadline")
			}
		})
	}
}

func TestMCPAuditObserverRejectsUnexpectedStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observer.db")
	writer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Exec(`CREATE TABLE audit(action TEXT, result TEXT); INSERT INTO audit VALUES('local_attest','denied'),('local_attest','denied')`); err != nil {
		t.Fatal(err)
	}
	observer, err := openMCPAuditObserver(path)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := waitMCPDeniedAudit(ctx, observer); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("multiple denials did not fail immediately: %v", err)
	}
	_, err = observer.ExecContext(ctx, `DELETE FROM audit`)
	var driverErr *sqlite.Error
	if !errors.As(err, &driverErr) || driverErr.Code()&0xff != sqlite3.SQLITE_READONLY {
		t.Fatalf("observer write did not fail read-only: %v", err)
	}
	var count, queryOnly int
	if err := observer.QueryRowContext(ctx, mcpDeniedAuditQuery).Scan(&count); err != nil || count != 2 {
		t.Fatalf("observer write changed audit rows: count %d, %v", count, err)
	}
	if err := observer.QueryRowContext(ctx, `PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly != 1 {
		t.Fatalf("observer lost query-only restriction: %d, %v", queryOnly, err)
	}
	if _, err := writer.ExecContext(ctx, `DROP TABLE audit`); err != nil {
		t.Fatal(err)
	}
	err = waitMCPDeniedAudit(ctx, observer)
	if !errors.As(err, &driverErr) || driverErr.Code()&0xff != sqlite3.SQLITE_ERROR {
		t.Fatalf("non-BUSY SQL error was not propagated: %v", err)
	}
}

func TestMCPProcessAdmittedBlockedOutputEOF(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial-frame=%t", partial), func(t *testing.T) {
			p := startMCPProcessWithGrants(t, "10s", false, 32)
			p.unlock(t)
			if _, err := io.WriteString(p.input, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}}`+"\n"); err != nil {
				t.Fatal(err)
			}
			if err := p.output.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(p.output)
			line, err := reader.ReadBytes('\n')
			if err != nil || !bytes.Contains(line, []byte(`"protocolVersion":"2025-11-25"`)) {
				t.Fatal("initialize response missing")
			}
			if _, err := io.WriteString(p.input, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"+`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_capabilities","arguments":{}}}`+"\n"); err != nil {
				t.Fatal(err)
			}
			// Read directly, avoiding bufio read-ahead that could drain the
			// kernel pipe and unintentionally release its blocked writer.
			var prefix [128]byte
			if _, err := io.ReadFull(p.output, prefix[:]); err != nil || !bytes.Contains(prefix[:], []byte(`"id":2`)) || !bytes.Contains(prefix[:], []byte(`"result":`)) {
				t.Fatal("admitted catalogue response did not begin")
			}
			raw, err := p.output.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				var queued int
				var queryErr error
				if err := raw.Control(func(fd uintptr) { queued, queryErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ) }); err != nil || queryErr != nil {
					t.Fatalf("inspect stdout backlog: %v, %v", err, queryErr)
				}
				if queued == 4096-len(prefix) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("actual admitted response did not fill stdout")
				}
				time.Sleep(time.Millisecond)
			}
			// The 32-entry catalogue exceeds the single pipe page. Its prefix
			// is delivered, the rest of that page is still queued, and further
			// response bytes cannot fit. No cancellation signal is sent below.
			if partial {
				// Complete JSON without its NDJSON delimiter yields the ordinary
				// terminal read error io.ErrUnexpectedEOF and needs its own denial.
				if _, err := io.WriteString(p.input, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"invoke_capability","arguments":{}}}`); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.input.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-p.done:
			case <-time.After(4 * time.Second):
				t.Fatal("EOF did not release the blocked admitted response without a signal")
			}
			code := p.cmd.ProcessState.ExitCode()
			if code != 0 && code != 1 {
				t.Fatalf("MCP process did not exit normally: %d", code)
			}
			p.finish(t, code, "") // Also checks terminal restoration and audit integrity.
			db, err := sql.Open("sqlite", p.path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var listed, denied int
			if err := db.QueryRow(`SELECT count(*) FROM audit WHERE action='capability_list' AND result='allowed'`).Scan(&listed); err != nil || listed != 1 {
				t.Fatalf("admitted catalogue was not audited exactly once: count %d, error %v", listed, err)
			}
			if err := db.QueryRow(`SELECT count(*) FROM audit WHERE action='local_attest' AND result='denied'`).Scan(&denied); err != nil || denied != map[bool]int{false: 0, true: 1}[partial] {
				t.Fatalf("partial-frame denial count %d, error %v", denied, err)
			}
		})
	}
}

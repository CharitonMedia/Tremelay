//go:build linux

package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
	"golang.org/x/sys/unix"
)

// This subprocess runs the actual command dispatch and signal handling.
// Only a test-mode marker, never a passphrase, is supplied in its environment.
func TestLifecycleProcessHelper(t *testing.T) {
	if os.Getenv("TREMELAY_TEST_CLI_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Exit(run(os.Args[i+1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
		}
	}
	os.Exit(99)
}

type lifecycleOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lifecycleOutput) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(b)
}
func (w *lifecycleOutput) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }

type lifecycleProcess struct {
	cmd            *exec.Cmd
	master, slave  *os.File
	initial        *unix.Termios
	stderr, stdout *lifecycleOutput
	done           chan error
}

func startLifecycleProcess(t *testing.T, args []string, brokenOutput bool) *lifecycleProcess {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "pty-master")
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	initial, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestLifecycleProcessHelper$", "--"}, args...)...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TREMELAY_PASSPHRASE=") && !strings.HasPrefix(entry, "TREMELAY_TEST_CLI_HELPER=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "TREMELAY_TEST_CLI_HELPER=1")
	out, diag := &lifecycleOutput{}, &lifecycleOutput{}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, out, diag
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if brokenOutput {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		cmd.Stdout = w
		t.Cleanup(func() { w.Close() })
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &lifecycleProcess{cmd: cmd, master: master, slave: slave, initial: initial, stdout: out, stderr: diag, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	return p
}

func (p *lifecycleProcess) prompt(t *testing.T, prompt string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state, err := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(p.stderr.String(), prompt) && state.Lflag&unix.ECHO == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("prompt did not arrive with echo disabled: %q", prompt)
}

func (p *lifecycleProcess) input(t *testing.T, input []byte) {
	t.Helper()
	if _, err := p.master.Write(input); err != nil {
		t.Fatal(err)
	}
}

func (p *lifecycleProcess) finish(t *testing.T, want int, secrets ...string) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(16 * time.Second):
		t.Fatal("child did not finish")
	}
	if p.cmd.ProcessState.ExitCode() != want {
		t.Fatalf("child exit %d: %s", p.cmd.ProcessState.ExitCode(), p.stderr.String())
	}
	state, err := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
	if err != nil || !reflect.DeepEqual(state, p.initial) {
		t.Fatalf("terminal state not restored: %v", err)
	}
	for _, secret := range secrets {
		if strings.Contains(p.stdout.String()+p.stderr.String(), secret) {
			t.Fatal("subprocess disclosed input")
		}
	}
}

func TestLifecycleProcessCancellation(t *testing.T) {
	for _, interruption := range []string{"ctrl-c", "SIGINT", "SIGTERM"} {
		for stage := 0; stage < 3; stage++ {
			t.Run(fmt.Sprintf("%s/prompt%d", interruption, stage), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "vault.db")
				old, next := randHex(t, 24), randHex(t, 24)
				s, err := vault.Create(path, []byte(old), nil)
				if err != nil {
					t.Fatal(err)
				}
				s.Lock()
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				p := startLifecycleProcess(t, []string{"vault", "change-passphrase", "--path", path}, false)
				prompts := []string{"old passphrase: ", "new passphrase: ", "confirm new passphrase: "}
				answers := []string{old, next}
				for i := 0; i <= stage; i++ {
					p.prompt(t, prompts[i])
					if i < stage {
						p.input(t, []byte(answers[i]+"\n"))
					}
				}
				partial := randHex(t, 12)
				p.input(t, []byte(partial))
				if interruption == "ctrl-c" {
					p.input(t, []byte{3})
				} else {
					sig := syscall.SIGINT
					if interruption == "SIGTERM" {
						sig = syscall.SIGTERM
					}
					if err := p.cmd.Process.Signal(sig); err != nil {
						t.Fatal(err)
					}
				}
				p.finish(t, 1, old, next, partial)
				if _, err := vault.VerifyAudit(path, []byte(old)); err != nil {
					t.Fatal(err)
				}
				if _, err := vault.VerifyAudit(path, []byte(next)); err == nil {
					t.Fatal("cancellation granted replacement authority")
				}
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				var denied, allowed int
				if err := db.QueryRow(`SELECT count(*) FROM audit WHERE action='vault_passphrase_change' AND result='denied'`).Scan(&denied); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow(`SELECT count(*) FROM audit WHERE action='vault_passphrase_change' AND result='allowed'`).Scan(&allowed); err != nil {
					t.Fatal(err)
				}
				wantDenied := 1
				if stage == 0 {
					wantDenied = 0
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("old-prompt cancellation changed vault")
					}
				}
				if denied != wantDenied || allowed != 0 {
					t.Fatalf("unexpected change audit: denied=%d allowed=%d", denied, allowed)
				}
			})
		}
	}
}

func TestLifecycleProcessBrokenStdout(t *testing.T) {
	for _, operation := range []string{"backup", "restore", "change-passphrase"} {
		t.Run(operation, func(t *testing.T) {
			source, pass, _ := backupCLIVault(t)
			target := filepath.Join(backupCLITemp(t), "destination.db")
			args := []string{"vault", "backup", "--path", source, "--output", target}
			want, warning := 1, "artifact created but checkpoint output failed"
			if operation == "restore" {
				artifact, cp := backupCLIArtifact(t, source, pass)
				args = []string{"vault", "restore", "--input", artifact, "--path", target, "--checkpoint-file", cp}
				want, warning = 3, "vault restored but confirmation output failed"
			}
			if operation == "change-passphrase" {
				args = []string{"vault", "change-passphrase", "--path", source}
				warning = "passphrase changed; confirmation output failed"
			}
			p := startLifecycleProcess(t, args, true)
			next := randHex(t, 24)
			if operation == "change-passphrase" {
				p.prompt(t, "old passphrase: ")
				p.input(t, []byte(pass+"\n"))
				p.prompt(t, "new passphrase: ")
				p.input(t, []byte(next+"\n"))
				p.prompt(t, "confirm new passphrase: ")
				p.input(t, []byte(next+"\n"))
			} else {
				p.prompt(t, "passphrase: ")
				p.input(t, []byte(pass+"\n"))
			}
			p.finish(t, want, pass, next)
			if !strings.Contains(p.stderr.String(), warning) {
				t.Fatalf("missing committed-outcome warning: %s", p.stderr.String())
			}
			if operation == "change-passphrase" {
				target, pass = source, next
			}
			if _, err := vault.VerifyAudit(target, []byte(pass)); err != nil {
				t.Fatalf("committed target missing: %v", err)
			}
		})
	}
}

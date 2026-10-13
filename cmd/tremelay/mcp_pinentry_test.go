package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPinentryReply(t *testing.T) {
	for _, tc := range []struct {
		name, wire, want string
		data             bool
		wantErr          error
	}{
		{"greeting", "OK hello\n", "", false, nil},
		{"escape", "S fixed status\n# comment\nD abc%25%0A%0d%00%ff\nD tail\nOK\n", "abc%\n\r\x00\xfftail", true, nil},
		{"limit", "D " + strings.Repeat("%ff", 1024) + "\r\nOK\r\n", strings.Repeat("\xff", 1024), true, nil},
		{"split-limit", "D " + strings.Repeat("a", 512) + "\nD " + strings.Repeat("b", 512) + "\nOK\n", strings.Repeat("a", 512) + strings.Repeat("b", 512), true, nil},
		{"too-long", "D " + strings.Repeat("a", 1025) + "\nOK\n", "", true, errPinentryFailed},
		{"split-too-long", "D " + strings.Repeat("a", 1024) + "\nD b\nOK\n", "", true, errPinentryFailed},
		{"wire-limit", strings.Repeat("S "+strings.Repeat("x", 3000)+"\n", 6) + "OK\n", "", true, errPinentryFailed},
		{"line-limit", "S " + strings.Repeat("x", maxPinentryLine) + "\nOK\n", "", true, errPinentryFailed},
		{"line-count", strings.Repeat("#\n", 64) + "OK\n", "", true, errPinentryFailed},
		{"bad-escape", "D text%xx\nOK\n", "", true, errPinentryFailed},
		{"short-escape", "D text%0\nOK\n", "", true, errPinentryFailed},
		{"unexpected-data", "D hidden\nOK\n", "", false, errPinentryFailed},
		{"inquire", "INQUIRE QUALITY hidden\n", "", true, errPinentryFailed},
		{"cancel", "D partial\nERR 83886179 ignored\n", "", true, errPinentryCancelled},
		{"fully-cancelled", "D partial\nERR 83886278 ignored\n", "", true, errPinentryCancelled},
		{"code-277-is-failure", "ERR 83886357 ignored\n", "", true, errPinentryFailed},
		{"timeout", "ERR 83886142 ignored\n", "", true, errPinentryTimeout},
		{"error-text", "ERR 1 synthetic-private-diagnostic\n", "", true, errPinentryFailed},
		{"no-newline", "D incomplete", "", true, errPinentryFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pinentryProtocol{reader: strings.NewReader(tc.wire)}
			got, err := p.reply(tc.data)
			if !errors.Is(err, tc.wantErr) || string(got) != tc.want {
				t.Fatalf("unexpected reply result: length %d, error %v", len(got), err)
			}
			if err != nil && got != nil {
				t.Fatal("failed reply returned data")
			}
		})
	}
}

func TestCLIMCPFixedArgumentsAndNoEnvironmentPassphrase(t *testing.T) {
	sentinel := randHex(t, 24)
	for _, args := range [][]string{
		{}, {"serve"}, {"serve", "--passphrase", sentinel},
		{"serve", "--path", "vault", "--agent", "agent", "--pinentry", "relative"},
		{"serve", "--path", "vault", "--agent", "agent", "--pinentry", filepath.Join(t.TempDir(), "helper"), "--unlock-timeout", "6m"},
		{"serve", "--path", "vault", "--agent", "agent", "--pinentry", filepath.Join(t.TempDir(), "helper"), "--pinentry-tty", "/dev/tty\n" + sentinel},
	} {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"mcp"}, args...), func(string) string {
			t.Fatal("MCP consulted an environment passphrase source")
			return sentinel
		}, strings.NewReader(sentinel), &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 || stderr.String() != mcpServeUsage+"\n" {
			t.Fatal("MCP argument failure was not fixed and stdout-free")
		}
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"mcp", "serve", "--path", "vault", "--agent", "agent", "--pinentry", filepath.Join(t.TempDir(), "helper")}, func(string) string {
		t.Fatal("MCP consulted getenv")
		return sentinel
	}, strings.NewReader(sentinel), &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || stderr.String() != errMCPStdio.Error()+"\n" {
		t.Fatal("non-pipe MCP streams were accepted")
	}
}

func TestPinentryAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pass, err := readPinentry(ctx, pinentryOptions{path: filepath.Join(t.TempDir(), "does-not-run")})
	if pass != nil || !errors.Is(err, errPinentryCancelled) {
		t.Fatal("cancelled prompt was launched")
	}
}

func TestPinentryDiagnosticPrecedence(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	timedOut, stop := context.WithDeadline(context.Background(), time.Time{})
	defer stop()
	for _, tc := range []struct {
		name        string
		ctx         context.Context
		protocolErr error
		waitErr     error
		want        error
	}{
		{"success", context.Background(), nil, nil, nil},
		{"late-parent-cancellation", cancelled, nil, nil, errPinentryCancelled},
		{"read-failure-with-cancellation", cancelled, errPinentryFailed, nil, errPinentryCancelled},
		{"restore-before-cancellation", cancelled, errPinentryTerminal, nil, errPinentryTerminal},
		{"restore-before-timeout", timedOut, errPinentryTerminal, nil, errPinentryTerminal},
		{"timeout-before-cancellation", cancelled, errPinentryTimeout, nil, errPinentryTimeout},
		{"observed-timeout", timedOut, errPinentryFailed, nil, errPinentryTimeout},
		{"unknown-eof", context.Background(), io.EOF, nil, errPinentryFailed},
		{"unknown-reap-error", context.Background(), nil, errors.New("synthetic private reap detail"), errPinentryFailed},
		{"unavailable", context.Background(), errPinentryUnavailable, nil, errPinentryUnavailable},
		{"assuan-cancellation", context.Background(), errPinentryCancelled, nil, errPinentryCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pinentryDiagnostic(tc.ctx, tc.protocolErr, tc.waitErr); got != tc.want {
				t.Fatalf("unexpected fixed diagnostic: %v", got)
			}
		})
	}
}

// A test-only executable identity selects a synthetic Assuan peer without
// arguments or environment credentials. Its passphrase is generated only
// inside the helper and transported solely through the private data pipe.
func TestMain(m *testing.M) {
	mode := strings.TrimPrefix(filepath.Base(os.Args[0]), "tremelay-pinentry-test-")
	if mode != filepath.Base(os.Args[0]) {
		mode = strings.TrimSuffix(mode, ".exe")
		os.Exit(testPinentryHelper(mode))
	}
	os.Exit(m.Run())
}

func testPinentryHelper(mode string) int {
	if os.Getenv("TREMELAY_PASSPHRASE") != "" || os.Getenv("TREMELAY_TEST_PRIVATE") != "" || len(os.Args) != 1 {
		fmt.Fprintln(os.Stdout, "ERR 1 environment or argv violation")
		return 1
	}
	fmt.Fprintln(os.Stdout, "OK")
	for {
		var line []byte
		for {
			var b [1]byte
			if _, err := io.ReadFull(os.Stdin, b[:]); err != nil {
				return 0
			}
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
		}
		switch string(line) {
		case "SETTITLE Tremelay", "SETDESC Unlock the local vault for this MCP session.", "SETPROMPT Vault passphrase:":
			fmt.Fprintln(os.Stdout, "OK")
		case "GETPIN":
			switch mode {
			case "success":
				// Random synthetic response data remains only in memory.
				b := make([]byte, 24)
				if _, err := io.ReadFull(rand.Reader, b); err != nil {
					return 1
				}
				fmt.Fprint(os.Stdout, "D ")
				for _, ch := range b {
					fmt.Fprintf(os.Stdout, "%%%02X", ch)
				}
				clear(b)
				fmt.Fprint(os.Stdout, "\nOK\n")
			case "cancel":
				fmt.Fprintln(os.Stdout, "ERR 83886179 hidden")
			case "hang":
				_, _ = io.Copy(io.Discard, os.Stdin)
				return 0
			case "malformed":
				_, _ = io.WriteString(os.Stdout, "D do-not-reflect%xx\nOK\n")
			case "sigint", "sigterm", "sigkill":
				var sig os.Signal = syscall.SIGINT
				if mode == "sigterm" {
					sig = syscall.SIGTERM
				} else if mode == "sigkill" {
					sig = os.Kill
				}
				process, err := os.FindProcess(os.Getpid())
				if err != nil || process.Signal(sig) != nil {
					return 1
				}
				// Let normal OS signal handling determine the typed wait status.
				time.Sleep(time.Second)
				return 1
			case "exit1":
				return 1
			case "eof":
				os.Stdout.Close()
				time.Sleep(time.Hour) // The parent's cleanup kill must stay a failure.
				return 0
			default:
				return 2
			}
		case "BYE":
			fmt.Fprintln(os.Stdout, "OK")
			return 0
		default:
			if strings.HasPrefix(string(line), "OPTION ttyname=") {
				fmt.Fprintln(os.Stdout, "OK")
			} else {
				fmt.Fprintln(os.Stdout, "ERR 1 forbidden command")
				return 1
			}
		}
	}
}

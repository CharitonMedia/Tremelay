package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/CharitonMedia/Tremelay/internal/vault"
	"golang.org/x/term"
)

func cmdChangePassphrase(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	terminal := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{stdin, io.Discard}, "")
	return changePassphrase(args, stdout, stderr, func(prompt string) ([]byte, error) {
		return readChangePassphrase(ctx, stdin, stderr, terminal, prompt)
	})
}

// Only this goroutine owns terminal state. MakeRaw runs before the reader
// starts, so cancellation cannot race a late echo-disabling ioctl. Terminal's
// line reader changes no OS flags and treats Ctrl-C as an input cancellation.
// A signal can leave a blocked reader until main exits; it has no state-writing
// authority and wipes any late returned buffer. Cancellation never waits for it.
func readChangePassphrase(ctx context.Context, stdin io.Reader, stderr io.Writer, terminal *term.Terminal, prompt string) (pass []byte, err error) {
	f, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) || ctx.Err() != nil {
		return nil, vault.ErrPassphrase
	}
	state, err := term.MakeRaw(int(f.Fd()))
	if err != nil {
		return nil, vault.ErrPassphrase
	}
	defer func() {
		if restoreErr := term.Restore(int(f.Fd()), state); restoreErr != nil {
			vault.Wipe(pass)
			pass, err = nil, vault.ErrIO
		}
	}()
	if _, err := fmt.Fprint(stderr, prompt); err != nil {
		return nil, vault.ErrIO
	}
	type answer struct {
		pass []byte
		err  error
	}
	result := make(chan answer)
	done := make(chan struct{})
	defer close(done)
	go func() {
		line, err := terminal.ReadPassword("")
		p := []byte(line)
		select {
		case result <- answer{p, err}:
		case <-done:
			vault.Wipe(p)
		}
	}()
	select {
	case <-ctx.Done():
		err = vault.ErrPassphrase
	case got := <-result:
		pass, err = got.pass, got.err
	}
	_, outputErr := fmt.Fprintln(stderr)
	if err != nil || outputErr != nil || ctx.Err() != nil {
		vault.Wipe(pass)
		return nil, vault.ErrPassphrase
	}
	return pass, nil
}

// The prompt function is injected only for tests. The command's sole input
// source is the no-echo terminal above, never argv, a pipe, or the environment.
func changePassphrase(args []string, stdout, stderr io.Writer, prompt func(string) ([]byte, error)) int {
	fs := flag.NewFlagSet("vault change-passphrase", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Flag diagnostics may echo secret-looking caller text.
	path := fs.String("path", "", "vault file")
	if err := fs.Parse(args); err != nil || *path == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: tremelay vault change-passphrase --path PATH")
		return 2
	}
	red := &vault.Redactor{}
	defer red.Wipe()
	fail := func(err error) int {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	oldPass, err := prompt("old passphrase: ")
	defer vault.Wipe(oldPass)
	if err != nil {
		return fail(vault.ErrPassphrase)
	}
	red.Add(oldPass)
	logger := log.New(vault.RedactingWriter{Dst: stderr, Redactor: red}, "", 0)
	session, err := vault.Unlock(*path, oldPass, logger)
	if err != nil {
		return fail(err)
	}
	defer session.Lock()
	newPass, err := prompt("new passphrase: ")
	defer vault.Wipe(newPass)
	if err != nil {
		return fail(session.RejectPassphraseChange())
	}
	red.Add(newPass)
	confirmation, err := prompt("confirm new passphrase: ")
	defer vault.Wipe(confirmation)
	if err != nil {
		return fail(session.RejectPassphraseChange())
	}
	red.Add(confirmation)
	if !bytes.Equal(newPass, confirmation) {
		return fail(session.RejectPassphraseChange())
	}
	if err := session.ChangePassphrase(oldPass, newPass); err != nil {
		return fail(err)
	}
	const confirmationOutput = "passphrase changed\n"
	if n, err := io.WriteString(stdout, confirmationOutput); err != nil || n != len(confirmationOutput) {
		fmt.Fprintln(stderr, "passphrase changed; confirmation output failed")
		return 1
	}
	return 0
}

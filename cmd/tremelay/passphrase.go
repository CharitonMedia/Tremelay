package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/CharitonMedia/Tremelay/internal/vault"
	"golang.org/x/term"
)

func cmdChangePassphrase(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return changePassphrase(args, stdout, stderr, func(prompt string) ([]byte, error) {
		f, ok := stdin.(*os.File)
		if !ok || !term.IsTerminal(int(f.Fd())) {
			return nil, vault.ErrPassphrase
		}
		if _, err := fmt.Fprint(stderr, prompt); err != nil {
			return nil, vault.ErrIO
		}
		pass, err := term.ReadPassword(int(f.Fd()))
		_, outputErr := fmt.Fprintln(stderr)
		if err != nil || outputErr != nil {
			vault.Wipe(pass)
			return nil, vault.ErrPassphrase
		}
		return pass, nil
	})
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

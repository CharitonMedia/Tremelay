package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

func cmdBackup(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vault backup", flag.ContinueOnError)
	// The flag package can echo unknown flags, including --passphrase=VALUE.
	fs.SetOutput(io.Discard)
	path := fs.String("path", "", "source vault file")
	output := fs.String("output", "", "new backup artifact")
	if err := fs.Parse(args); err != nil || *path == "" || *output == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "invalid vault backup arguments")
		return 2
	}
	pass, err := readPassphrase(getenv, stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "passphrase required")
		return 1
	}
	defer vault.Wipe(pass)
	red := &vault.Redactor{}
	red.Add(pass)
	defer red.Wipe()
	safeErr := vault.RedactingWriter{Dst: stderr, Redactor: red}
	logger := log.New(safeErr, "", 0)
	// Do not use withSession: Unlock would migrate or append an audit row.
	cp, err := vault.Backup(*path, *output, pass, logger)
	if err != nil {
		fmt.Fprintln(safeErr, err.Error()) // The engine returns fixed errors.
		return 1
	}
	text, err := cp.MarshalText()
	if err == nil {
		var n int
		n, err = stdout.Write(text)
		if err == nil && n != len(text) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		// The artifact is already durable. A caller's writer error may carry
		// arbitrary text; do not echo it or claim the artifact was rolled back.
		fmt.Fprintln(safeErr, "backup artifact created but checkpoint output failed; retain the artifact and obtain a complete checkpoint before relying on it")
		return 1
	}
	return 0
}

func cmdRestore(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vault restore", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	input := fs.String("input", "", "backup artifact")
	path := fs.String("path", "", "new destination vault file")
	checkpointFile := fs.String("checkpoint-file", "", "independently retained current checkpoint")
	if err := fs.Parse(args); err != nil || *input == "" || *path == "" || *checkpointFile == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "invalid vault restore arguments")
		return 2
	}
	cp, err := readCheckpointFile(*checkpointFile)
	if err != nil {
		fmt.Fprintln(stderr, "invalid or unreadable checkpoint file")
		return 1
	}
	pass, err := readPassphrase(getenv, stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "passphrase required")
		return 1
	}
	defer vault.Wipe(pass)
	red := &vault.Redactor{}
	red.Add(pass)
	defer red.Wipe()
	safeErr := vault.RedactingWriter{Dst: stderr, Redactor: red}
	logger := log.New(safeErr, "", 0)
	// Restore authenticates without opening a session or changing the artifact.
	err = vault.Restore(*input, *path, pass, cp, logger)
	return reportRestoreResult(err, stdout, safeErr)
}

func readCheckpointFile(path string) (vault.Checkpoint, error) {
	const maxCheckpointText = 512 // ADR 0016 and Checkpoint.UnmarshalText.
	f, err := os.Open(path)
	if err != nil {
		return vault.Checkpoint{}, vault.ErrInvalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return vault.Checkpoint{}, vault.ErrInvalid
	}
	text, err := io.ReadAll(io.LimitReader(f, maxCheckpointText+1))
	if err != nil || len(text) > maxCheckpointText {
		return vault.Checkpoint{}, vault.ErrInvalid
	}
	var cp vault.Checkpoint
	if err := cp.UnmarshalText(text); err != nil {
		return vault.Checkpoint{}, vault.ErrInvalid
	}
	return cp, nil
}

// Exit 3 means the destination remains; exit 4 means its rollback durability
// is uncertain. Neither is an ordinary failure that can be retried blindly.
func reportRestoreResult(err error, stdout, stderr io.Writer) int {
	switch {
	case errors.Is(err, vault.ErrPublished):
		fmt.Fprintln(stderr, "vault restore destination remains; directory durability or staging cleanup may be incomplete; inspect destination and single-active-instance state before retry or cutover; do not retry blindly")
		return 3
	case errors.Is(err, vault.ErrPublicationUncertain):
		fmt.Fprintln(stderr, "vault restore publication uncertain; destination is absent now but may reappear after a crash; inspect destination and single-active-instance state before retry or cutover; do not retry blindly")
		return 4
	case err != nil:
		fmt.Fprintln(stderr, err.Error()) // The engine returns fixed errors.
		return 1
	}
	const confirmation = "vault restored\n"
	if n, err := io.WriteString(stdout, confirmation); err != nil || n != len(confirmation) {
		fmt.Fprintln(stderr, "vault restored but confirmation output failed; destination remains; inspect destination and single-active-instance state before retry or cutover; do not retry blindly")
		return 3
	}
	return 0
}

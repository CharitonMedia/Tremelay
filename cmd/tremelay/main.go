package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	case "vault":
		return cmdVault(args[1:], getenv, stdin, stdout, stderr)
	case "credential":
		return cmdCredential(args[1:], getenv, stdin, stdout, stderr)
	case "audit":
		return cmdAudit(args[1:], getenv, stdin, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `tremelay is the human control plane for a local vault.
It does not provide an agent interface or raw-secret retrieval for agents.

  tremelay vault create --path PATH
  tremelay credential put --path PATH --label LABEL --type TYPE --secret-file PATH
  tremelay credential get --path PATH --id ID
  tremelay credential list --path PATH
  tremelay audit verify --path PATH

Types: %s
Passphrase: TREMELAY_PASSPHRASE, or a no-echo terminal prompt.
The passphrase is not accepted as an argument. credential get writes the raw secret to stdout.
`, strings.Join(vault.CredentialTypes(), ", "))
}

func cmdVault(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "create" {
		usage(stderr)
		return 2
	}
	fs := flag.NewFlagSet("vault create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *path == "" || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	red := &vault.Redactor{}
	pass, err := readPassphrase(getenv, stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	defer vault.Wipe(pass)
	red.Add(pass)
	logger := log.New(vault.RedactingWriter{Dst: stderr, Redactor: red}, "", 0)
	session, err := vault.Create(*path, pass, logger)
	if err != nil {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	defer session.Lock()
	if _, err := fmt.Fprintln(stdout, "vault created"); err != nil {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	return 0
}

func cmdCredential(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "put":
		return cmdPut(args[1:], getenv, stdin, stdout, stderr)
	case "get":
		return cmdGet(args[1:], getenv, stdin, stdout, stderr)
	case "list":
		return cmdList(args[1:], getenv, stdin, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
}

func cmdPut(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("credential put", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	label := fs.String("label", "", "label")
	typ := fs.String("type", "", "credential type")
	secretFile := fs.String("secret-file", "", "file containing the secret")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" || *label == "" || *typ == "" || *secretFile == "" || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	secret, err := readSecretFile(*secretFile)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	defer vault.Wipe(secret)
	red := &vault.Redactor{}
	red.Add(secret)
	return withSession(*path, getenv, stdin, stderr, red, func(session *vault.Session) error {
		cred, err := session.Put(*label, *typ, secret, vault.PutOptions{})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, cred.ID)
		return err
	})
}

func cmdGet(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("credential get", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	id := fs.String("id", "", "credential id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" || *id == "" || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	red := &vault.Redactor{}
	return withSession(*path, getenv, stdin, stderr, red, func(session *vault.Session) error {
		cred, err := session.Get(*id)
		if err != nil {
			return err
		}
		defer vault.Wipe(cred.Secret)
		// A writer error can echo the bytes it was given. Do not return that
		// error: it is a direct path for the retrieved secret into stderr.
		if _, err := stdout.Write(cred.Secret); err != nil {
			return errors.New("stdout write failed")
		}
		return nil
	})
}

func cmdList(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("credential list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	red := &vault.Redactor{}
	return withSession(*path, getenv, stdin, stderr, red, func(session *vault.Session) error {
		creds, err := session.List()
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		for _, cred := range creds {
			view := listEntry{
				ID:            cred.ID,
				Label:         cred.Label,
				Type:          cred.Type,
				State:         cred.Lifecycle.State,
				CreatedAt:     cred.Lifecycle.CreatedAt,
				UpdatedAt:     cred.Lifecycle.UpdatedAt,
				ExpiresAt:     cred.Lifecycle.ExpiresAt,
				ReviewDueAt:   cred.Lifecycle.ReviewDueAt,
				RotationDueAt: cred.Lifecycle.RotationDueAt,
			}
			if err := enc.Encode(view); err != nil {
				// A writer error can echo the encoded entry. Labels are
				// free-form and may hold a credential the session redactor
				// does not know. Do not return that error.
				return errors.New("stdout write failed")
			}
		}
		return nil
	})
}

type listEntry struct {
	ID            string     `json:"id"`
	Label         string     `json:"label"`
	Type          string     `json:"type"`
	State         string     `json:"state"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ReviewDueAt   *time.Time `json:"review_due_at,omitempty"`
	RotationDueAt *time.Time `json:"rotation_due_at,omitempty"`
}

func cmdAudit(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "verify" {
		usage(stderr)
		return 2
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *path == "" || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	red := &vault.Redactor{}
	pass, err := readPassphrase(getenv, stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	defer vault.Wipe(pass)
	red.Add(pass)
	head, err := vault.VerifyAudit(*path, pass)
	if err != nil {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	if _, err := fmt.Fprintln(stdout, head); err != nil {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	return 0
}

func withSession(path string, getenv func(string) string, stdin io.Reader, stderr io.Writer, red *vault.Redactor, fn func(*vault.Session) error) int {
	if red == nil {
		red = &vault.Redactor{}
	}
	pass, err := readPassphrase(getenv, stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	defer vault.Wipe(pass)
	red.Add(pass)
	logger := log.New(vault.RedactingWriter{Dst: stderr, Redactor: red}, "", 0)
	session, err := vault.Unlock(path, pass, logger)
	if err != nil {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	defer session.Lock()
	if err := fn(session); err != nil {
		fmt.Fprintln(stderr, red.Redact(err.Error()))
		return 1
	}
	return 0
}

func readPassphrase(getenv func(string) string, stdin io.Reader, stderr io.Writer) ([]byte, error) {
	if getenv != nil {
		if v := getenv("TREMELAY_PASSPHRASE"); v != "" {
			return []byte(v), nil
		}
	}
	f, ok := stdin.(*os.File)
	if ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(stderr, "passphrase: ")
		pw, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return nil, vault.ErrPassphrase
		}
		return pw, nil
	}
	return nil, vault.ErrPassphrase
}

func readSecretFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, vault.ErrInvalid
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, vault.MaxSecret+1))
	if err != nil {
		return nil, vault.ErrIO
	}
	if len(b) == 0 || len(b) > vault.MaxSecret {
		return nil, vault.ErrInvalid
	}
	return b, nil
}

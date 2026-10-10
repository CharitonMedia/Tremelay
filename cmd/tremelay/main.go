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
	case "agent":
		return cmdAgent(args[1:], getenv, stdin, stdout, stderr)
	case "grant":
		return cmdGrant(args[1:], getenv, stdin, stdout, stderr)
	case "capability":
		return cmdCapability(args[1:], getenv, stdin, stdout, stderr)
	case "audit":
		return cmdAudit(args[1:], getenv, stdin, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `tremelay is the human control plane for a local vault.
Agent and grant commands manage capability authority. They do not retrieve raw secrets.

  tremelay vault create --path PATH
  tremelay credential put --path PATH --label LABEL --type TYPE --secret-file PATH
  tremelay credential get --path PATH --id ID
  tremelay credential list --path PATH
  tremelay credential replace --path PATH --id ID --secret-file PATH
  tremelay credential lifecycle --path PATH --id ID [--expires RFC3339] [--review RFC3339] [--rotation RFC3339] [--rotation-every DURATION] [--review-every DURATION]
  tremelay credential health --path PATH [--id ID]
  tremelay credential refresh --path PATH [--id ID]
  tremelay credential policy --path PATH [--min-length N] [--pattern-run N] [--freshness DURATION] [--reminder-lead DURATION] [--compromise-opt-in true|false]
  tremelay agent create --path PATH --label LABEL
  tremelay grant create --path PATH --agent ID (--credential ID | --class TYPE) --operation OP --resource SCOPE --expires RFC3339
  tremelay grant revoke --path PATH --id ID
  tremelay capability list --path PATH --agent ID
  tremelay capability authorize --path PATH --agent ID --credential ID --operation OP --resource SCOPE
  tremelay audit verify --path PATH
  tremelay audit list --path PATH [--credential ID] [--agent ID] [--action ACTION] [--class CLASS] [--since RFC3339] [--until RFC3339] [--after SEQ] [--limit N]
  tremelay audit get --path PATH --seq SEQ

Types: %s
Grant operations: %s
Passphrase: TREMELAY_PASSPHRASE, or a no-echo terminal prompt.
The passphrase is not accepted as an argument. credential get writes the raw secret to stdout.
Health is advisory. Refresh runs only while the vault is unlocked; a locked or stopped process does not evaluate credentials.
`, strings.Join(vault.CredentialTypes(), ", "), strings.Join(vault.GrantOperations(), ", "))
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
	case "replace":
		return cmdReplace(args[1:], getenv, stdin, stdout, stderr)
	case "lifecycle":
		return cmdLifecycle(args[1:], getenv, stdin, stdout, stderr)
	case "health":
		return cmdHealth(args[1:], getenv, stdin, stdout, stderr)
	case "refresh":
		return cmdRefresh(args[1:], getenv, stdin, stdout, stderr)
	case "policy":
		return cmdPolicy(args[1:], getenv, stdin, stdout, stderr)
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
		// --path is applied before a later bad flag. That is an attempted put.
		// A bad flag before --path leaves the path empty and cannot name a vault.
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectPut(vault.ErrInvalid)
		})
	}
	// A missing path cannot name a vault. Every other path-known rejection,
	// including an extra positional, is an attempted put and is denied inside
	// the unlocked session so the audit chain records it.
	if *path == "" {
		usage(stderr)
		return 2
	}
	red := &vault.Redactor{}
	return withSession(*path, getenv, stdin, stderr, red, func(session *vault.Session) error {
		if fs.NArg() != 0 || *secretFile == "" {
			return session.RejectPut(vault.ErrInvalid)
		}
		// File checks used to return before unlock, so empty, oversized, and
		// unreadable secret files never produced a credential_put denial.
		secret, err := readSecretFile(*secretFile)
		if err != nil {
			return session.RejectPut(err)
		}
		defer vault.Wipe(secret)
		red.Add(secret)
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
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectGet(vault.ErrInvalid)
		})
	}
	// An empty id is an attempted get. Session.Get records a metadata-free denial.
	// An extra positional is rejected the same way, without looking up --id.
	if *path == "" {
		usage(stderr)
		return 2
	}
	red := &vault.Redactor{}
	return withSession(*path, getenv, stdin, stderr, red, func(session *vault.Session) error {
		if fs.NArg() != 0 {
			return session.RejectGet(vault.ErrInvalid)
		}
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
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectList(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	red := &vault.Redactor{}
	return withSession(*path, getenv, stdin, stderr, red, func(session *vault.Session) error {
		if fs.NArg() != 0 {
			return session.RejectList(vault.ErrInvalid)
		}
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
				// String form matches time.ParseDuration, including 0s when disabled.
				RotationEvery: cred.Lifecycle.RotationEvery.String(),
				ReviewEvery:   cred.Lifecycle.ReviewEvery.String(),
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

func cmdReplace(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("credential replace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	id := fs.String("id", "", "credential id")
	secretFile := fs.String("secret-file", "", "file containing the secret")
	opt, times := lifecycleFlags(fs)
	if err := fs.Parse(args); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectReplace(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	red := &vault.Redactor{}
	return withSession(*path, getenv, stdin, stderr, red, func(session *vault.Session) error {
		if fs.NArg() != 0 || *secretFile == "" {
			return session.RejectReplace(vault.ErrInvalid)
		}
		parsed, err := finishLifecycle(*opt, times)
		if err != nil {
			return session.RejectReplace(vault.ErrInvalid)
		}
		secret, err := readSecretFile(*secretFile)
		if err != nil {
			return session.RejectReplace(err)
		}
		defer vault.Wipe(secret)
		red.Add(secret)
		cred, err := session.Replace(*id, secret, parsed)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, cred.ID)
		return err
	})
}

func cmdLifecycle(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("credential lifecycle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	id := fs.String("id", "", "credential id")
	opt, times := lifecycleFlags(fs)
	if err := fs.Parse(args); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectLifecycle(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		if fs.NArg() != 0 || *id == "" {
			return session.RejectLifecycle(vault.ErrInvalid)
		}
		parsed, err := finishLifecycle(*opt, times)
		if err != nil {
			return session.RejectLifecycle(vault.ErrInvalid)
		}
		cred, err := session.SetLifecycle(*id, parsed)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, cred.ID)
		return err
	})
}

func cmdHealth(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("credential health", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	id := fs.String("id", "", "credential id")
	if err := fs.Parse(args); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectHealth(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		if fs.NArg() != 0 {
			return session.RejectHealth(vault.ErrInvalid)
		}
		enc := json.NewEncoder(stdout)
		if *id == "" {
			items, policy, err := session.ListHealth()
			if err != nil {
				return err
			}
			return enc.Encode(struct {
				Policy vault.HealthPolicy `json:"policy"`
				Items  []vault.Health     `json:"items"`
			}{Policy: policy, Items: items})
		}
		item, err := session.Health(*id)
		if err != nil {
			return err
		}
		return enc.Encode(item)
	})
}

func cmdRefresh(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("credential refresh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	id := fs.String("id", "", "credential id")
	if err := fs.Parse(args); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectRefresh(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		if fs.NArg() != 0 {
			return session.RejectRefresh(vault.ErrInvalid)
		}
		if err := session.RefreshHealth(*id); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "refreshed")
		return err
	})
}

func cmdPolicy(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("credential policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	minLen := fs.Int("min-length", 0, "minimum password length")
	run := fs.Int("pattern-run", 0, "predictable-run length")
	fresh := fs.String("freshness", "", "assessment freshness")
	lead := fs.String("reminder-lead", "", "reminder lead")
	optIn := fs.String("compromise-opt-in", "", "true or false")
	if err := fs.Parse(args); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectHealthPolicy(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		if fs.NArg() != 0 || (*minLen == 0 && *run == 0 && *fresh == "" && *lead == "" && *optIn == "") {
			return session.RejectHealthPolicy(vault.ErrInvalid)
		}
		_, current, err := session.ListHealth()
		if err != nil {
			return err
		}
		if *minLen != 0 {
			current.MinPasswordLength = *minLen
		}
		if *run != 0 {
			current.PatternRun = *run
		}
		if *fresh != "" {
			d, err := time.ParseDuration(*fresh)
			if err != nil {
				return session.RejectHealthPolicy(vault.ErrInvalid)
			}
			current.Freshness = d
		}
		if *lead != "" {
			d, err := time.ParseDuration(*lead)
			if err != nil {
				return session.RejectHealthPolicy(vault.ErrInvalid)
			}
			current.ReminderLead = d
		}
		switch *optIn {
		case "":
		case "true":
			current.CompromiseOptIn = true
		case "false":
			current.CompromiseOptIn = false
		default:
			return session.RejectHealthPolicy(vault.ErrInvalid)
		}
		if err := session.SetHealthPolicy(current); err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, "policy updated")
		return err
	})
}

type lifecycleTimes struct {
	expires  *string
	review   *string
	rotation *string
	everyRot *string
	everyRev *string
	clearExp *bool
	clearRev *bool
	clearRot *bool
}

func lifecycleFlags(fs *flag.FlagSet) (*vault.LifecycleOptions, lifecycleTimes) {
	opt := &vault.LifecycleOptions{}
	times := lifecycleTimes{
		expires:  fs.String("expires", "", "explicit expiry (RFC3339)"),
		review:   fs.String("review", "", "explicit review time (RFC3339)"),
		rotation: fs.String("rotation", "", "explicit rotation time (RFC3339)"),
		everyRot: fs.String("rotation-every", "", "rotation interval"),
		everyRev: fs.String("review-every", "", "review interval"),
		clearExp: fs.Bool("clear-expires", false, "clear explicit expiry"),
		clearRev: fs.Bool("clear-review", false, "clear explicit review time"),
		clearRot: fs.Bool("clear-rotation", false, "clear explicit rotation time"),
	}
	return opt, times
}

func finishLifecycle(opt vault.LifecycleOptions, times lifecycleTimes) (vault.LifecycleOptions, error) {
	opt.ClearExpires = *times.clearExp
	opt.ClearReview = *times.clearRev
	opt.ClearRotation = *times.clearRot
	var err error
	if opt.ExpiresAt, err = parseOptionalTime(*times.expires); err != nil {
		return opt, err
	}
	if opt.ReviewDueAt, err = parseOptionalTime(*times.review); err != nil {
		return opt, err
	}
	if opt.RotationDueAt, err = parseOptionalTime(*times.rotation); err != nil {
		return opt, err
	}
	if opt.RotationEvery, err = parseOptionalDuration(*times.everyRot); err != nil {
		return opt, err
	}
	if opt.ReviewEvery, err = parseOptionalDuration(*times.everyRev); err != nil {
		return opt, err
	}
	return opt, nil
}

func parseOptionalTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}
	t = t.UTC()
	return &t, nil
}

func parseOptionalDuration(s string) (*time.Duration, error) {
	if s == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, err
	}
	return &d, nil
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
	RotationEvery string     `json:"rotation_every"`
	ReviewEvery   string     `json:"review_every"`
}

func cmdAudit(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "verify":
		return cmdAuditVerify(args[1:], getenv, stdin, stdout, stderr)
	case "list":
		return cmdAuditList(args[1:], getenv, stdin, stdout, stderr)
	case "get":
		return cmdAuditGet(args[1:], getenv, stdin, stdout, stderr)
	default:
		usage(stderr)
		return 2
	}
}

func cmdAuditVerify(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
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

func cmdAuditList(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	cred := fs.String("credential", "", "credential id")
	agent := fs.String("agent", "", "agent id")
	action := fs.String("action", "", "audit action")
	class := fs.String("class", "", "risk class")
	since := fs.String("since", "", "inclusive start (RFC3339)")
	until := fs.String("until", "", "inclusive end (RFC3339)")
	after := fs.Uint64("after", 0, "return rows after this sequence")
	limit := fs.Int("limit", 0, "page size")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	filter := vault.AuditFilter{
		CredentialID: *cred,
		AgentID:      *agent,
		Action:       *action,
		Class:        *class,
		AfterSeq:     *after,
		Limit:        *limit,
	}
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintln(stderr, "invalid vault input")
			return 1
		}
		filter.Since = t
	}
	if *until != "" {
		t, err := time.Parse(time.RFC3339, *until)
		if err != nil {
			fmt.Fprintln(stderr, "invalid vault input")
			return 1
		}
		filter.Until = t
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		rows, err := session.AuditHistory(filter)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		for _, row := range rows {
			if err := enc.Encode(row); err != nil {
				return err
			}
		}
		return nil
	})
}

func cmdAuditGet(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit get", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	seq := fs.Uint64("seq", 0, "audit sequence")
	hash := fs.String("hash", "", "expected row hash")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" || *seq == 0 || fs.NArg() != 0 {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		row, err := session.AuditBySeq(*seq, *hash)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		return enc.Encode(row)
	})
}

// denyKnownVault records a metadata-free denial when parsing fails after a
// vault path is known. An empty path cannot name a vault; the flag package
// has already described that error.
func denyKnownVault(path string, getenv func(string) string, stdin io.Reader, stderr io.Writer, deny func(*vault.Session) error) int {
	if path == "" {
		return 2
	}
	return withSession(path, getenv, stdin, stderr, &vault.Redactor{}, deny)
}

func withSession(path string, getenv func(string) string, stdin io.Reader, stderr io.Writer, red *vault.Redactor, fn func(*vault.Session) error) int {
	if red == nil {
		red = &vault.Redactor{}
	}
	pass, err := readPassphrase(getenv, stdin, stderr)
	if err != nil {
		// No passphrase never reached Unlock, so a credential attempt against
		// an existing vault left no denial. An empty passphrase is rejected
		// and recorded like any other locked-state failure. A missing vault
		// is ErrInvalid from Unlock and still surfaces as ErrPassphrase.
		if errors.Is(err, vault.ErrPassphrase) {
			logger := log.New(vault.RedactingWriter{Dst: stderr, Redactor: red}, "", 0)
			if _, uerr := vault.Unlock(path, nil, logger); uerr != nil && !errors.Is(uerr, vault.ErrInvalid) {
				err = uerr
			}
		}
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

func cmdAgent(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "create" {
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
	fs := flag.NewFlagSet("agent create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	label := fs.String("label", "", "agent label")
	if err := fs.Parse(args[1:]); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectAgentCreate(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		if fs.NArg() != 0 || *label == "" {
			return session.RejectAgentCreate(vault.ErrInvalid)
		}
		agent, err := session.CreateAgent(*label)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, agent.ID)
		return err
	})
}

func cmdGrant(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "create":
		return cmdGrantCreate(args[1:], getenv, stdin, stdout, stderr)
	case "revoke":
		return cmdGrantRevoke(args[1:], getenv, stdin, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
}

func cmdGrantCreate(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("grant create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	agent := fs.String("agent", "", "agent id")
	cred := fs.String("credential", "", "credential id")
	class := fs.String("class", "", "credential class")
	resource := fs.String("resource", "", "resource scope")
	expires := fs.String("expires", "", "expiration time (RFC3339)")
	var ops opsFlag
	fs.Var(&ops, "operation", "permitted operation")
	if err := fs.Parse(args); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectGrantCreate(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		if fs.NArg() != 0 || *agent == "" || *resource == "" || *expires == "" || len(ops) == 0 || (*cred == "") == (*class == "") {
			return session.RejectGrantCreate(vault.ErrInvalid)
		}
		exp, err := time.Parse(time.RFC3339, *expires)
		if err != nil {
			return session.RejectGrantCreate(vault.ErrInvalid)
		}
		grant, err := session.IssueGrant(vault.GrantSpec{
			AgentID:         *agent,
			CredentialID:    *cred,
			CredentialClass: *class,
			Operations:      ops,
			Resource:        *resource,
			ExpiresAt:       exp.UTC(),
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, grant.ID)
		return err
	})
}

func cmdGrantRevoke(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("grant revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	id := fs.String("id", "", "grant id")
	if err := fs.Parse(args); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectGrantRevoke(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		if fs.NArg() != 0 || *id == "" {
			return session.RejectGrantRevoke(vault.ErrInvalid)
		}
		if err := session.RevokeGrant(*id); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, *id)
		return err
	})
}

func cmdCapability(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "list":
		return cmdCapabilityList(args[1:], getenv, stdin, stdout, stderr)
	case "authorize":
		return cmdCapabilityAuthorize(args[1:], getenv, stdin, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
}

func cmdCapabilityList(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capability list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	agentID := fs.String("agent", "", "agent id")
	if err := fs.Parse(args); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectCapabilityList(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		if fs.NArg() != 0 || *agentID == "" {
			return session.RejectCapabilityList(vault.ErrInvalid)
		}
		agent, err := session.Agent(*agentID)
		if err != nil {
			return err
		}
		caps, err := agent.Capabilities()
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		for _, cap := range caps {
			view := capabilityEntry{
				GrantID:         cap.GrantID,
				AgentID:         cap.AgentID,
				CredentialID:    cap.CredentialID,
				CredentialClass: cap.CredentialClass,
				Operations:      cap.Operations,
				Resource:        cap.Resource,
				CreatedAt:       cap.CreatedAt,
				ExpiresAt:       cap.ExpiresAt,
				RevokedAt:       cap.RevokedAt,
				Status:          cap.Status,
				KeyID:           cap.KeyID,
			}
			if err := enc.Encode(view); err != nil {
				return errors.New("stdout write failed")
			}
		}
		return nil
	})
}

func cmdCapabilityAuthorize(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capability authorize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "vault file")
	agentID := fs.String("agent", "", "agent id")
	cred := fs.String("credential", "", "credential id")
	operation := fs.String("operation", "", "operation")
	resource := fs.String("resource", "", "resource scope")
	if err := fs.Parse(args); err != nil {
		return denyKnownVault(*path, getenv, stdin, stderr, func(session *vault.Session) error {
			return session.RejectAuthorize(vault.ErrInvalid)
		})
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	return withSession(*path, getenv, stdin, stderr, &vault.Redactor{}, func(session *vault.Session) error {
		if fs.NArg() != 0 || *agentID == "" || *cred == "" || *operation == "" || *resource == "" {
			return session.RejectAuthorize(vault.ErrInvalid)
		}
		agent, err := session.Agent(*agentID)
		if err != nil {
			return err
		}
		grantID, err := agent.Authorize(*cred, *operation, *resource)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "allowed %s\n", grantID)
		return err
	})
}

type capabilityEntry struct {
	GrantID         string     `json:"grant_id"`
	AgentID         string     `json:"agent_id"`
	CredentialID    string     `json:"credential_id,omitempty"`
	CredentialClass string     `json:"credential_class,omitempty"`
	Operations      []string   `json:"operations"`
	Resource        string     `json:"resource"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	Status          string     `json:"status"`
	KeyID           string     `json:"key_id,omitempty"`
}

type opsFlag []string

func (o *opsFlag) String() string { return strings.Join(*o, ",") }

func (o *opsFlag) Set(v string) error {
	*o = append(*o, v)
	return nil
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

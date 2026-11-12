package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

// The command line end to end: archive, verify against the file, and the
// refusals a person will actually hit.
func TestCLIAuditArchive(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	session, err := vault.Create(path, []byte(pass), nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 12 {
		if _, err := session.List(); err != nil {
			t.Fatal(err)
		}
	}
	session.Lock()
	env := envGet(map[string]string{"TREMELAY_PASSPHRASE": pass})
	cli := func(args ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := run(args, env, strings.NewReader(""), &stdout, &stderr)
		if strings.Contains(stdout.String()+stderr.String(), pass) {
			t.Fatal("the passphrase was printed")
		}
		return code, stdout.String(), stderr.String()
	}

	// The docs promise this default: it is what keeps a running daemon's
	// last verified row in the vault.
	if auditArchiveKeep != 1000 {
		t.Fatalf("default --keep is %d; docs/vault-lifecycle.md and ADR 0029 say 1000", auditArchiveKeep)
	}
	out := filepath.Join(dir, "audit-1.jsonl")
	if code, _, _ := cli("audit", "archive", "--path", path); code != 2 {
		t.Fatalf("archive without --out: exit %d", code)
	}
	if code, _, stderr := cli("audit", "archive", "--path", path, "--out", out, "--keep", "100000"); code != 1 || !strings.Contains(stderr, vault.ErrArchiveEmpty.Error()) {
		t.Fatalf("nothing to archive: exit %d %q", code, stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a refused archive left a file")
	}

	code, stdout, stderr := cli("audit", "archive", "--path", path, "--out", out, "--keep", "3")
	if code != 0 {
		t.Fatalf("archive: exit %d %q", code, stderr)
	}
	var info vault.AuditArchive
	if err := json.Unmarshal([]byte(stdout), &info); err != nil || info.FirstSeq != 1 || info.Rows == 0 || info.LastSeq != uint64(info.Rows) {
		t.Fatalf("archive output %q: %v", stdout, err)
	}
	if code, _, stderr := cli("audit", "archive", "--path", path, "--out", out, "--keep", "1"); code != 1 || !strings.Contains(stderr, vault.ErrInvalid.Error()) || strings.Contains(stderr, vault.ErrArchiveKept.Error()) {
		t.Fatalf("archive onto an existing file: exit %d %q", code, stderr)
	}

	code, plain, stderr := cli("audit", "verify", "--path", path)
	if code != 0 || len(strings.TrimSpace(plain)) != 64 {
		t.Fatalf("verify: exit %d %q %q", code, plain, stderr)
	}
	code, stdout, stderr = cli("audit", "verify", "--path", path, "--archive", out)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if code != 0 || len(lines) != 2 || lines[0] != strings.TrimSpace(plain) {
		t.Fatalf("verify with the archive: exit %d %q %q", code, stdout, stderr)
	}
	var covered vault.AuditArchive
	if err := json.Unmarshal([]byte(lines[1]), &covered); err != nil || covered.FirstSeq != 1 || covered.LastSeq != info.LastSeq {
		t.Fatalf("coverage line %q: %v", lines[1], err)
	}

	// The list starts after the cut, and an archived row is not found.
	code, stdout, _ = cli("audit", "list", "--path", path, "--limit", "1")
	var first vault.AuditRecord
	if err := json.Unmarshal([]byte(stdout), &first); code != 0 || err != nil || first.Seq != info.LastSeq+1 {
		t.Fatalf("list after archive: exit %d %q", code, stdout)
	}
	if code, _, stderr := cli("audit", "get", "--path", path, "--seq", "1"); code != 1 || !strings.Contains(stderr, vault.ErrAuditNotFound.Error()) {
		t.Fatalf("get of an archived row: exit %d %q", code, stderr)
	}

	// An altered file fails, and so does the vault's check against it.
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "altered.jsonl")
	if err := os.WriteFile(bad, bytes.Replace(raw, []byte(`"result":"allowed"`), []byte(`"result":"denied"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := cli("audit", "verify", "--path", path, "--archive", bad); code != 1 || stdout != "" || !strings.Contains(stderr, vault.ErrAudit.Error()) {
		t.Fatalf("verify with an altered archive: exit %d %q %q", code, stdout, stderr)
	}
	// So does one with its front removed, and the message says which it is.
	short := filepath.Join(dir, "short.jsonl")
	if err := os.WriteFile(short, raw[bytes.IndexByte(raw, '\n')+1:], 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := cli("audit", "verify", "--path", path, "--archive", short); code != 1 || stdout != "" || !strings.Contains(stderr, vault.ErrArchiveIncomplete.Error()) {
		t.Fatalf("verify with a shortened archive: exit %d %q %q", code, stdout, stderr)
	}

	// The archive lands and the report cannot be printed. The file is the
	// only copy of its rows, and the command says so.
	var stderrBuf bytes.Buffer
	unprinted := filepath.Join(dir, "audit-unprinted.jsonl")
	if code := run([]string{"audit", "archive", "--path", path, "--out", unprinted, "--keep", "2"}, env, strings.NewReader(""), failWriter{}, &stderrBuf); code != 1 || !strings.Contains(stderrBuf.String(), vault.ErrArchiveKept.Error()) {
		t.Fatalf("archive with a closed stdout: exit %d %q", code, stderrBuf.String())
	}
	if code, _, stderr := cli("audit", "verify", "--path", path, "--archive", out, "--archive", unprinted); code != 0 {
		t.Fatalf("the archive whose report was lost: exit %d %q", code, stderr)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

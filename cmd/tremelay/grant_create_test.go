package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

func TestCLIGrantCreateFlagReasons(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, randBytes(t, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"TREMELAY_PASSPHRASE": pass}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"vault", "create", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("create %d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "put", "--path", path, "--label", "ci", "--type", "api_key", "--secret-file", secretPath}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("put %d %s", code, stderr.String())
	}
	credID := strings.TrimSpace(stdout.String())
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"agent", "create", "--path", path, "--label", "worker"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("agent %d %s", code, stderr.String())
	}
	agentID := strings.TrimSpace(stdout.String())
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	validBase := []string{"grant", "create", "--path", path, "--agent", agentID, "--credential", credID,
		"--operation", "http_request", "--resource", "svc:one", "--expires", expires}

	sentinel := humanFlagSentinel
	cases := []struct {
		name   string
		args   []string
		msg    string
		reason string
	}{
		{
			name:   "missing operation",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--credential", credID, "--resource", "svc:one", "--expires", expires},
			msg:    "grant create: --operation is required",
			reason: vault.ReasonOperationRequired,
		},
		{
			name:   "class without operation",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--class", "api_key", "--resource", "svc:one", "--expires", expires},
			msg:    "grant create: --operation is required",
			reason: vault.ReasonOperationRequired,
		},
		{
			name:   "missing agent",
			args:   []string{"grant", "create", "--path", path, "--credential", credID, "--operation", "http_request", "--resource", "svc:one", "--expires", expires},
			msg:    "grant create: --agent is required",
			reason: vault.ReasonAgentRequired,
		},
		{
			name:   "missing credential",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--operation", "http_request", "--resource", "svc:one", "--expires", expires},
			msg:    "grant create: --credential or --class is required",
			reason: vault.ReasonCredentialRequired,
		},
		{
			name:   "credential and class",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--credential", credID, "--class", "api_key", "--operation", "http_request", "--resource", "svc:one", "--expires", expires},
			msg:    "grant create: specify only one of --credential or --class",
			reason: vault.ReasonCredentialConflict,
		},
		{
			name:   "missing resource",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--credential", credID, "--operation", "http_request", "--expires", expires},
			msg:    "grant create: --resource is required",
			reason: vault.ReasonResourceRequired,
		},
		{
			name:   "missing expires",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--credential", credID, "--operation", "http_request", "--resource", "svc:one"},
			msg:    "grant create: --expires is required",
			reason: vault.ReasonExpiresRequired,
		},
		{
			name:   "invalid expires",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--credential", credID, "--operation", "http_request", "--resource", "svc:one", "--expires", "not-rfc3339"},
			msg:    "grant create: --expires is invalid",
			reason: vault.ReasonExpiresInvalid,
		},
		{
			name:   "unknown operation",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--credential", credID, "--operation", sentinel, "--resource", "svc:one", "--expires", expires},
			msg:    "unknown --operation; valid:",
			reason: vault.ReasonUnknownOperation,
		},
		{
			name:   "unknown class",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--class", sentinel, "--operation", "http_request", "--resource", "svc:one", "--expires", expires},
			msg:    "unknown --class; valid:",
			reason: vault.ReasonUnknownClass,
		},
		{
			name:   "invalid ssh host key",
			args:   []string{"grant", "create", "--path", path, "--agent", agentID, "--credential", credID, "--operation", "http_request", "--resource", "svc:one", "--expires", expires, "--ssh-host-key", "zz"},
			msg:    "grant create: --ssh-host-key is invalid",
			reason: vault.ReasonSSHHostKeyInvalid,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, envGet(env), strings.NewReader(""), &stdout, &stderr); code == 0 {
				t.Fatal("expected failure")
			}
			errOut := strings.TrimSpace(stderr.String())
			if !strings.Contains(errOut, tc.msg) {
				t.Fatalf("stderr %q want substring %q", errOut, tc.msg)
			}
			if strings.Contains(errOut, pass) || strings.Contains(errOut, sentinel) {
				t.Fatal("stderr echoed passphrase or flag value")
			}
			row := lastGrantCreateAudit(t, path, env)
			if row["result"] != "denied" || row["reasons"] != tc.reason {
				t.Fatalf("audit row %#v", row)
			}
			if reasons, _ := row["reasons"].(string); strings.Contains(reasons, sentinel) {
				t.Fatal("audit reason echoed sentinel")
			}
		})
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(validBase, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("valid grant %d %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("missing grant id")
	}
	row := lastGrantCreateAudit(t, path, env)
	if row["result"] != "allowed" {
		t.Fatalf("allowed audit %#v", row)
	}
	if reasons, _ := row["reasons"].(string); reasons != "" {
		t.Fatalf("allowed grant carried reasons %q", reasons)
	}
}

func lastGrantCreateAudit(t *testing.T, path string, env map[string]string) map[string]any {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"audit", "list", "--path", path, "--action", "grant_create", "--limit", "100"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("audit list %d %s", code, stderr.String())
	}
	var last map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		last = row
	}
	if last == nil {
		t.Fatal("no audit row")
	}
	return last
}

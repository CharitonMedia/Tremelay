//go:build linux || darwin

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

// alertScript is an alert command that appends its stdin to a file.
func alertScript(t *testing.T) (script, out string) {
	t.Helper()
	dir := t.TempDir()
	script, out = filepath.Join(dir, "alert.sh"), filepath.Join(dir, "alerts.jsonl")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat >> '"+out+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return script, out
}

func alertLines(t *testing.T, path string, want int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var lines []map[string]any
		if f, err := os.Open(path); err == nil {
			scan := bufio.NewScanner(f)
			for scan.Scan() {
				var line map[string]any
				if err := json.Unmarshal(scan.Bytes(), &line); err != nil {
					t.Fatalf("alert line %q: %v", scan.Text(), err)
				}
				lines = append(lines, line)
			}
			f.Close()
		}
		if len(lines) >= want {
			return lines
		}
		if time.Now().After(deadline) {
			t.Fatalf("alert command received %d lines, want %d", len(lines), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A revoked grant used again is a high-risk event. With --alert-command the
// owner's command is told, and what it is told holds no secret.
func TestDaemonAlertCommandReceivesHighRiskEvents(t *testing.T) {
	f := startDaemon(t, time.Hour)
	f.cancel()
	f.wait(t, 15*time.Second)
	script, out := alertScript(t)
	f.alertCommand = script
	f.launch(t, time.Hour)

	worker := f.agents[0]
	token := f.token(t, worker)
	agent := f.relay(t, worker.tokenFile)
	before := capabilityEntries(t, agent.capabilities(t))
	if len(before) != 1 {
		t.Fatalf("capabilities: %+v", before)
	}
	// An allowed call alerts nobody.
	if frame, signed := agent.attest(t, 3, before[0].Handle); !signed {
		t.Fatalf("granted call refused: %q", frame)
	}
	f.cli(t, "grant", "revoke", "--path", f.path, "--id", f.grantIDFor(t, worker.id, worker.resource))
	if frame, signed := agent.attest(t, 4, before[0].Handle); signed {
		t.Fatalf("revoked grant signed: %q", frame)
	}
	lines := alertLines(t, out, 1)
	got := lines[0]
	if got["class"] != vault.ClassReplay || got["severity"] != vault.SeverityHigh || got["agent_id"] != worker.id {
		t.Fatalf("alert %v", got)
	}
	if seq, _ := got["audit_seq"].(float64); seq == 0 || got["audit_hash"] == "" {
		t.Fatalf("alert does not reference its audit row: %v", got)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) || strings.Contains(string(raw), f.pass) {
		t.Fatal("alert disclosed the agent token or passphrase")
	}
	agent.finish(t)
	f.cancel()
	if code := f.wait(t, 15*time.Second); code != 0 {
		t.Fatalf("daemon exited %d: %q", code, f.stderr.String())
	}
	if strings.Contains(f.stderr.String(), errAlertFailed.Error()) {
		t.Fatalf("alert command reported failed: %q", f.stderr.String())
	}
}

// A flood reaches the command as bounded batches. What does not fit is
// refused, so the vault audits it as not delivered, and the next batch says
// how many were refused.
func TestAlertSinkBatchesAndReportsDrops(t *testing.T) {
	script, out := alertScript(t)
	sink := newAlertSink(script, os.Stderr)
	sink.interval = 50 * time.Millisecond
	refused := 0
	for i := 0; i < alertQueueMax+7; i++ {
		if err := sink.Notify(vault.Notification{Class: vault.ClassSecretProbe, AuditSeq: uint64(i + 1)}); err != nil {
			refused++
		}
	}
	if refused != 7 {
		t.Fatalf("refused %d alerts, want 7", refused)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go sink.run(ctx)
	lines := alertLines(t, out, alertQueueMax+1)
	if n, _ := lines[alertQueueMax]["dropped"].(float64); n != 7 || len(lines) != alertQueueMax+1 {
		t.Fatalf("%d lines, last %v", len(lines), lines[len(lines)-1])
	}
	// What is queued when the daemon stops is still delivered.
	if err := sink.Notify(vault.Notification{Class: vault.ClassReplay, AuditSeq: 999}); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-sink.done
	if last := alertLines(t, out, alertQueueMax+2)[alertQueueMax+1]; last["class"] != vault.ClassReplay {
		t.Fatalf("final alert %v", last)
	}
}

func TestAlertCommandMustBeAnAbsoluteExecutable(t *testing.T) {
	script, out := alertScript(t)
	if err := checkAlertCommand(script); err != nil {
		t.Fatalf("executable script refused: %v", err)
	}
	if err := os.WriteFile(out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"alert.sh", "./alert.sh", filepath.Dir(script), out, script + ".missing"} {
		if checkAlertCommand(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	var stderr strings.Builder
	if code := run([]string{"daemon", "--vault", "/nonexistent/vault.db", "--alert-command", "alert.sh"}, envGet(nil), strings.NewReader(""), &strings.Builder{}, &stderr); code != 2 || !strings.Contains(stderr.String(), errAlertCommand.Error()) {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
}

func TestAlertEnvDropsThePassphrase(t *testing.T) {
	got := alertEnv([]string{"PATH=/bin", "TREMELAY_PASSPHRASE=hunter2hunter2", "Tremelay_Passphrase=x", "HOME=/h"})
	if strings.Join(got, " ") != "PATH=/bin HOME=/h" {
		t.Fatalf("alert environment %q", got)
	}
}

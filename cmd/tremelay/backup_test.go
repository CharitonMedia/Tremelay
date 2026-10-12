package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

func TestCLIBackupRestore(t *testing.T) {
	source, pass, secret := backupCLIVault(t)
	// A canonical locked-denial suffix belongs in the checkpoint too. Taking
	// the snapshot must not incorporate it by opening an ordinary session.
	if _, err := vault.Unlock(source, []byte(randHex(t, 16)), nil); !errors.Is(err, vault.ErrUnauthenticated) {
		t.Fatal(err)
	}
	before := backupCLIRead(t, source)
	tip, err := vault.VerifyAudit(source, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(source, 0o600) })
	artifact := filepath.Join(filepath.Dir(source), "backup.db")
	var stdout, stderr bytes.Buffer
	env := envGet(map[string]string{"TREMELAY_PASSPHRASE": pass})
	if code := run([]string{"vault", "backup", "--path", source, "--output", artifact}, env, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("backup exit %d: %s", code, stderr.String())
	}
	var cp vault.Checkpoint
	if err := cp.UnmarshalText(stdout.Bytes()); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	canonical, err := cp.MarshalText()
	if err != nil || !bytes.Equal(stdout.Bytes(), canonical) || cp.AuditTip != tip {
		t.Fatal("backup did not return the canonical checkpoint for the unchanged audit tip")
	}
	artifactBytes := backupCLIRead(t, artifact)
	digest := sha256.Sum256(artifactBytes)
	if cp.Digest != hex.EncodeToString(digest[:]) {
		t.Fatal("checkpoint did not bind artifact bytes")
	}
	assertNoSecret(t, &stdout, secret, pass)
	assertNoSecret(t, &stderr, secret, pass)
	assertNoSecret(t, bytes.NewBuffer(artifactBytes), secret, pass)
	backupCLIUnchanged(t, source, before)
	backupCLIMode(t, artifact)
	// Retain the checkpoint in a separately selected directory. The command
	// neither creates nor discovers a sibling manifest automatically.
	cpPath := filepath.Join(backupCLITemp(t), "current.checkpoint")
	if err := os.WriteFile(cpPath, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(source), "restored.db")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"vault", "restore", "--input", artifact, "--path", target, "--checkpoint-file", cpPath}, env, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("restore exit %d: %s", code, stderr.String())
	}
	if stdout.String() != "vault restored\n" {
		t.Fatalf("restore output %q", stdout.String())
	}
	backupCLIUnchanged(t, source, before)
	backupCLIUnchanged(t, artifact, artifactBytes)
	backupCLIUnchanged(t, target, artifactBytes)
	backupCLIUnchanged(t, cpPath, canonical)
	backupCLIMode(t, target)
	for _, path := range []string{source, artifact, target} {
		backupCLINoSidecars(t, path)
	}
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil || len(entries) != 3 {
		t.Fatalf("unexpected manifest, staging file, or sidecar: %v", err)
	}
	assertNoSecret(t, &stdout, secret, pass)
	assertNoSecret(t, &stderr, secret, pass)
	// Only this later ordinary open is allowed to append an unlock row.
	session, err := vault.Unlock(target, []byte(pass), nil)
	if err != nil {
		t.Fatal(err)
	}
	session.Lock()
}

func TestCLIBackupRestoreRejectsArguments(t *testing.T) {
	source, pass, secret := backupCLIVault(t)
	before := backupCLIRead(t, source)
	artifact := filepath.Join(filepath.Dir(source), "backup.db")
	target := filepath.Join(filepath.Dir(source), "restored.db")
	cpPath := filepath.Join(filepath.Dir(source), "explicit.checkpoint")
	callerText := randHex(t, 24)
	for _, command := range []string{"backup", "restore"} {
		base := []string{"vault", command, "--path", source, "--output", artifact}
		if command == "restore" {
			base = []string{"vault", command, "--input", artifact, "--path", target, "--checkpoint-file", cpPath}
		}
		for _, extra := range [][]string{{"--passphrase=" + callerText}, {"--passphrase", callerText}, {"--secret=" + callerText}, {callerText}, {"--" + callerText}, {"--path"}} {
			var stdout, stderr bytes.Buffer
			args := append(append([]string{}, base...), extra...)
			if code := run(args, envGet(map[string]string{"TREMELAY_PASSPHRASE": pass}), strings.NewReader(""), &stdout, &stderr); code != 2 {
				t.Fatalf("%s malformed arguments exit %d", command, code)
			}
			if stdout.Len() != 0 || strings.Contains(stderr.String(), callerText) {
				t.Fatal("invalid arguments disclosed caller text or wrote success output")
			}
			assertNoSecret(t, &stderr, secret, pass)
		}
		var stdout, stderr bytes.Buffer
		if code := run([]string{"vault", command}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code != 2 {
			t.Fatalf("%s missing arguments exit %d", command, code)
		}
	}
	backupCLIUnchanged(t, source, before)
	backupCLINoSidecars(t, source)
	backupCLIAbsent(t, artifact)
	backupCLIAbsent(t, target)
}

func TestCLIBackupRestoreAuthenticationReadOnly(t *testing.T) {
	source, pass, secret := backupCLIVault(t)
	artifact, cpPath := backupCLIArtifact(t, source, pass)
	sourceBytes := backupCLIRead(t, source)
	artifactBytes := backupCLIRead(t, artifact)
	for _, command := range []string{"backup", "restore"} {
		for _, supplied := range []string{"", "short", randHex(t, 16)} {
			t.Run(command+fmt.Sprint(len(supplied)), func(t *testing.T) {
				target := filepath.Join(backupCLITemp(t), "destination.db")
				args := []string{"vault", "backup", "--path", source, "--output", target}
				if command == "restore" {
					args = []string{"vault", "restore", "--input", artifact, "--path", target, "--checkpoint-file", cpPath}
				}
				var stdout, stderr bytes.Buffer
				// A plaintext stdin value is never an alternate passphrase source.
				if code := run(args, envGet(map[string]string{"TREMELAY_PASSPHRASE": supplied}), strings.NewReader(pass), &stdout, &stderr); code != 1 {
					t.Fatalf("exit %d: %s", code, stderr.String())
				}
				if stdout.Len() != 0 {
					t.Fatal("authentication failure wrote success output")
				}
				assertNoSecret(t, &stderr, secret, pass)
				if supplied != "" && strings.Contains(stderr.String(), supplied) {
					t.Fatal("authentication failure disclosed supplied passphrase")
				}
				backupCLIAbsent(t, target)
				backupCLINoSidecars(t, target)
				backupCLIUnchanged(t, source, sourceBytes)
				backupCLIUnchanged(t, artifact, artifactBytes)
				backupCLINoSidecars(t, source)
				backupCLINoSidecars(t, artifact)
			})
		}
	}
}

func TestCLIRestoreRequiresExplicitValidCheckpoint(t *testing.T) {
	source, pass, secret := backupCLIVault(t)
	artifact, cpPath := backupCLIArtifact(t, source, pass)
	artifactBytes := backupCLIRead(t, artifact)
	checkpointBytes := backupCLIRead(t, cpPath)
	sourceBytes := backupCLIRead(t, source)
	var mismatch vault.Checkpoint
	if err := mismatch.UnmarshalText(checkpointBytes); err != nil {
		t.Fatal(err)
	}
	mismatch.AuditSeq++
	mismatched, err := mismatch.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		text    []byte
		omit    bool
		missing bool
	}{
		{name: "omitted", omit: true},
		{name: "missing", missing: true},
		{name: "empty"},
		{name: "malformed", text: []byte(randHex(t, 24))},
		{name: "oversized", text: bytes.Repeat([]byte("x"), 513)},
		{name: "extra-line", text: append(append([]byte{}, checkpointBytes...), []byte("\nextra data")...)},
		{name: "mismatched", text: mismatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := backupCLITemp(t)
			target := filepath.Join(dir, "restored.db")
			inputCP := filepath.Join(dir, "selected.checkpoint")
			if !tc.missing {
				if err := os.WriteFile(inputCP, tc.text, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"vault", "restore", "--input", artifact, "--path", target}
			if !tc.omit {
				args = append(args, "--checkpoint-file", inputCP)
			}
			var stdout, stderr bytes.Buffer
			wantCode := 1
			if tc.omit {
				wantCode = 2
			}
			if code := run(args, envGet(map[string]string{"TREMELAY_PASSPHRASE": pass}), strings.NewReader(""), &stdout, &stderr); code != wantCode {
				t.Fatalf("exit %d: %s", code, stderr.String())
			}
			if stdout.Len() != 0 || (len(tc.text) > 0 && bytes.Contains(stderr.Bytes(), tc.text)) {
				t.Fatal("checkpoint rejection emitted success or caller-controlled data")
			}
			assertNoSecret(t, &stderr, secret, pass)
			backupCLIAbsent(t, target)
			backupCLINoSidecars(t, target)
			backupCLIUnchanged(t, source, sourceBytes)
			backupCLIUnchanged(t, artifact, artifactBytes)
		})
	}
	// A file selected explicitly may have the format's optional final newline.
	if err := os.WriteFile(cpPath, append(checkpointBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCheckpointFile(cpPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readCheckpointFile(filepath.Dir(cpPath)); err == nil {
		t.Fatal("accepted a directory as a checkpoint file")
	}
}

func TestCLIBackupRestorePreservesCollisions(t *testing.T) {
	source, pass, _ := backupCLIVault(t)
	artifact, cpPath := backupCLIArtifact(t, source, pass)
	sourceBytes := backupCLIRead(t, source)
	artifactBytes := backupCLIRead(t, artifact)
	for _, command := range []string{"backup", "restore"} {
		for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
			t.Run(command+suffix, func(t *testing.T) {
				target := filepath.Join(backupCLITemp(t), "destination.db")
				collision := target + suffix
				original := randBytes(t, 64)
				if err := os.WriteFile(collision, original, 0o600); err != nil {
					t.Fatal(err)
				}
				args := []string{"vault", "backup", "--path", source, "--output", target}
				if command == "restore" {
					args = []string{"vault", "restore", "--input", artifact, "--path", target, "--checkpoint-file", cpPath}
				}
				var stdout, stderr bytes.Buffer
				if code := run(args, envGet(map[string]string{"TREMELAY_PASSPHRASE": pass}), strings.NewReader(""), &stdout, &stderr); code != 1 || stdout.Len() != 0 {
					t.Fatalf("collision exit %d: %s", code, stderr.String())
				}
				backupCLIUnchanged(t, collision, original)
				if suffix != "" {
					backupCLIAbsent(t, target)
				}
				entries, err := os.ReadDir(filepath.Dir(target))
				if err != nil || len(entries) != 1 {
					t.Fatalf("collision left staging data or extra sidecars: %v", err)
				}
				backupCLIUnchanged(t, source, sourceBytes)
				backupCLIUnchanged(t, artifact, artifactBytes)
			})
		}
	}
}

func TestCLIBackupRestoreOutputFailure(t *testing.T) {
	source, pass, secret := backupCLIVault(t)
	before := backupCLIRead(t, source)
	for _, writer := range []struct {
		name string
		out  io.Writer
	}{
		{name: "error", out: errWriter{errors.New(pass + string(secret))}},
		{name: "short", out: backupCLIShortWriter{}},
	} {
		t.Run(writer.name, func(t *testing.T) {
			artifact := filepath.Join(backupCLITemp(t), "backup.db")
			var stderr bytes.Buffer
			env := envGet(map[string]string{"TREMELAY_PASSPHRASE": pass})
			if code := run([]string{"vault", "backup", "--path", source, "--output", artifact}, env, strings.NewReader(""), writer.out, &stderr); code != 1 {
				t.Fatalf("backup exit %d", code)
			}
			if !strings.Contains(stderr.String(), "artifact created but checkpoint output failed") {
				t.Fatal("backup failed to warn that the artifact remains")
			}
			assertNoSecret(t, &stderr, secret, pass)
			if _, err := vault.VerifyAudit(artifact, []byte(pass)); err != nil {
				t.Fatalf("backup artifact was not retained: %v", err)
			}
			backupCLIUnchanged(t, source, before)
			goodArtifact, cpPath := backupCLIArtifact(t, source, pass)
			artifactBytes := backupCLIRead(t, goodArtifact)
			target := filepath.Join(backupCLITemp(t), "restored.db")
			stderr.Reset()
			if code := run([]string{"vault", "restore", "--input", goodArtifact, "--path", target, "--checkpoint-file", cpPath}, env, strings.NewReader(""), writer.out, &stderr); code != 3 {
				t.Fatalf("restore confirmation failure exit %d", code)
			}
			if !strings.Contains(stderr.String(), "confirmation output failed; destination remains") || !strings.Contains(stderr.String(), "do not retry blindly") {
				t.Fatal("restore failed to describe the published destination")
			}
			assertNoSecret(t, &stderr, secret, pass)
			backupCLIUnchanged(t, target, artifactBytes)
			backupCLIUnchanged(t, goodArtifact, artifactBytes)
			backupCLIUnchanged(t, source, before)
		})
	}
}

func TestCLIRestorePublicationOutcomes(t *testing.T) {
	// The engine's internal fault tests establish filesystem outcomes. This
	// tests CLI interpretation without adding production injection hooks.
	sentinel := randHex(t, 24)
	for _, tc := range []struct {
		err  error
		code int
		text string
	}{
		{vault.ErrPublished, 3, "destination remains"},
		{vault.ErrPublicationUncertain, 4, "absent now but may reappear after a crash"},
	} {
		var stdout, stderr bytes.Buffer
		if code := reportRestoreResult(fmt.Errorf("%s: %w", sentinel, tc.err), &stdout, &stderr); code != tc.code {
			t.Fatalf("publication outcome exit %d", code)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.text) || !strings.Contains(stderr.String(), "do not retry blindly") || !strings.Contains(stderr.String(), "single-active-instance") || strings.Contains(stderr.String(), sentinel) {
			t.Fatal("unsafe or incomplete publication outcome message")
		}
	}
}

type backupCLIShortWriter struct{}

func (backupCLIShortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func backupCLITemp(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func backupCLIVault(t *testing.T) (string, string, []byte) {
	t.Helper()
	path := filepath.Join(backupCLITemp(t), "vault.db")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	session, err := vault.Create(path, []byte(pass), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Lock()
	if _, err := session.Put("synthetic", "api_key", secret, vault.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	return path, pass, secret
}

func backupCLIArtifact(t *testing.T, source, pass string) (string, string) {
	t.Helper()
	artifact := filepath.Join(backupCLITemp(t), "backup.db")
	cpPath := filepath.Join(backupCLITemp(t), "current.checkpoint")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"vault", "backup", "--path", source, "--output", artifact}, envGet(map[string]string{"TREMELAY_PASSPHRASE": pass}), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("backup exit %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(cpPath, stdout.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return artifact, cpPath
}

func backupCLIRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func backupCLIUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()
	if !bytes.Equal(backupCLIRead(t, path), before) {
		t.Fatal("custody command changed protected file bytes")
	}
}

func backupCLIAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected destination or file state: %v", err)
	}
}

func backupCLINoSidecars(t *testing.T, path string) {
	t.Helper()
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		backupCLIAbsent(t, path+suffix)
	}
}

func backupCLIMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("vault artifact mode %o", info.Mode().Perm())
	}
}

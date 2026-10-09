package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"

	_ "modernc.org/sqlite"
)

func TestCLICreatePutGetListAndRedaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
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
	id := strings.TrimSpace(stdout.String())
	if id == "" {
		t.Fatal("missing id")
	}
	assertNoSecret(t, &stderr, secret, pass)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "list", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("list %d %s", code, stderr.String())
	}
	assertNoSecret(t, &stdout, secret, pass)
	assertNoSecret(t, &stderr, secret, pass)
	var listed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if _, ok := listed["secret"]; ok {
		t.Fatal("list JSON has a secret field")
	}
	if listed["type"] != "api_key" || listed["state"] != "active" || listed["id"] != id {
		t.Fatalf("list metadata %#v", listed)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "get", "--path", path, "--id", id}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("get %d %s", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), secret) {
		t.Fatal("human retrieval mismatch")
	}
	assertNoSecret(t, &stderr, secret, pass)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("verify %d %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("missing audit head")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "list", "--path", path, "--action", "credential_put", "--limit", "5"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("audit list %d %s", code, stderr.String())
	}
	assertNoSecret(t, &stdout, secret, pass)
	assertNoSecret(t, &stderr, secret, pass)
	if !strings.Contains(stdout.String(), `"action":"credential_put"`) || strings.Contains(stdout.String(), `"secret"`) {
		t.Fatalf("audit list %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "get", "--path", path, "--seq", "1"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("audit get %d %s", code, stderr.String())
	}
	assertNoSecret(t, &stdout, secret, pass)
	if !strings.Contains(stdout.String(), `"seq":1`) {
		t.Fatalf("audit get %s", stdout.String())
	}
	wrongVerify := map[string]string{"TREMELAY_PASSPHRASE": randHex(t, 16)}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(wrongVerify), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("verify accepted a wrong passphrase")
	}
	if stdout.Len() != 0 {
		t.Fatal("failed verify wrote a head")
	}
	assertNoSecret(t, &stderr, secret, pass)
	assertNoSecret(t, &stderr, []byte(wrongVerify["TREMELAY_PASSPHRASE"]), pass)
	wrong := map[string]string{"TREMELAY_PASSPHRASE": randHex(t, 16)}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "get", "--path", path, "--id", id}, envGet(wrong), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("wrong passphrase succeeded")
	}
	if stdout.Len() != 0 {
		t.Fatal("wrong passphrase wrote a secret")
	}
	assertNoSecret(t, &stderr, secret, pass)
	assertNoSecret(t, &stderr, []byte(wrong["TREMELAY_PASSPHRASE"]), pass)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(pass)) {
		t.Fatal("vault file contains secret material")
	}
}

func TestCLIRejectsAgentAndPassphraseArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	secret := randHex(t, 16)
	if code := run([]string{"agent", "get-secret"}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("agent command succeeded")
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatal(stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"vault", "create", "--path", filepath.Join(t.TempDir(), "v"), "--passphrase", secret}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("passphrase argument accepted")
	}
	if strings.Contains(stderr.String(), secret) {
		t.Fatal("stderr echoed passphrase argument")
	}
	stderr.Reset()
	if code := run([]string{"credential", "put", "--secret", secret}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("secret argument accepted")
	}
	if strings.Contains(stderr.String(), secret) {
		t.Fatal("stderr echoed secret argument")
	}
}

func TestCLICreateReportsStdoutWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	env := map[string]string{"TREMELAY_PASSPHRASE": pass}

	writeErr := errors.New("stdout write failed")
	var stderr bytes.Buffer
	if code := run([]string{"vault", "create", "--path", path}, envGet(env), strings.NewReader(""), errWriter{writeErr}, &stderr); code == 0 {
		t.Fatal("create returned success after stdout write failure")
	}
	if !strings.Contains(stderr.String(), writeErr.Error()) {
		t.Fatalf("stderr missing write failure: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), pass) {
		t.Fatal("stderr echoed passphrase")
	}

	var stdout bytes.Buffer
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("verify %d %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("vault missing after a failed create confirmation")
	}
	if strings.Contains(stderr.String(), pass) {
		t.Fatal("stderr echoed passphrase")
	}
}

func TestCLIPutSecretFileRejectionIsAudited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	env := map[string]string{"TREMELAY_PASSPHRASE": pass}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"vault", "create", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("create %d %s", code, stderr.String())
	}

	sentinel := randBytes(t, 32)
	oversized := append(append([]byte{}, sentinel...), make([]byte, vault.MaxSecret+1-len(sentinel))...)
	oversizedPath := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversizedPath, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	emptyPath := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	missingPath := filepath.Join(dir, "missing")
	dirPath := filepath.Join(dir, "not-a-file")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatal(err)
	}

	attempts := []struct {
		file string
		want error
	}{
		{file: emptyPath, want: vault.ErrInvalid},
		{file: oversizedPath, want: vault.ErrInvalid},
		{file: missingPath, want: vault.ErrInvalid},
		{file: dirPath, want: vault.ErrIO},
	}
	for _, attempt := range attempts {
		stdout.Reset()
		stderr.Reset()
		code := run([]string{"credential", "put", "--path", path, "--label", "ci", "--type", "api_key", "--secret-file", attempt.file}, envGet(env), strings.NewReader(""), &stdout, &stderr)
		if code == 0 {
			t.Fatalf("put accepted %s", attempt.file)
		}
		if stdout.Len() != 0 {
			t.Fatal("rejected put wrote stdout")
		}
		if !strings.Contains(stderr.String(), attempt.want.Error()) {
			t.Fatalf("stderr %q, want %s", stderr.String(), attempt.want)
		}
		if bytes.Contains(stderr.Bytes(), sentinel) || strings.Contains(stderr.String(), pass) {
			t.Fatal("stderr contains secret material")
		}
	}
	if n := deniedPutCount(t, path); n != len(attempts) {
		t.Fatalf("denied credential_put events %d", n)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, sentinel) || bytes.Contains(raw, []byte(pass)) {
		t.Fatal("vault file contains secret material")
	}

	good := randBytes(t, 24)
	goodPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(goodPath, good, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "put", "--path", path, "--label", "ci", "--type", "api_key", "--secret-file", goodPath}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("put %d %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("missing id after audited denials")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("verify %d %s", code, stderr.String())
	}
}

func TestCLIPutInvalidFieldsAreAudited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"TREMELAY_PASSPHRASE": pass}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"vault", "create", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("create %d %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "put", "--label", "ci", "--type", "api_key", "--secret-file", secretPath}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("missing vault path code %d %s", code, stderr.String())
	}
	if deniedPutCount(t, path) != 0 {
		t.Fatal("missing vault path wrote a credential_put denial")
	}

	badLabel := "bad-\n" + hex.EncodeToString(secret)
	extra := hex.EncodeToString(secret)
	attempts := [][]string{
		{"credential", "put", "--path", path, "--label", "ci", "--type", "api_key"},
		{"credential", "put", "--path", path, "--type", "api_key", "--secret-file", secretPath},
		{"credential", "put", "--path", path, "--label", "ci", "--secret-file", secretPath},
		{"credential", "put", "--path", path, "--label", "ci", "--type", "not-a-type", "--secret-file", secretPath},
		{"credential", "put", "--path", path, "--label", badLabel, "--type", "api_key", "--secret-file", secretPath},
		{"credential", "put", "--path", path, "--label", "ci", "--type", "api_key", "--secret-file", secretPath, extra},
	}
	for _, args := range attempts {
		stdout.Reset()
		stderr.Reset()
		code := run(args, envGet(env), strings.NewReader(""), &stdout, &stderr)
		if code == 0 {
			t.Fatalf("put accepted %q", args)
		}
		if stdout.Len() != 0 {
			t.Fatal("rejected put wrote stdout")
		}
		if !strings.Contains(stderr.String(), vault.ErrInvalid.Error()) {
			t.Fatalf("stderr %q", stderr.String())
		}
		if !strings.Contains(stderr.String(), "credential_put result=denied") {
			t.Fatalf("stderr missing denial: %s", stderr.String())
		}
		assertNoSecret(t, &stderr, secret, pass)
		if strings.Contains(stderr.String(), badLabel) || strings.Contains(stderr.String(), extra) {
			t.Fatal("stderr echoed rejected label or positional")
		}
	}
	if n := deniedPutCount(t, path); n != len(attempts) {
		t.Fatalf("denied credential_put events %d", n)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(pass)) || bytes.Contains(raw, []byte(badLabel)) || bytes.Contains(raw, []byte(extra)) {
		t.Fatal("vault file contains secret material, rejected label, or positional")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "put", "--path", path, "--label", "ci", "--type", "api_key", "--secret-file", secretPath}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("put %d %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("missing id after audited denials")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("verify %d %s", code, stderr.String())
	}
}

func TestCLIMalformedCredentialArgsAreAudited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
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
	id := strings.TrimSpace(stdout.String())
	extra := hex.EncodeToString(secret)

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "put", "--bogus", "--path", path, "--label", "ci", "--type", "api_key", "--secret-file", secretPath}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("unknown flag before path code %d %s", code, stderr.String())
	}
	if deniedPutCount(t, path) != 0 {
		t.Fatal("unknown flag before path wrote a credential_put denial")
	}

	attempts := []struct {
		args   []string
		action string
		log    string
	}{
		{[]string{"credential", "put", "--path", path, "--bogus"}, "credential_put", "credential_put result=denied"},
		{[]string{"credential", "get", "--path", path, "--bogus"}, "credential_get", "credential_get result=denied"},
		{[]string{"credential", "list", "--path", path, "--bogus"}, "credential_list", "credential_list result=denied"},
		{[]string{"credential", "get", "--path", path, "--id", id, extra}, "credential_get", "credential_get result=denied"},
		{[]string{"credential", "list", "--path", path, extra}, "credential_list", "credential_list result=denied"},
	}
	for _, attempt := range attempts {
		stdout.Reset()
		stderr.Reset()
		code := run(attempt.args, envGet(env), strings.NewReader(""), &stdout, &stderr)
		if code == 0 {
			t.Fatalf("accepted %q", attempt.args)
		}
		if stdout.Len() != 0 {
			t.Fatalf("rejected %q wrote stdout", attempt.args)
		}
		if !strings.Contains(stderr.String(), vault.ErrInvalid.Error()) {
			t.Fatalf("stderr %q", stderr.String())
		}
		if !strings.Contains(stderr.String(), attempt.log) {
			t.Fatalf("stderr missing denial: %s", stderr.String())
		}
		assertNoSecret(t, &stderr, secret, pass)
		if strings.Contains(stderr.String(), extra) {
			t.Fatal("stderr echoed rejected positional")
		}
	}
	if n := deniedPutCount(t, path); n != 1 {
		t.Fatalf("denied credential_put events %d", n)
	}
	if n := deniedActionCount(t, path, "credential_get"); n != 2 {
		t.Fatalf("denied credential_get events %d", n)
	}
	if n := deniedActionCount(t, path, "credential_list"); n != 2 {
		t.Fatalf("denied credential_list events %d", n)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(pass)) || bytes.Contains(raw, []byte(extra)) {
		t.Fatal("vault file contains secret material or rejected positional")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "get", "--path", path, "--id", id}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("get %d %s", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), secret) {
		t.Fatal("get after denial returned the wrong secret")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "list", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("list %d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), id) || bytes.Contains(stdout.Bytes(), secret) {
		t.Fatal("list after denial missing id or included secret")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("verify %d %s", code, stderr.String())
	}
}

func TestCLIGetMissingIDIsAudited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
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
	id := strings.TrimSpace(stdout.String())

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "get", "--id", id}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("missing vault path code %d %s", code, stderr.String())
	}
	if deniedActionCount(t, path, "credential_get") != 0 {
		t.Fatal("missing vault path wrote a credential_get denial")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "get", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("get without id succeeded")
	}
	if stdout.Len() != 0 {
		t.Fatal("get without id wrote stdout")
	}
	if !strings.Contains(stderr.String(), vault.ErrNotFound.Error()) {
		t.Fatalf("stderr %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "credential_get result=denied") {
		t.Fatalf("stderr missing denial: %s", stderr.String())
	}
	assertNoSecret(t, &stderr, secret, pass)
	if n := deniedActionCount(t, path, "credential_get"); n != 1 {
		t.Fatalf("denied credential_get events %d", n)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(pass)) {
		t.Fatal("vault file contains secret material")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "get", "--path", path, "--id", id}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("get %d %s", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), secret) {
		t.Fatal("get after denial returned the wrong secret")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("verify %d %s", code, stderr.String())
	}
}

func TestCLIMissingPassphraseIsAudited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
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
	id := strings.TrimSpace(stdout.String())

	stdout.Reset()
	stderr.Reset()
	missing := filepath.Join(dir, "missing-vault")
	if code := run([]string{"credential", "get", "--path", missing, "--id", id}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("missing vault and passphrase succeeded")
	}
	if !strings.Contains(stderr.String(), vault.ErrPassphrase.Error()) {
		t.Fatalf("stderr %q", stderr.String())
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing passphrase created a vault")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "get", "--path", path, "--id", id}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("get without passphrase succeeded")
	}
	if stdout.Len() != 0 {
		t.Fatal("get without passphrase wrote stdout")
	}
	if !strings.Contains(stderr.String(), vault.ErrPassphrase.Error()) {
		t.Fatalf("stderr %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "vault_unlock result=denied") {
		t.Fatalf("stderr missing denial: %s", stderr.String())
	}
	assertNoSecret(t, &stderr, secret, pass)
	if n := deniedActionCount(t, path, "vault_unlock"); n != 1 {
		t.Fatalf("denied vault_unlock events %d", n)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(pass)) {
		t.Fatal("vault file contains secret material")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "get", "--path", path, "--id", id}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("get %d %s", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), secret) {
		t.Fatal("get after passphrase denial returned the wrong secret")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("verify %d %s", code, stderr.String())
	}
}

func deniedPutCount(t *testing.T, path string) int {
	t.Helper()
	return deniedActionCount(t, path, "credential_put")
}

func deniedActionCount(t *testing.T, path, action string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT credential_id, credential_type FROM audit WHERE action = ? AND result = ?`, action, "denied")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, typ string
		if err := rows.Scan(&id, &typ); err != nil {
			t.Fatal(err)
		}
		if id != "" || typ != "" {
			t.Fatalf("denial carried metadata id=%q type=%q", id, typ)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCLIPutReportsStdoutWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"TREMELAY_PASSPHRASE": pass}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"vault", "create", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("create %d %s", code, stderr.String())
	}

	writeErr := errors.New("stdout write failed")
	stderr.Reset()
	if code := run([]string{"credential", "put", "--path", path, "--label", "ci", "--type", "api_key", "--secret-file", secretPath}, envGet(env), strings.NewReader(""), errWriter{writeErr}, &stderr); code == 0 {
		t.Fatal("put returned success after stdout write failure")
	}
	if !strings.Contains(stderr.String(), writeErr.Error()) {
		t.Fatalf("stderr missing write failure: %s", stderr.String())
	}
	assertNoSecret(t, &stderr, secret, pass)

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "list", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("list %d %s", code, stderr.String())
	}
	var listed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed["label"] != "ci" || listed["id"] == "" {
		t.Fatalf("committed credential missing after stdout write failure: %#v", listed)
	}
	assertNoSecret(t, &stdout, secret, pass)
	assertNoSecret(t, &stderr, secret, pass)
}

func TestCLIGetOutputErrorOmitsSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
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
	id := strings.TrimSpace(stdout.String())

	stderr.Reset()
	if code := run([]string{"credential", "get", "--path", path, "--id", id}, envGet(env), strings.NewReader(""), payloadErrWriter{}, &stderr); code == 0 {
		t.Fatal("get returned success after stdout write failure")
	}
	if bytes.Contains(stderr.Bytes(), secret) || strings.Contains(stderr.String(), pass) {
		t.Fatal("stderr echoed secret material from the writer error")
	}
	if !strings.Contains(stderr.String(), "stdout write failed") {
		t.Fatalf("stderr missing write failure: %s", stderr.String())
	}
}

func TestCLIListOutputErrorOmitsLabel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	label := randHex(t, 32)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"TREMELAY_PASSPHRASE": pass}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"vault", "create", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("create %d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "put", "--path", path, "--label", label, "--type", "api_key", "--secret-file", secretPath}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("put %d %s", code, stderr.String())
	}

	stderr.Reset()
	if code := run([]string{"credential", "list", "--path", path}, envGet(env), strings.NewReader(""), payloadErrWriter{}, &stderr); code == 0 {
		t.Fatal("list returned success after stdout write failure")
	}
	if strings.Contains(stderr.String(), label) || bytes.Contains(stderr.Bytes(), secret) || strings.Contains(stderr.String(), pass) {
		t.Fatal("stderr echoed secret material from the writer error")
	}
	if !strings.Contains(stderr.String(), "stdout write failed") {
		t.Fatalf("stderr missing write failure: %s", stderr.String())
	}
}

func TestCLIAuditVerifyReportsStdoutWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	env := map[string]string{"TREMELAY_PASSPHRASE": pass}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"vault", "create", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("create %d %s", code, stderr.String())
	}

	writeErr := errors.New("stdout write failed")
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(env), strings.NewReader(""), errWriter{writeErr}, &stderr); code == 0 {
		t.Fatal("verify returned success after stdout write failure")
	}
	if !strings.Contains(stderr.String(), writeErr.Error()) {
		t.Fatalf("stderr missing write failure: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), pass) {
		t.Fatal("stderr echoed passphrase")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"audit", "verify", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("verify %d %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("missing audit head after a failed write")
	}
	if strings.Contains(stderr.String(), pass) {
		t.Fatal("stderr echoed passphrase")
	}
}

func TestCLIAgentGrantAndCapability(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secret := randBytes(t, 32)
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
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
	if agentID == "" || strings.Contains(stdout.String(), string(secret)) {
		t.Fatal(stdout.String())
	}
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"grant", "create", "--path", path, "--agent", agentID, "--credential", credID, "--operation", "http_request", "--resource", "svc:one", "--expires", expires}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("grant %d %s", code, stderr.String())
	}
	grantID := strings.TrimSpace(stdout.String())
	assertNoSecret(t, &stdout, secret, pass)
	assertNoSecret(t, &stderr, secret, pass)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"capability", "list", "--path", path, "--agent", agentID}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("list %d %s", code, stderr.String())
	}
	var listed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if _, ok := listed["secret"]; ok || listed["grant_id"] != grantID || listed["status"] != "active" {
		t.Fatalf("list %#v", listed)
	}
	assertNoSecret(t, &stdout, secret, pass)
	assertNoSecret(t, &stderr, secret, pass)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"capability", "authorize", "--path", path, "--agent", agentID, "--credential", credID, "--operation", "http_request", "--resource", "svc:one"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("authorize %d %s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "allowed "+grantID) {
		t.Fatal(stdout.String())
	}
	assertNoSecret(t, &stdout, secret, pass)
	assertNoSecret(t, &stderr, secret, pass)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"capability", "authorize", "--path", path, "--agent", agentID, "--credential", credID, "--operation", "http_request", "--resource", "svc:other"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("wrong scope was authorized")
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "denied_scope") {
		t.Fatalf("stdout %q stderr %s", stdout.String(), stderr.String())
	}
	assertNoSecret(t, &stderr, secret, pass)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"grant", "revoke", "--path", path, "--id", grantID}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("revoke %d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"capability", "authorize", "--path", path, "--agent", agentID, "--credential", credID, "--operation", "http_request", "--resource", "svc:one"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatal("revoked grant authorized")
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "denied_revoked") {
		t.Fatalf("stdout %q stderr %s", stdout.String(), stderr.String())
	}
	assertNoSecret(t, &stderr, secret, pass)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"capability", "get-secret"}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("get-secret %d %s", code, stderr.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(pass)) {
		t.Fatal("vault file contains secret material")
	}
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

// payloadErrWriter reports a failure that includes the rejected bytes.
type payloadErrWriter struct{}

func (payloadErrWriter) Write(p []byte) (int, error) {
	return 0, errors.New("rejected payload " + string(p))
}

func envGet(m map[string]string) func(string) string {
	return func(k string) string {
		if m == nil {
			return ""
		}
		return m[k]
	}
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	return hex.EncodeToString(randBytes(t, n))
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func assertNoSecret(t *testing.T, buf *bytes.Buffer, secret []byte, pass string) {
	t.Helper()
	if bytes.Contains(buf.Bytes(), secret) || strings.Contains(buf.String(), pass) {
		t.Fatal("output contains secret material")
	}
}

func TestCLIReplaceHealthRefreshAndPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	pass := randHex(t, 16)
	secret := []byte("password-" + randHex(t, 8))
	next := randBytes(t, 24)
	secretPath := filepath.Join(dir, "secret")
	nextPath := filepath.Join(dir, "next")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nextPath, next, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"TREMELAY_PASSPHRASE": pass}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"vault", "create", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("create %d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "put", "--path", path, "--label", "pw", "--type", "password", "--secret-file", secretPath}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("put %d %s", code, stderr.String())
	}
	id := strings.TrimSpace(stdout.String())
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "health", "--path", path, "--id", id}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("health %d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"weak"`) || bytes.Contains(stdout.Bytes(), secret) {
		t.Fatalf("health json %s", stdout.String())
	}
	assertNoSecret(t, &stderr, secret, pass)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "refresh", "--path", path, "--id", id}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("refresh %d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "replace", "--path", path, "--id", id, "--secret-file", nextPath}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("replace %d %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != id || bytes.Contains(stdout.Bytes(), next) || bytes.Contains(stderr.Bytes(), next) {
		t.Fatalf("replace output %s %s", stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "lifecycle", "--path", path, "--id", id, "--rotation-every", "1h", "--review-every", "24h"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("lifecycle %d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "list", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("list lifecycle %d %s", code, stderr.String())
	}
	var listed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed["id"] != id || listed["rotation_every"] != "1h0m0s" || listed["review_every"] != "24h0m0s" {
		t.Fatalf("list intervals %#v", listed)
	}
	if _, ok := listed["secret"]; ok || bytes.Contains(stdout.Bytes(), next) {
		t.Fatal("list exposed secret material")
	}
	assertNoSecret(t, &stdout, next, pass)
	assertNoSecret(t, &stderr, secret, pass)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "lifecycle", "--path", path, "--id", id, "--rotation-every", "0s", "--review-every", "0s"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("disable lifecycle %d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "list", "--path", path}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("list disabled %d %s", code, stderr.String())
	}
	listed = nil
	if err := json.Unmarshal(stdout.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed["rotation_every"] != "0s" || listed["review_every"] != "0s" {
		t.Fatalf("disabled intervals %#v", listed)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"credential", "policy", "--path", path, "--compromise-opt-in", "false", "--reminder-lead", "1h"}, envGet(env), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("policy %d %s", code, stderr.String())
	}
	assertNoSecret(t, &stdout, next, pass)
	assertNoSecret(t, &stderr, next, pass)
	assertNoSecret(t, &stderr, secret, pass)
}

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

func TestCLIChangePassphrase(t *testing.T) {
	for _, mode := range []string{"success", "mismatch", "short", "same", "wrong old", "cancel", "output failure"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vault.db")
			old, next := []byte(randHex(t, 24)), []byte(randHex(t, 24))
			s, err := vault.Create(path, old, nil)
			if err != nil {
				t.Fatal(err)
			}
			s.Lock()
			inputOld := old
			if mode == "wrong old" {
				inputOld = []byte(randHex(t, 24))
			}
			if mode == "short" {
				next = []byte("short")
			}
			if mode == "same" {
				next = old
			}
			confirmation := next
			if mode == "mismatch" {
				confirmation = []byte(randHex(t, 24))
			}
			inputs := [][]byte{inputOld, next, confirmation}
			var captured [][]byte
			var prompts []string
			var stdout, stderr bytes.Buffer
			var output io.Writer = &stdout
			if mode == "output failure" {
				output = errWriter{errors.New("synthetic output failure")}
			}
			code := changePassphrase([]string{"--path", path}, output, &stderr, func(prompt string) ([]byte, error) {
				prompts = append(prompts, prompt)
				if mode == "cancel" && len(prompts) == 3 {
					return nil, errors.New("synthetic prompt failure")
				}
				buf := append([]byte(nil), inputs[len(prompts)-1]...)
				captured = append(captured, buf)
				return buf, nil
			})
			changed := mode == "success" || mode == "output failure"
			if (code == 0) != (mode == "success") {
				t.Fatalf("exit %d: %s", code, stderr.String())
			}
			if mode == "wrong old" && len(prompts) != 1 {
				t.Fatal("requested new pass before authenticating old")
			}
			if mode != "wrong old" && strings.Join(prompts, "|") != "old passphrase: |new passphrase: |confirm new passphrase: " {
				t.Fatalf("prompts %v", prompts)
			}
			for _, buf := range captured {
				if !bytes.Equal(buf, make([]byte, len(buf))) {
					t.Fatal("prompt buffer not wiped")
				}
			}
			for _, pass := range [][]byte{old, next, inputOld, confirmation} {
				if len(pass) >= 8 && bytes.Contains(append(stdout.Bytes(), stderr.Bytes()...), pass) {
					t.Fatal("passphrase disclosed")
				}
			}
			valid := old
			if changed {
				valid = next
			}
			if _, err := vault.VerifyAudit(path, valid); err != nil {
				t.Fatalf("authority lost: %v", err)
			}
			if changed {
				if _, err := vault.VerifyAudit(path, old); !errors.Is(err, vault.ErrUnauthenticated) {
					t.Fatal("old pass still works")
				}
			}
			if !changed && !bytes.Equal(old, next) && len(next) >= 8 {
				if _, err := vault.VerifyAudit(path, next); !errors.Is(err, vault.ErrUnauthenticated) {
					t.Fatal("failure granted new authority")
				}
			}
			if mode == "output failure" && !strings.Contains(stderr.String(), "passphrase changed; confirmation output failed") {
				t.Fatal("lost committed outcome")
			}
		})
	}
}

func TestCLIChangePassphraseRequiresTerminal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	pass := randHex(t, 24)
	s, err := vault.Create(path, []byte(pass), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Lock()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"vault", "change-passphrase", "--path", path}, func(string) string { t.Fatal("passphrase change consulted environment"); return pass }, strings.NewReader(pass+"\n"), &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d", code)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("non-terminal invocation changed vault")
	}
	for _, args := range [][]string{
		{"--path", path, "--old-passphrase=" + pass},
		{"--path", path, "--new-passphrase=" + pass},
		{"--path", path, pass},
		{"--path", path, "--path"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := changePassphrase(args, &stdout, &stderr, func(string) ([]byte, error) { t.Fatal("invalid args prompted"); return nil, nil }); code != 2 {
			t.Fatal(code)
		}
		if strings.Contains(stderr.String()+stdout.String(), pass) {
			t.Fatal("argument disclosure")
		}
	}
}

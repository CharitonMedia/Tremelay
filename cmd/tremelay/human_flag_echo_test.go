package main

import (
	"bytes"
	"flag"
	"io"
	"strings"
	"testing"
)

const humanFlagSentinel = "TREMELAY_SENTINEL_DO_NOT_ECHO_7f3a9c2b1d4e8f6a0b5c"

func TestFlagNameFromParseError(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--limit=" + humanFlagSentinel}, "limit"},
		{[]string{"--clear-expires=" + humanFlagSentinel}, "clear-expires"},
		{[]string{"--=" + humanFlagSentinel}, ""},
		{[]string{"--unknown=" + humanFlagSentinel}, "unknown"},
	} {
		fs := flag.NewFlagSet("probe", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.Int("limit", 0, "")
		fs.Bool("clear-expires", false, "")
		err := fs.Parse(tc.args)
		if err == nil {
			t.Fatalf("%v: expected parse error", tc.args)
		}
		if got := flagNameFromParseError(err); got != tc.want {
			t.Fatalf("%v: got %q want %q (err %v)", tc.args, got, tc.want, err)
		}
	}
}

func TestCLIHumanFlagParseErrorsOmitSentinel(t *testing.T) {
	path := "/tmp/tremelay-test-vault"
	id := "cred-id"
	badSyntax := "--=" + humanFlagSentinel

	cases := []struct {
		name string
		args []string
	}{
		{"vault create bad syntax", []string{"vault", "create", badSyntax}},
		{"credential put bad syntax", []string{"credential", "put", "--path", path, badSyntax}},
		{"credential get bad syntax", []string{"credential", "get", "--path", path, badSyntax}},
		{"credential list bad syntax", []string{"credential", "list", "--path", path, badSyntax}},
		{"credential replace clear-review", []string{"credential", "replace", "--path", path, "--id", id, "--clear-review=" + humanFlagSentinel}},
		{"credential lifecycle clear-expires", []string{"credential", "lifecycle", "--path", path, "--id", id, "--clear-expires=" + humanFlagSentinel}},
		{"credential lifecycle clear-rotation", []string{"credential", "lifecycle", "--path", path, "--id", id, "--clear-rotation=" + humanFlagSentinel}},
		{"credential health bad syntax", []string{"credential", "health", "--path", path, badSyntax}},
		{"credential refresh bad syntax", []string{"credential", "refresh", "--path", path, badSyntax}},
		{"credential policy min-length", []string{"credential", "policy", "--path", path, "--min-length=" + humanFlagSentinel}},
		{"credential policy pattern-run", []string{"credential", "policy", "--path", path, "--pattern-run=" + humanFlagSentinel}},
		{"audit verify bad syntax", []string{"audit", "verify", "--path", path, badSyntax}},
		{"audit list limit", []string{"audit", "list", "--path", path, "--limit=" + humanFlagSentinel}},
		{"audit list after", []string{"audit", "list", "--path", path, "--after=" + humanFlagSentinel}},
		{"audit get seq", []string{"audit", "get", "--path", path, "--seq=" + humanFlagSentinel}},
		{"agent create bad syntax", []string{"agent", "create", "--path", path, badSyntax}},
		{"agent token issue bad syntax", []string{"agent", "token", "issue", "--path", path, badSyntax}},
		{"agent token rotate bad syntax", []string{"agent", "token", "rotate", "--path", path, badSyntax}},
		{"agent token revoke bad syntax", []string{"agent", "token", "revoke", "--path", path, badSyntax}},
		{"grant create bad syntax", []string{"grant", "create", "--path", path, badSyntax}},
		{"grant create expires", []string{"grant", "create", "--path", path, "--expires=" + humanFlagSentinel}},
		{"grant revoke bad syntax", []string{"grant", "revoke", "--path", path, badSyntax}},
		{"capability list bad syntax", []string{"capability", "list", "--path", path, badSyntax}},
		{"capability authorize bad syntax", []string{"capability", "authorize", "--path", path, badSyntax}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, envGet(nil), strings.NewReader(""), &stdout, &stderr)
			if code == 0 {
				t.Fatal("parse error succeeded")
			}
			combined := stdout.String() + stderr.String()
			if strings.Contains(combined, humanFlagSentinel) {
				t.Fatalf("output contained sentinel: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLIHumanFlagHelpUnchanged(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"credential", "put", "-h"}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("help exit %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage of credential put:") {
		t.Fatalf("help stderr %q", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-h"}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("top-level help exit %d", code)
	}
	if !strings.Contains(stdout.String(), "tremelay is the human control plane") {
		t.Fatalf("top-level help stdout %q", stdout.String())
	}
}

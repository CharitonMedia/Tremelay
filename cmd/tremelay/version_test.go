package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func TestCLIVersionCommandShape(t *testing.T) {
	shape := regexp.MustCompile(`^tremelay \S+( \(commit [0-9a-f]{7}(, modified)?\)| \(modified\))?\n$`)
	for _, args := range [][]string{{"version"}, {"--version"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, envGet(nil), strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("%v exited %d: %s", args, code, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("%v stderr %q", args, stderr.String())
		}
		if !shape.Match(stdout.Bytes()) {
			t.Fatalf("%v stdout %q", args, stdout.String())
		}
	}
}

func TestCLIShortVersionFlagUnknown(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-v"}, envGet(nil), strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("-v exited %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatal(stderr.String())
	}
}

func TestVersionHelpers(t *testing.T) {
	if got := pickVersion("(devel)", "v9.9.9-test"); got != "v9.9.9-test" {
		t.Fatalf("pickVersion override %q", got)
	}
	if got := pickVersion("v1.0.0", "v9.9.9-test"); got != "v1.0.0" {
		t.Fatalf("pickVersion build info %q", got)
	}
	if got := shortRevision("abcdef0123456789"); got != "abcdef0" {
		t.Fatalf("shortRevision %q", got)
	}
}

// Package release holds the check for `go install` of the published command.
package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `go install github.com/CharitonMedia/Tremelay/cmd/tremelay@REF` resolves the
// module from its import path and fetches it from the proxy. It therefore fails
// if the module path stops matching the GitHub path, if go.mod carries a replace
// directive, or if the command package moves. None of that is caught by a local
// build, so assert it here.
func TestGoInstallPathPreconditions(t *testing.T) {
	const wantModule = "module github.com/CharitonMedia/Tremelay"

	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read application go.mod: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	if got := strings.TrimSpace(lines[0]); got != wantModule {
		t.Errorf("go.mod module path %q, want %q: go install resolves the module from its import path", got, wantModule)
	}
	for i, line := range lines {
		if f := strings.Fields(line); len(f) > 0 && f[0] == "replace" {
			t.Errorf("go.mod:%d has a replace directive (%q); go install ignores it and the install fails", i+1, strings.TrimSpace(line))
		}
	}
	if _, err := os.Stat(filepath.Join(root, "cmd", "tremelay", "main.go")); err != nil {
		t.Errorf("cmd/tremelay/main.go: %v", err)
	}
}

func TestREADMEChecksumVerifyOneLiner(t *testing.T) {
	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"SHA256SUMS | sha256sum -c -",
		"shasum -a 256 -c -",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README.md missing checksum verify one-liner %q (ADR 0027)", want)
		}
	}
}

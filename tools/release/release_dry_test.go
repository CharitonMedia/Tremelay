package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func runReleaseDry(t *testing.T, root, out string, extraEnv ...string) error {
	t.Helper()
	script := filepath.Join(root, "tools", "release-dry.sh")
	env := append(os.Environ(),
		"TREMELAY_VERSION=v0.0.0-test",
		"TREMELAY_RELEASE_OUT="+out,
	)
	env = append(env, extraEnv...)
	cmd := exec.Command("sh", script)
	cmd.Dir = root
	cmd.Env = env
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		return &execError{err: err, output: outBytes}
	}
	if len(outBytes) > 0 {
		t.Logf("release-dry: %s", strings.TrimSpace(string(outBytes)))
	}
	return nil
}

type execError struct {
	err    error
	output []byte
}

func (e *execError) Error() string {
	return e.err.Error() + ": " + strings.TrimSpace(string(e.output))
}

func TestReleaseDryArtifacts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("release-dry integration needs GNU tar and a Linux builder")
	}
	root := repoRoot(t)
	out := t.TempDir()
	if err := runReleaseDry(t, root, out); err != nil {
		t.Fatal(err)
	}

	var tarGz, zip, sbom int
	for _, name := range listNames(t, out) {
		switch {
		case strings.HasSuffix(name, ".tar.gz"):
			tarGz++
		case strings.HasSuffix(name, ".zip"):
			zip++
		case strings.HasSuffix(name, ".cdx.json"):
			sbom++
		}
	}
	if tarGz != 4 || zip != 2 || sbom != 6 {
		t.Fatalf("archives tar.gz=%d zip=%d sbom=%d, want 4/2/6", tarGz, zip, sbom)
	}
	sums, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(sums)), "\n")
	if len(lines) != 12 {
		t.Fatalf("SHA256SUMS has %d lines, want 12", len(lines))
	}
	verify := exec.Command("sha256sum", "-c", "--ignore-missing", "SHA256SUMS")
	verify.Dir = out
	if outVerify, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("sha256sum -c: %v\n%s", err, outVerify)
	}
}

func TestReleaseDryTarFailureExitsNonZero(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("release-dry integration needs GNU tar and a Linux builder")
	}
	root := repoRoot(t)
	out := t.TempDir()
	fakeBin := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeTar := filepath.Join(fakeBin, "tar")
	if err := os.WriteFile(fakeTar, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := runReleaseDry(t, root, out, "PATH="+fakeBin+":"+os.Getenv("PATH"))
	if err == nil {
		t.Fatal("expected release-dry to fail when tar fails")
	}
	matches, _ := filepath.Glob(filepath.Join(out, "*.tar.gz"))
	for _, path := range matches {
		info, statErr := os.Stat(path)
		if statErr != nil {
			continue
		}
		// ponytail: empty-input gzip is ~20 bytes; a failed piped tar used to produce that.
		if info.Size() <= 32 {
			t.Fatalf("suspiciously small archive %s (%d bytes) after tar failure", path, info.Size())
		}
	}
}

func listNames(t *testing.T, dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	return names
}

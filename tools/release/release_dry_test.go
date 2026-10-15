package release

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
	verify := exec.Command("sha256sum", "-c", "SHA256SUMS")
	verify.Dir = out
	if outVerify, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("sha256sum -c: %v\n%s", err, outVerify)
	}
	// A checksum says nothing about what is inside the archive: zip and tar
	// take options from the environment, and an --exclude there would ship a
	// LICENSE-only archive that verifies.
	assertArchivesHoldTheBinary(t, out)
}

// TestReleaseDryIgnoresArchiveOptionsFromTheEnvironment covers a builder whose
// environment carries ZIPOPT or TAR_OPTIONS: Info-ZIP appends the first and GNU
// tar prepends the second, so an --exclude there would ship an archive with no
// binary that still matches its checksum.
func TestReleaseDryIgnoresArchiveOptionsFromTheEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("release-dry integration needs GNU tar and a Linux builder")
	}
	out := t.TempDir()
	if err := runReleaseDry(t, repoRoot(t), out,
		"ZIPOPT=-x *.exe", "TAR_OPTIONS=--exclude=tremelay*"); err != nil {
		t.Fatal(err)
	}
	assertArchivesHoldTheBinary(t, out)
}

// TestReleaseDryRefusesRelativeOutput covers the output override naming a
// different directory at each of the script's cd steps, starting with the
// caller's own, which it would rm -rf.
func TestReleaseDryRefusesRelativeOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("release-dry integration needs a POSIX shell")
	}
	caller := t.TempDir()
	precious := filepath.Join(caller, "dist", "release")
	if err := os.MkdirAll(precious, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(precious, "sentinel-not-ours-to-delete")
	if err := os.WriteFile(keep, []byte("sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", filepath.Join(repoRoot(t), "tools", "release-dry.sh"))
	cmd.Dir = caller
	cmd.Env = append(os.Environ(), "TREMELAY_VERSION=v0.0.0-test", "TREMELAY_RELEASE_OUT=dist/release")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("a relative output path was accepted")
	}
	if !strings.Contains(string(output), "must be an absolute path") {
		t.Fatalf("unexpected failure: %s", output)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the caller's directory was touched: %v", err)
	}
}

// assertArchivesHoldTheBinary opens every archive and requires the binary its
// name promises, plus LICENSE.
func assertArchivesHoldTheBinary(t *testing.T, out string) {
	t.Helper()
	for _, name := range listNames(t, out) {
		path := filepath.Join(out, name)
		var members []string
		switch {
		case strings.HasSuffix(name, ".zip"):
			zr, err := zip.OpenReader(path)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			for _, f := range zr.File {
				members = append(members, f.Name)
			}
			zr.Close()
		case strings.HasSuffix(name, ".tar.gz"):
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(f)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			tr := tar.NewReader(gz)
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				members = append(members, h.Name)
			}
			f.Close()
		default:
			continue
		}
		want := "tremelay"
		if strings.Contains(name, "windows") {
			want += ".exe"
		}
		if !slices.Contains(members, want) || !slices.Contains(members, "LICENSE") {
			t.Fatalf("%s holds %v, want %s and LICENSE", name, members, want)
		}
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

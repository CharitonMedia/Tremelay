package release

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	var tarGz, zip, mcpb, sbom int
	for _, name := range listNames(t, out) {
		switch {
		case strings.HasSuffix(name, ".tar.gz"):
			tarGz++
		case strings.HasSuffix(name, ".zip"):
			zip++
		case strings.HasSuffix(name, ".mcpb"):
			mcpb++
		case strings.HasSuffix(name, ".cdx.json"):
			sbom++
		}
	}
	if tarGz != 4 || zip != 2 || mcpb != 6 || sbom != 12 {
		t.Fatalf("archives tar.gz=%d zip=%d mcpb=%d sbom=%d, want 4/2/6/12", tarGz, zip, mcpb, sbom)
	}
	sums, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(sums)), "\n")
	if len(lines) != 24 {
		t.Fatalf("SHA256SUMS has %d lines, want 24", len(lines))
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
	assertMCPBundles(t, out)
	assertRenderedServerJSON(t, out)
}

func TestReleaseDryMCPBReproducible(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("release-dry integration needs GNU tar and a Linux builder")
	}
	root := repoRoot(t)
	outA := t.TempDir()
	outB := t.TempDir()
	if err := runReleaseDry(t, root, outA); err != nil {
		t.Fatal(err)
	}
	if err := runReleaseDry(t, root, outB); err != nil {
		t.Fatal(err)
	}
	for _, name := range listNames(t, outA) {
		if !strings.HasSuffix(name, ".mcpb") {
			continue
		}
		a, err := os.ReadFile(filepath.Join(outA, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(outB, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("%s differs between two release-dry runs", name)
		}
	}
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

func assertMCPBundles(t *testing.T, out string) {
	t.Helper()
	version := "v0.0.0-test"
	for _, target := range []string{
		"linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64",
		"windows_amd64", "windows_arm64",
	} {
		mcpbName := "tremelay-mcp_" + version + "_" + target + ".mcpb"
		archiveBin := archiveBinaryBytes(t, out, version, target)
		assertMCPBundleContents(t, filepath.Join(out, mcpbName), target, archiveBin)
	}
}

func archiveBinaryBytes(t *testing.T, out, version, target string) []byte {
	t.Helper()
	osName := target
	if i := strings.LastIndex(target, "_"); i >= 0 {
		osName = target[:i]
	}
	base := "tremelay_" + version + "_" + target
	var path string
	if osName == "windows" {
		path = filepath.Join(out, base+".zip")
	} else {
		path = filepath.Join(out, base+".tar.gz")
	}
	wantName := "tremelay"
	if osName == "windows" {
		wantName += ".exe"
	}
	return extractMember(t, path, wantName)
}

func extractMember(t *testing.T, archivePath, member string) []byte {
	t.Helper()
	switch {
	case strings.HasSuffix(archivePath, ".zip"):
		zr, err := zip.OpenReader(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		defer zr.Close()
		for _, f := range zr.File {
			if f.Name != member {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
		t.Fatalf("%s: missing %s", archivePath, member)
	case strings.HasSuffix(archivePath, ".tar.gz"):
		f, err := os.Open(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if h.Name != member {
				continue
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
		t.Fatalf("%s: missing %s", archivePath, member)
	default:
		t.Fatalf("unsupported archive %s", archivePath)
	}
	return nil
}

func assertMCPBundleContents(t *testing.T, mcpbPath, target string, wantBin []byte) {
	t.Helper()
	osName := target[:strings.LastIndex(target, "_")]
	zr, err := zip.OpenReader(mcpbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var manifest []byte
	var serverBin []byte
	hasLicense := false
	serverMember := "server/tremelay"
	if osName == "windows" {
		serverMember += ".exe"
	}
	for _, f := range zr.File {
		switch f.Name {
		case "manifest.json":
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			manifest, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
		case serverMember:
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			serverBin, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
		case "LICENSE":
			hasLicense = true
		}
	}
	if manifest == nil {
		t.Fatalf("%s: no manifest.json at zip root", mcpbPath)
	}
	if !hasLicense {
		t.Fatalf("%s: missing LICENSE", mcpbPath)
	}
	if serverBin == nil {
		t.Fatalf("%s: missing %s", mcpbPath, serverMember)
	}
	if !bytes.Equal(serverBin, wantBin) {
		t.Fatalf("%s: %s bytes differ from release archive binary", mcpbPath, serverMember)
	}
	low := strings.ToLower(string(manifest))
	for _, forbidden := range []string{"passphrase", "sensitive"} {
		if strings.Contains(low, forbidden) {
			t.Fatalf("%s manifest.json contains forbidden text %q", mcpbPath, forbidden)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(manifest, &doc); err != nil {
		t.Fatalf("%s manifest.json: %v", mcpbPath, err)
	}
	if doc["manifest_version"] != "0.3" {
		t.Fatalf("%s manifest_version %v", mcpbPath, doc["manifest_version"])
	}
	if doc["name"] != "tremelay" || doc["display_name"] != "Tremelay" {
		t.Fatalf("%s unexpected name/display_name: %v / %v", mcpbPath, doc["name"], doc["display_name"])
	}
	if doc["version"] != "0.0.0-test" {
		t.Fatalf("%s version %v", mcpbPath, doc["version"])
	}
	server, _ := doc["server"].(map[string]any)
	if server == nil || server["type"] != "binary" {
		t.Fatalf("%s server block: %v", mcpbPath, doc["server"])
	}
	if server["entry_point"] != serverMember {
		t.Fatalf("%s entry_point %v want %s", mcpbPath, server["entry_point"], serverMember)
	}
	mcpCfg, _ := server["mcp_config"].(map[string]any)
	if mcpCfg == nil {
		t.Fatalf("%s missing mcp_config", mcpbPath)
	}
	args, _ := mcpCfg["args"].([]any)
	if len(args) != 4 || args[0] != "mcp" || args[1] != "--daemon" || args[2] != "--token-file" {
		t.Fatalf("%s args %v", mcpbPath, args)
	}
	userCfg, _ := doc["user_config"].(map[string]any)
	if userCfg == nil {
		t.Fatalf("%s missing user_config", mcpbPath)
	}
	tok, _ := userCfg["token_file"].(map[string]any)
	if tok == nil || tok["type"] != "file" || tok["required"] != true {
		t.Fatalf("%s token_file: %v", mcpbPath, userCfg["token_file"])
	}
	wantPlatform := map[string]string{
		"linux": "linux", "darwin": "darwin", "windows": "win32",
	}[osName]
	compat, _ := doc["compatibility"].(map[string]any)
	platforms, _ := compat["platforms"].([]any)
	if len(platforms) != 1 || platforms[0] != wantPlatform {
		t.Fatalf("%s platforms %v want [%s]", mcpbPath, platforms, wantPlatform)
	}
}

func assertRenderedServerJSON(t *testing.T, out string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(out, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["name"] != "io.github.CharitonMedia/tremelay" {
		t.Fatalf("server.json name %v", doc["name"])
	}
	pkgs, _ := doc["packages"].([]any)
	if len(pkgs) != 6 {
		t.Fatalf("server.json packages len %d", len(pkgs))
	}
	for _, p := range pkgs {
		pkg, _ := p.(map[string]any)
		if pkg == nil {
			t.Fatal("bad package entry")
		}
		if pkg["registryType"] != "mcpb" {
			t.Fatalf("registryType %v", pkg["registryType"])
		}
		id, _ := pkg["identifier"].(string)
		if !strings.Contains(id, "mcp") {
			t.Fatalf("identifier %q must contain mcp", id)
		}
		hash, _ := pkg["fileSha256"].(string)
		base := filepath.Base(id)
		onDisk, err := os.ReadFile(filepath.Join(out, base))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(onDisk)
		if hash != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s fileSha256 %q != %s", base, hash, hex.EncodeToString(sum[:]))
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

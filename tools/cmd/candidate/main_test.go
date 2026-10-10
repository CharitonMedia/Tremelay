package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/tools/evidence"
)

func TestProfileEnvDisablesAmbientConfig(t *testing.T) {
	t.Setenv("GOEXPERIMENT", "fieldtrack")
	t.Setenv("GOCACHEPROG", "echo")
	t.Setenv("GOWORK", "on")
	t.Setenv("GOFIPS140", "latest")
	env := envMap(profileEnv(filepath.Join("go", "bin", "go"), filepath.Join(t.TempDir(), "mod"), filepath.Join(t.TempDir(), "cache")))
	want := map[string]string{
		"GOENV": "off", "GOWORK": "off", "GOEXPERIMENT": "", "GOCACHEPROG": "", "GOFIPS140": "off",
		"GOTOOLCHAIN": evidence.GoToolchain, "GOOS": evidence.TargetGOOS, "GOARCH": evidence.TargetGOARCH,
		"CGO_ENABLED": evidence.TargetCGO, "GOFLAGS": "-mod=readonly",
	}
	for k, v := range want {
		if env[k] != v {
			t.Fatalf("%s=%q, want %q", k, env[k], v)
		}
	}
	if _, ok := env["GOEXPERIMENT"]; !ok {
		t.Fatal("GOEXPERIMENT was not explicitly configured")
	}
	tool := envMap(toolEnv(filepath.Join("go", "bin", "go"), filepath.Join(t.TempDir(), "mod"), filepath.Join(t.TempDir(), "cache")))
	if tool["GOENV"] != "off" || tool["GOWORK"] != "off" || tool["GOCACHEPROG"] != "" || tool["GOEXPERIMENT"] != "" {
		t.Fatalf("tool env %+v", tool)
	}
}

func TestGoEnvIgnoresPersistedConfig(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configDir := filepath.Join(home, ".config", "go")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "GOEXPERIMENT=fieldtrack\nGOCACHEPROG=/tmp/evil-cacheprog\nGOFIPS140=latest\n"
	if err := os.WriteFile(filepath.Join(configDir, "env"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bare := exec.Command(goBin, "env", "GOEXPERIMENT", "GOCACHEPROG", "GOFIPS140")
	bare.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "GOTOOLCHAIN=" + evidence.GoToolchain}
	out, err := bare.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "fieldtrack") || !strings.Contains(string(out), "/tmp/evil-cacheprog") {
		t.Fatalf("poisoned go env was not readable: %q", out)
	}
	env := profileEnv(goBin, t.TempDir(), t.TempDir())
	for i, e := range env {
		if strings.HasPrefix(e, "HOME=") {
			env[i] = "HOME=" + home
		}
	}
	cmd := exec.Command(goBin, "env", "GOEXPERIMENT", "GOCACHEPROG", "GOFIPS140", "GOWORK")
	cmd.Env = env
	out, err = cmd.Output()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 || fields[0] != "off" || fields[1] != "off" {
		t.Fatalf("persisted Go settings leaked into the candidate environment: %q", out)
	}
}

func TestArchiveUsesCapturedCommit(t *testing.T) {
	root := gitRepo(t)
	writeRepoFile(t, root, "go.mod", "module example.com/old\n\ngo 1.26.9\n")
	gitCommit(t, root, "old")
	commit, err := gitOut(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, root, "go.mod", "module example.com/new\n\ngo 1.26.9\n")
	gitCommit(t, root, "new")
	dest := t.TempDir()
	if err := extractArchive(root, commit, dest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "example.com/old") {
		t.Fatalf("archive followed moving HEAD:\n%s", b)
	}
	if err := extractArchive(root, "HEAD", dest); err == nil {
		t.Fatal("expected refusal to archive HEAD")
	}
}

func TestStableSourceRejectsDrift(t *testing.T) {
	root := gitRepo(t)
	writeRepoFile(t, root, "go.mod", "module example.com/x\n\ngo 1.26.9\n")
	gitCommit(t, root, "one")
	commit, err := gitOut(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := gitOut(root, "rev-parse", commit+"^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	if err := assertStableSource(root, commit, tree); err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, root, "go.mod", "module example.com/y\n\ngo 1.26.9\n")
	gitCommit(t, root, "two")
	if err := assertStableSource(root, commit, tree); err == nil {
		t.Fatal("expected commit drift")
	}
}

func TestScanParseFailureKeepsExitStatus(t *testing.T) {
	_, meta, err := finishScan("binary", []string{"govulncheck"}, evidence.Identity{}, time.Now().UTC(), time.Now().UTC(), "", 2, []byte("not-json\n"))
	if err == nil {
		t.Fatal("expected parse error")
	}
	if meta.ExitStatus != 2 || meta.SymbolGatePass {
		t.Fatalf("exit %d gate %v", meta.ExitStatus, meta.SymbolGatePass)
	}
}

func TestScanFailureKeepsVerifiedDir(t *testing.T) {
	out := filepath.Join(t.TempDir(), "m11a-candidate")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "tremelay"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	meta := evidence.ScanMeta{Scope: "binary", ExitStatus: 3, RawReport: evidence.ReportName("binary")}
	err := persistScanFailure(out, "binary", []byte("{"), meta, errString("govulncheck json"))
	if err == nil {
		t.Fatal("expected scan failure")
	}
	b, err := os.ReadFile(filepath.Join(out, "tremelay"))
	if err != nil || string(b) != "keep" {
		t.Fatalf("verified evidence changed: %q %v", b, err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(out), "m11a-scan-failure-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("failure records: %v %v", matches, err)
	}
	saved, err := os.ReadFile(filepath.Join(matches[0], "govulncheck-binary-meta.json"))
	if err != nil || !strings.Contains(string(saved), `"exit_status": 3`) {
		t.Fatalf("failure metadata: %s %v", saved, err)
	}
}

func TestModVerifyDetectsCacheModification(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/corrupt\n\ngo 1.26.9\n\nrequire github.com/google/uuid v1.6.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package corrupt\n\nimport _ \"github.com/google/uuid\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	gocache := t.TempDir()
	t.Cleanup(func() {
		for _, root := range []string{cache, gocache} {
			filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					os.Chmod(path, 0o755)
				} else {
					os.Chmod(path, 0o644)
				}
				return nil
			})
		}
	})
	prep := controlledEnv(goBin, cache, gocache)
	for i, e := range prep {
		if strings.HasPrefix(e, "GOFLAGS=") {
			prep[i] = "GOFLAGS="
		}
	}
	cmd := exec.Command(goBin, "mod", "tidy")
	cmd.Dir = dir
	cmd.Env = prep
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tidy: %v\n%s", err, out)
	}
	env := profileEnv(goBin, cache, gocache)
	if err := requireModVerify(goBin, dir, env, "application"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cache, "github.com", "google", "uuid@v1.6.0", "uuid.go")
	if _, err := os.Stat(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if err := requireModVerify(goBin, dir, env, "application"); err == nil {
		t.Fatal("modified module cache was verified")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	gitRun(t, root, "init")
	gitRun(t, root, "config", "user.email", "candidate@example.com")
	gitRun(t, root, "config", "user.name", "candidate")
	return root
}

func gitCommit(t *testing.T, root, message string) {
	t.Helper()
	gitRun(t, root, "add", "-A")
	gitRun(t, root, "commit", "-m", message)
}

func gitRun(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeRepoFile(t *testing.T, root, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

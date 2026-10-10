package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
	configDir, identity := userConfigIdentity(home)
	if err := os.MkdirAll(filepath.Join(configDir, "go"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "GOEXPERIMENT=fieldtrack\nGOCACHEPROG=/tmp/evil-cacheprog\nGOFIPS140=latest\n"
	if err := os.WriteFile(filepath.Join(configDir, "go", "env"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bare := exec.Command(goBin, "env", "GOEXPERIMENT", "GOCACHEPROG", "GOFIPS140")
	bare.Env = append([]string{"PATH=" + os.Getenv("PATH"), "GOTOOLCHAIN=" + evidence.GoToolchain}, identity...)
	out, err := bare.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "fieldtrack") || !strings.Contains(string(out), "/tmp/evil-cacheprog") {
		t.Fatalf("poisoned go env was not readable: %q", out)
	}
	env := profileEnv(goBin, t.TempDir(), t.TempDir())
	for _, e := range identity {
		k, v, _ := strings.Cut(e, "=")
		env = setEnv(env, k, v)
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
	err := persistAttemptFailure(out, []scanRecord{{scope: "binary", raw: []byte("{"), meta: meta}}, errString("govulncheck json"))
	if err == nil {
		t.Fatal("expected scan failure")
	}
	b, err := os.ReadFile(filepath.Join(out, "tremelay"))
	if err != nil || string(b) != "keep" {
		t.Fatalf("verified evidence changed: %q %v", b, err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(out), "m11a-failed-attempt-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("failure records: %v %v", matches, err)
	}
	saved, err := os.ReadFile(filepath.Join(matches[0], "govulncheck-binary-meta.json"))
	if err != nil || !strings.Contains(string(saved), `"exit_status": 3`) {
		t.Fatalf("failure metadata: %s %v", saved, err)
	}
}

func TestBlockedScansPersistEvidence(t *testing.T) {
	called := govulncheckJSON("binary", "{\"finding\":{\"osv\":\"GO-2026-0001\",\"trace\":[{\"module\":\"example.com/dep\",\"function\":\"F\"}]}}\n")
	clean := govulncheckJSON("binary", "")
	moduleOnly := govulncheckJSON("binary", "{\"finding\":{\"osv\":\"GO-2026-0002\",\"trace\":[{\"module\":\"example.com/dep\",\"version\":\"v1.2.3\"}]}}\n")
	now := time.Now().UTC()
	if _, _, err := finishScan("binary", []string{"govulncheck"}, evidence.Identity{}, now, now, "", 0, moduleOnly); err != nil {
		t.Fatalf("module finding is visible and does not fail the symbol gate: %v", err)
	}
	cases := []struct {
		name string
		exit int
		raw  []byte
		want string
	}{
		{"called finding exit zero", 0, called, "symbol-level"},
		{"parseable nonzero exit", 1, clean, "exit status 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, meta, err := finishScan("binary", []string{"govulncheck"}, evidence.Identity{}, now, now, "", tc.exit, tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v", err)
			}
			if meta.ExitStatus != tc.exit || meta.SymbolGatePass {
				t.Fatalf("exit %d gate %v", meta.ExitStatus, meta.SymbolGatePass)
			}
			out := filepath.Join(t.TempDir(), "m11a-candidate")
			if err := os.MkdirAll(out, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "tremelay"), []byte("keep"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := persistAttemptFailure(out, []scanRecord{{scope: "binary", raw: raw, meta: meta}}, err); err == nil {
				t.Fatal("expected scan failure")
			}
			if b, err := os.ReadFile(filepath.Join(out, "tremelay")); err != nil || string(b) != "keep" {
				t.Fatalf("verified evidence changed: %q %v", b, err)
			}
			dir := oneFailureDir(t, filepath.Dir(out))
			saved, err := os.ReadFile(filepath.Join(dir, "govulncheck-binary.json"))
			if err != nil || string(saved) != string(raw) {
				t.Fatalf("raw report: %s %v", saved, err)
			}
			metaText, err := os.ReadFile(filepath.Join(dir, "govulncheck-binary-meta.json"))
			if err != nil || !strings.Contains(string(metaText), "\"exit_status\": "+strconv.Itoa(tc.exit)) {
				t.Fatalf("metadata: %s %v", metaText, err)
			}
		})
	}
}

func TestLaterScanKeepsEarlierReport(t *testing.T) {
	now := time.Now().UTC()
	sourceRaw := govulncheckJSON("source", "")
	raw, meta, err := finishScan("source", []string{"govulncheck"}, evidence.Identity{}, now, now, "", 0, sourceRaw)
	if err != nil {
		t.Fatal(err)
	}
	binaryRaw := []byte("not-json\n")
	braw, bmeta, err := finishScan("binary", []string{"govulncheck"}, evidence.Identity{}, now, now, "", 2, binaryRaw)
	if err == nil {
		t.Fatal("expected binary parse failure")
	}
	if bmeta.ExitStatus != 2 {
		t.Fatalf("exit %d", bmeta.ExitStatus)
	}
	out := filepath.Join(t.TempDir(), "m11a-candidate")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "tremelay"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := persistAttemptFailure(out, []scanRecord{
		{scope: "source", raw: raw, meta: meta},
		{scope: "binary", raw: braw, meta: bmeta},
	}, err); err == nil {
		t.Fatal("expected scan failure")
	}
	if b, err := os.ReadFile(filepath.Join(out, "tremelay")); err != nil || string(b) != "keep" {
		t.Fatalf("verified evidence changed: %q %v", b, err)
	}
	dir := oneFailureDir(t, filepath.Dir(out))
	saved, err := os.ReadFile(filepath.Join(dir, "govulncheck-source.json"))
	if err != nil || string(saved) != string(sourceRaw) {
		t.Fatalf("source report: %s %v", saved, err)
	}
	if _, err := os.ReadFile(filepath.Join(dir, "govulncheck-source-meta.json")); err != nil {
		t.Fatal(err)
	}
	saved, err = os.ReadFile(filepath.Join(dir, "govulncheck-binary.json"))
	if err != nil || string(saved) != "not-json\n" {
		t.Fatalf("binary report: %s %v", saved, err)
	}
}

func TestPublishRechecksSource(t *testing.T) {
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
	out := filepath.Join(t.TempDir(), "m11a-candidate")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "tremelay"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	staging := t.TempDir()
	if err := os.WriteFile(filepath.Join(staging, "tremelay"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, root, "go.mod", "module example.com/y\n\ngo 1.26.9\n")
	gitCommit(t, root, "two")
	if err := publishVerified(root, commit, tree, staging, out); err == nil {
		t.Fatal("expected source drift to stop publication")
	}
	b, err := os.ReadFile(filepath.Join(out, "tremelay"))
	if err != nil || string(b) != "old" {
		t.Fatalf("verified candidate changed: %q %v", b, err)
	}
	if _, err := os.ReadFile(filepath.Join(staging, "tremelay")); err != nil {
		t.Fatalf("unpublished staging was removed: %v", err)
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
	home := t.TempDir()
	gopath := t.TempDir()
	t.Cleanup(func() {
		for _, root := range []string{cache, gocache, gopath, home} {
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
	prep = applyPlatform(prep, home, gopath)
	cmd := exec.Command(goBin, "mod", "tidy")
	cmd.Dir = dir
	cmd.Env = prep
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tidy: %v\n%s", err, out)
	}
	env := applyPlatform(profileEnv(goBin, cache, gocache), home, gopath)
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

func TestBootstrapControlsHelper(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join("..", "..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(makefile), "sh tools/bootstrap-candidate.sh") || strings.Contains(string(makefile), "go run") {
		t.Fatalf("make candidate still builds the helper with ambient go run:\n%s", makefile)
	}
	scriptPath := filepath.Join("..", "..", "bootstrap-candidate.sh")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	verifyAt := strings.Index(text, "go mod verify")
	buildAt := strings.Index(text, "go build -mod=readonly")
	if verifyAt < 0 || buildAt < 0 || verifyAt > buildAt {
		t.Fatal("bootstrap must verify the tools module cache before building the helper")
	}
	for _, needle := range []string{
		"GOENV=off", "GOWORK=off", "GOEXPERIMENT=", "GOCACHEPROG=", "GOFIPS140=off",
		"GOFLAGS=-mod=readonly", "GOSUMDB=sum.golang.org", "go mod download",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("bootstrap missing %s", needle)
		}
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		return
	}
	home := t.TempDir()
	configDir, identity := userConfigIdentity(home)
	if err := os.MkdirAll(filepath.Join(configDir, "go"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "go", "env"), []byte("GOEXPERIMENT=fieldtrack\nGOCACHEPROG=/tmp/evil-cacheprog\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, scriptPath, "print-env")
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "TMPDIR=" + t.TempDir()}, identity...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	env := append([]string{}, identity...)
	env = append(env, "PATH="+os.Getenv("PATH"))
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimRight(line, "\r")
		k, _, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			t.Fatalf("print-env line %q", line)
		}
		env = setEnv(env, k, strings.TrimPrefix(line, k+"="))
	}
	if got := envValue(env, "GOENV"); got != "off" || envValue(env, "GOFLAGS") != "-mod=readonly" || envValue(env, "GOWORK") != "off" {
		t.Fatalf("print-env %+v", env)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	probe := exec.Command(goBin, "env", "GOEXPERIMENT", "GOCACHEPROG")
	probe.Env = env
	out, err = probe.Output()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(string(out), "fieldtrack") || strings.Contains(string(out), "evil-cacheprog") {
		t.Fatalf("bootstrap env read persisted Go settings: %q", out)
	}
}

func userConfigIdentity(home string) (string, []string) {
	switch runtime.GOOS {
	case "windows":
		appData := filepath.Join(home, "AppData", "Roaming")
		return appData, []string{"HOME=" + home, "USERPROFILE=" + home, "APPDATA=" + appData}
	case "darwin":
		return filepath.Join(home, "Library", "Application Support"), []string{"HOME=" + home}
	default:
		return filepath.Join(home, ".config"), []string{"HOME=" + home}
	}
}

func applyPlatform(env []string, home, gopath string) []string {
	_, identity := userConfigIdentity(home)
	for _, e := range identity {
		k, v, _ := strings.Cut(e, "=")
		env = setEnv(env, k, v)
	}
	return setEnv(env, "GOPATH", gopath)
}

func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix)
		}
	}
	return ""
}

func govulncheckJSON(mode, body string) []byte {
	return []byte(`{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"` + evidence.VulnVersion + `","db":"https://vuln.go.dev","db_last_modified":"2026-10-08T22:31:09Z","scan_level":"symbol","scan_mode":"` + mode + `"}}` + "\n" + body)
}

func oneFailureDir(t *testing.T, parent string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(parent, "m11a-failed-attempt-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("failure records: %v %v", matches, err)
	}
	return matches[0]
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

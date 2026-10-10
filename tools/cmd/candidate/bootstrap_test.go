package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the actual shell entry point without building or running a candidate.
// The fake Go executable is visible only in this subprocess's private PATH.
func TestBootstrapExecution(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "bootstrap-candidate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, mode, wantError string
		build, execute        bool
	}{
		{"clean identity and host profile", "success", "", true, true},
		{"different host profile", "alternate-host", "", true, true},
		{"initial dirty source", "dirty-before", "refusing modified source", false, false},
		{"clean checkout changes during preparation", "checkout", "source identity changed", true, false},
		{"source becomes dirty during build", "dirty-build", "refusing modified source", true, false},
		{"module integrity before build", "verify-before", "tools module cache:", false, false},
		{"module integrity after build", "verify-after", "tools module cache changed before exec", true, false},
		{"module inputs change during download", "module-before", "tools go.mod/go.sum changed", false, false},
		{"module inputs change during build", "module-after", "tools go.mod/go.sum changed", true, false},
		{"wrong toolchain", "wrong-version", "want go1.26.9", false, false},
		{"helper exit and cleanup", "helper-failure", "exit status 23", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := gitRepo(t)
			gitRun(t, root, "config", "core.autocrlf", "false")
			toolsDir := filepath.Join(root, "tools")
			if err := os.MkdirAll(filepath.Join(toolsDir, "cmd", "candidate"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeRepoFile(t, root, "tools/bootstrap-candidate.sh", string(script))
			writeRepoFile(t, root, "tools/go.mod", "module example.com/bootstrap\n\ngo 1.26.9\n")
			writeRepoFile(t, root, "tools/go.sum", "synthetic module integrity fixture\n")
			writeRepoFile(t, root, "tools/cmd/candidate/main.go", "package main\n// old helper source\n")
			gitCommit(t, root, "synthetic original source")
			commit, err := gitOut(root, "rev-parse", "HEAD")
			if err != nil {
				t.Fatal(err)
			}
			tree, err := gitOut(root, "rev-parse", "HEAD^{tree}")
			if err != nil {
				t.Fatal(err)
			}
			writeRepoFile(t, root, "tools/cmd/candidate/main.go", "package main\n// new helper source\n")
			gitCommit(t, root, "synthetic replacement source")
			replacement, err := gitOut(root, "rev-parse", "HEAD")
			if err != nil {
				t.Fatal(err)
			}
			gitRun(t, root, "checkout", "--quiet", commit)
			if tc.mode == "dirty-before" {
				writeRepoFile(t, root, "untracked.txt", "uncommitted source\n")
			}

			private := t.TempDir()
			temp := filepath.Join(private, "tmp")
			fakeBin := filepath.Join(private, "bin")
			for _, dir := range []string{temp, fakeBin} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(fakeBin, "go"), []byte(bootstrapFakeGo), 0o755); err != nil {
				t.Fatal(err)
			}
			helper := "#!/bin/sh\nset -eu\n[ \"$1\" = --root ]\ngit -C \"$2\" rev-parse HEAD > \"$TEST_EXECUTED\"\nif [ \"$TEST_MODE\" = helper-failure ]; then exit 23; fi\n"
			if err := os.WriteFile(filepath.Join(private, "helper"), []byte(helper), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(sh, "tools/bootstrap-candidate.sh")
			cmd.Dir = root
			cmd.Env = os.Environ()
			for k, v := range map[string]string{
				"PATH":   fakeBin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"TMPDIR": filepath.ToSlash(temp), "TEST_PRIVATE": filepath.ToSlash(private),
				"TEST_ROOT": filepath.ToSlash(root), "TEST_MODE": tc.mode,
				"TEST_REPLACEMENT": replacement, "TEST_EXECUTED": filepath.ToSlash(filepath.Join(private, "executed")),
				"TEST_BOUND": "-X main.bootstrapCommit=" + commit + " -X main.bootstrapTree=" + tree,
				"GOOS":       "plan9", "GOARCH": "mips", "GOHOSTOS": "poison", "GOHOSTARCH": "poison",
				"GOAMD64": "v4", "GO386": "sse2", "GOARM": "7", "GOARM64": "v9.5",
				"GOMIPS": "hardfloat", "GOMIPS64": "hardfloat", "GOPPC64": "power10",
				"GORISCV64": "rva23u64", "GOWASM": "satconv,signext", "CGO_ENABLED": "1",
				"GOENV": "/poison/go-env", "GOWORK": "/poison/go.work", "GOROOT": "/poison/go",
				"GOFLAGS": "-overlay=/poison/overlay.json", "GOEXPERIMENT": "fieldtrack",
				"GOCACHEPROG": "/poison/cache", "GOFIPS140": "latest", "GOTOOLCHAIN": "auto",
				"GO_EXTLINK_ENABLED": "1", "GOPRIVATE": "*", "GONOSUMDB": "*", "GONOPROXY": "*", "GOINSECURE": "*",
				"CC": "/poison/cc", "CXX": "/poison/cxx", "CGO_CFLAGS": "-poison", "CGO_LDFLAGS": "-poison",
			} {
				cmd.Env = setEnv(cmd.Env, k, v)
			}
			out, runErr := cmd.CombinedOutput()
			if tc.wantError == "" && runErr != nil {
				t.Fatalf("bootstrap: %v\n%s", runErr, out)
			}
			if tc.wantError != "" && (runErr == nil || !strings.Contains(fmt.Sprint(runErr)+string(out), tc.wantError)) {
				t.Fatalf("bootstrap: %v\n%s\nwant %q", runErr, out, tc.wantError)
			}
			log, err := os.ReadFile(filepath.Join(private, "calls"))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if built := strings.Contains(string(log), "build -mod=readonly"); built != tc.build {
				t.Fatalf("built=%v, want %v; calls:\n%s", built, tc.build, log)
			}
			executed, err := os.ReadFile(filepath.Join(private, "executed"))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if got := err == nil; got != tc.execute {
				t.Fatalf("executed=%v, want %v; calls:\n%s", got, tc.execute, log)
			}
			if tc.execute && strings.TrimSpace(string(executed)) != commit {
				t.Fatalf("helper root identity %q, want %s", executed, commit)
			}
			if tc.mode == "checkout" {
				if err := assertStableSource(root, replacement, mustGitTree(t, root)); err != nil {
					t.Fatalf("fixture did not leave a different clean checkout: %v", err)
				}
			}
			remaining, err := os.ReadDir(temp)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("bootstrap did not clean temporary helper and inputs: %v, %v", remaining, err)
			}
		})
	}
}

func mustGitTree(t *testing.T, root string) string {
	t.Helper()
	tree, err := gitOut(root, "rev-parse", "HEAD^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

const bootstrapFakeGo = `#!/bin/sh
set -eu
fail() { echo "fake Go: $*" >&2; exit 91; }
for pair in GOENV=off GOWORK=off GOEXPERIMENT= GOCACHEPROG= GOFIPS140=off GOTOOLCHAIN=go1.26.9 GO111MODULE=on GOFLAGS=-mod=readonly CGO_ENABLED=0 GO_EXTLINK_ENABLED=0 GOAMD64=v1 GO386=softfloat GOARM=5,softfloat GOARM64=v8.0 GOMIPS=softfloat GOMIPS64=softfloat GOPPC64=power8 GORISCV64=rva20u64 GOWASM= GOPRIVATE= GONOPROXY= GONOSUMDB= GOINSECURE=; do
    key=${pair%%=*}
    eval 'value=${'"$key"'-not-set}'
    [ "$key=$value" = "$pair" ] || fail "unexpected $key=$value"
done
for key in GOROOT GOHOSTOS GOHOSTARCH CC CXX CGO_CFLAGS CGO_LDFLAGS; do
    eval 'value=${'"$key"'-}'
    [ -z "$value" ] || fail "inherited $key=$value"
done
host_os=linux host_arch=amd64
if [ "$TEST_MODE" = alternate-host ]; then host_os=darwin; host_arch=arm64; fi
printf '%s\n' "$*" >> "$TEST_PRIVATE/calls"
case "$*" in
    "env GOVERSION")
        if [ "$TEST_MODE" = wrong-version ]; then echo go1.26.8; else echo go1.26.9; fi
        exit ;;
    "env GOHOSTOS"|"env GOHOSTARCH")
        [ -z "${GOOS-}" ] && [ -z "${GOARCH-}" ] || fail "host discovery inherited a target"
        if [ "$2" = GOHOSTOS ]; then echo "$host_os"; else echo "$host_arch"; fi
        exit ;;
esac
[ "$GOOS/$GOARCH" = "$host_os/$host_arch" ] || fail "helper target is not the Go host"
case "$*" in
    "env GOPATH") echo "$TEST_PRIVATE/gopath"; exit ;;
    "env GOMODCACHE") echo "$TEST_PRIVATE/modcache"; exit ;;
    "mod download")
        if [ "$TEST_MODE" = checkout ]; then git -C "$TEST_ROOT" checkout --quiet "$TEST_REPLACEMENT"; fi
        if [ "$TEST_MODE" = module-before ]; then echo changed >> go.mod; fi
        ;;
    "mod verify")
        count=0
        if [ -f "$TEST_PRIVATE/verifies" ]; then count=$(cat "$TEST_PRIVATE/verifies"); fi
        count=$((count + 1))
        echo "$count" > "$TEST_PRIVATE/verifies"
        case "$TEST_MODE/$count" in
            verify-before/1|verify-after/2) echo 'fixture module checksum mismatch'; exit ;;
        esac
        echo 'all modules verified'
        ;;
    "build "*)
        [ "$(cat cmd/candidate/main.go)" = 'package main
// old helper source' ] || fail "build used the moving checkout instead of captured source"
        output= bound=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -o) output=$2; shift ;;
                -ldflags) bound=$2; shift ;;
            esac
            shift
        done
        [ "$bound" = "$TEST_BOUND" ] || fail "helper not linked to the captured commit/tree"
        [ -n "$output" ] || fail "no helper output"
        if [ "$TEST_MODE" = dirty-build ]; then echo dirty >> "$TEST_ROOT/tools/cmd/candidate/main.go"; fi
        if [ "$TEST_MODE" = module-after ]; then echo changed >> go.sum; fi
        cp "$TEST_PRIVATE/helper" "$output"
        chmod +x "$output"
        ;;
    *) fail "unexpected command $*" ;;
esac
`

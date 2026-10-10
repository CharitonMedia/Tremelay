package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/tools/evidence"
)

func fixtureIdentity(t *testing.T, root string) (string, string) {
	t.Helper()
	commit, err := gitOut(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := gitOut(root, "rev-parse", commit+"^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	return commit, tree
}

func TestHelperRequiresMatchingBootstrapSource(t *testing.T) {
	root := gitRepo(t)
	writeRepoFile(t, root, "input.txt", "captured")
	gitCommit(t, root, "captured helper source")
	commit, tree := fixtureIdentity(t, root)
	if err := checkBootstrapSource(root, commit, tree); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"", ""}, {commit, ""}, {commit, "HEAD"}, {commit, strings.Repeat("0", 40)}} {
		if err := checkBootstrapSource(root, pair[0], pair[1]); err == nil {
			t.Fatalf("unbound or mismatched helper source accepted: %q", pair)
		}
	}
	writeRepoFile(t, root, "input.txt", "later clean checkout")
	gitCommit(t, root, "later source")
	if err := checkBootstrapSource(root, commit, tree); err == nil {
		t.Fatal("helper compiled from an earlier source accepted a later clean checkout")
	}
}

func TestCompletedScansRetainedOnLaterFailures(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"module verification", "source drift", "write", "final verification", "publication"} {
		t.Run(failure, func(t *testing.T) {
			root := gitRepo(t)
			writeRepoFile(t, root, "go.mod", "module example.com/fixture\n\ngo 1.26.9\n")
			gitCommit(t, root, "fixture")
			commit, tree := fixtureIdentity(t, root)
			out := filepath.Join(t.TempDir(), "m11a-candidate")
			if err := os.Mkdir(out, 0o755); err != nil {
				t.Fatal(err)
			}
			writeRepoFile(t, out, "tremelay", "previous verified candidate")
			staging := t.TempDir()
			id := evidence.Identity{SourceCommit: commit, SourceTree: tree, ArtifactSHA256: strings.Repeat("1", 64)}
			var scans []scanRecord
			for _, scope := range []string{"source", "binary"} {
				now := time.Now().UTC()
				raw, meta, err := finishScan(scope, []string{"govulncheck"}, id, now, now, "", 0, govulncheckJSON(scope, ""))
				if err != nil {
					t.Fatal(err)
				}
				scans = append(scans, scanRecord{scope: scope, raw: raw, meta: meta})
			}
			var cause error
			err = withScanEvidence(out, func(record func(scanRecord)) error {
				for _, sc := range scans {
					record(sc)
				}
				switch failure {
				case "module verification":
					writeRepoFile(t, root, "go.mod", "invalid module definition\n")
					cause = requireModVerify(goBin, root, controlledEnv(goBin, t.TempDir(), t.TempDir()), "application")
				case "source drift":
					writeRepoFile(t, root, "changed.txt", "changed after scans")
					cause = assertStableSource(root, commit, tree)
				case "write":
					cause = evidence.WriteJSON(staging, map[string]string{"state": "cannot replace a directory"})
				case "final verification":
					cause = evidence.Verify(staging, filepath.Join("..", "..", "schema", "cyclonedx"))
				case "publication":
					cause = publishVerified(root, commit, tree, filepath.Join(staging, "missing"), out)
				}
				return cause
			})
			if cause == nil || err == nil || !errors.Is(err, cause) {
				t.Fatalf("failure lost: cause %v, result %v", cause, err)
			}
			dir := oneFailureDir(t, filepath.Dir(out))
			for _, sc := range scans {
				raw, err := os.ReadFile(filepath.Join(dir, evidence.ReportName(sc.scope)))
				if err != nil || string(raw) != string(sc.raw) {
					t.Fatalf("%s raw report lost: %v", sc.scope, err)
				}
				data, err := os.ReadFile(filepath.Join(dir, "govulncheck-"+sc.scope+"-meta.json"))
				if err != nil {
					t.Fatal(err)
				}
				var meta evidence.ScanMeta
				if err := json.Unmarshal(data, &meta); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(meta, sc.meta) {
					t.Fatalf("%s actual scan status changed: got %+v, want %+v", sc.scope, meta, sc.meta)
				}
			}
			marker, err := os.ReadFile(filepath.Join(dir, "FAILED.txt"))
			if err != nil || !strings.Contains(string(marker), "FAILED candidate attempt") || !strings.Contains(string(marker), cause.Error()) {
				t.Fatalf("missing explicit failure: %s %v", marker, err)
			}
			if b, err := os.ReadFile(filepath.Join(out, "tremelay")); err != nil || string(b) != "previous verified candidate" {
				t.Fatalf("previous evidence changed: %s %v", b, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "README.md")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed attempt has a success README")
			}
		})
	}
}

func TestSuccessfulScanPhaseDoesNotWriteFailureEvidence(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "m11a-candidate")
	if err := withScanEvidence(out, func(record func(scanRecord)) error {
		record(scanRecord{scope: "source"})
		record(scanRecord{scope: "binary"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("success wrote failure evidence: %v %v", entries, err)
	}
}

func TestPublishRechecksAfterIncomingPreparation(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		for _, drift := range []string{"none", "clean commit", "dirty source"} {
			t.Run("copy="+strconv.FormatBool(fallback)+"/"+drift, func(t *testing.T) {
				root := gitRepo(t)
				writeRepoFile(t, root, "input.txt", "one")
				gitCommit(t, root, "one")
				commit, tree := fixtureIdentity(t, root)
				parent := t.TempDir()
				out := filepath.Join(parent, "m11a-candidate")
				if err := os.Mkdir(out, 0o755); err != nil {
					t.Fatal(err)
				}
				writeRepoFile(t, out, "tremelay", "old")
				staging := t.TempDir()
				writeRepoFile(t, staging, "tremelay", "new")
				prepared := false
				err := publishWithPreparation(root, commit, tree, staging, out, func(src, dst string) error {
					rename := os.Rename
					if fallback {
						rename = func(string, string) error { return errors.New("cross-device rename unavailable") }
					}
					if err := prepareIncoming(src, dst, rename); err != nil {
						return err
					}
					if b, err := os.ReadFile(filepath.Join(dst, "tremelay")); err != nil || string(b) != "new" {
						t.Fatalf("incoming not prepared: %q %v", b, err)
					}
					prepared = true
					if drift != "none" {
						writeRepoFile(t, root, "input.txt", "changed after incoming preparation")
						if drift == "clean commit" {
							gitCommit(t, root, "two")
						}
					}
					return nil
				})
				if !prepared {
					t.Fatal("publication did not prepare incoming evidence")
				}
				want := "new"
				if drift != "none" {
					want = "old"
					if err == nil {
						t.Fatal("source drift after preparation was accepted")
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if b, err := os.ReadFile(filepath.Join(out, "tremelay")); err != nil || string(b) != want {
					t.Fatalf("candidate %q, want %q: %v", b, want, err)
				}
				entries, err := os.ReadDir(parent)
				if err != nil || len(entries) != 1 || entries[0].Name() != "m11a-candidate" {
					t.Fatalf("publication left temporary evidence: %v %v", entries, err)
				}
			})
		}
	}
}

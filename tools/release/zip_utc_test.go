package release

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestReleaseDryZipUsesUTC guards the fix for a Windows archive whose checksum
// depended on the builder's timezone, because zip writes local time into each
// entry. The script's TZ=UTC prefix is the property this repository owns;
// whether an unforced zip actually differs depends on the builder having
// tzdata, so that half is a demonstration and skips where it cannot run.
func TestReleaseDryZipUsesUTC(t *testing.T) {
	script, err := os.ReadFile(filepath.Join(repoRoot(t), "tools", "release-dry.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "TZ=UTC zip") {
		t.Fatal("release-dry.sh does not run zip with TZ=UTC")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the timezone demonstration needs Info-ZIP on Linux")
	}
	stage := t.TempDir()
	exe := filepath.Join(stage, "tremelay.exe")
	lic := filepath.Join(stage, "LICENSE")
	if err := os.WriteFile(exe, []byte("sentinel-exe-not-a-real-binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lic, []byte("sentinel-license-text"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("touch", "-t", "198001010000", exe, lic).Run(); err != nil {
		t.Fatal(err)
	}
	zipWithTZ := func(tz string) []byte {
		out := filepath.Join(t.TempDir(), "artifact.zip")
		cmd := exec.Command("zip", "-qX9", out, filepath.Base(exe), "LICENSE")
		cmd.Dir = stage
		cmd.Env = append(os.Environ(), "TZ="+tz)
		if err := cmd.Run(); err != nil {
			t.Fatalf("zip TZ=%s: %v", tz, err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	utc := zipWithTZ("UTC")
	if bytes.Equal(utc, zipWithTZ("America/Los_Angeles")) {
		t.Skip("zip ignores TZ on this builder (no tzdata); the script's TZ=UTC prefix is asserted above")
	}
	if !bytes.Equal(utc, zipWithTZ("UTC")) {
		t.Fatal("two TZ=UTC runs over the same staged files differed")
	}
}

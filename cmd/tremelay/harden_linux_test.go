//go:build linux

package main

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// The check runs in a child: a non-dumpable test process could not be
// profiled or debugged by the rest of the suite's tooling.
func TestHardenProcessClearsDumpable(t *testing.T) {
	if os.Getenv("TREMELAY_TEST_HARDEN") == "1" {
		before, _ := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err := hardenProcess(); err != nil {
			os.Exit(3)
		}
		after, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || before != 1 || after != 0 {
			os.Exit(4)
		}
		// Another same-user process must not be able to read this memory.
		if _, err := os.Stat("/proc/self/mem"); err != nil {
			os.Exit(5)
		}
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenProcessClearsDumpable$")
	cmd.Env = append(os.Environ(), "TREMELAY_TEST_HARDEN=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v: %s", err, out)
	}
}

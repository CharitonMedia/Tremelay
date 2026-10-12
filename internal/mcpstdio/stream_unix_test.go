//go:build linux || darwin

package mcpstdio

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func testSocket(t *testing.T, family, kind int) int {
	t.Helper()
	fd, err := unix.Socket(family, kind, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func TestInheritedStreamClassification(t *testing.T) {
	for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
		pair, err := unix.Socketpair(unix.AF_UNIX, kind, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range pair {
			if got := ValidInheritedStream(fd); got != (kind == unix.SOCK_STREAM) {
				t.Errorf("socketpair classification: kind %d, accepted %t", kind, got)
			}
		}
		for _, fd := range pair {
			_ = unix.Close(fd)
		}
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if !ValidInheritedStream(int(read.Fd())) || !ValidInheritedStream(int(write.Fd())) {
		t.Fatal("inherited FIFO rejected")
	}
	regular, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	device, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	for _, fd := range []int{-1, int(regular.Fd()), int(device.Fd()), testSocket(t, unix.AF_INET, unix.SOCK_STREAM), testSocket(t, unix.AF_UNIX, unix.SOCK_STREAM)} {
		if ValidInheritedStream(fd) {
			t.Fatal("non-IPC or unconnected descriptor accepted")
		}
	}
	// A bound pathname socket is rejected without ever listening or accepting.
	dir, err := os.MkdirTemp("", "mcp-stdio-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	named := testSocket(t, unix.AF_UNIX, unix.SOCK_STREAM)
	if err := unix.Bind(named, &unix.SockaddrUnix{Name: filepath.Join(dir, "s")}); err != nil {
		t.Fatal(err)
	}
	if ValidInheritedStream(named) {
		t.Fatal("named Unix endpoint accepted")
	}
}

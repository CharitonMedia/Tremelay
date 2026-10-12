package mcpstdio

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnnamedAddressRejectsEmptyAbstractName(t *testing.T) {
	fd := testSocket(t, unix.AF_UNIX, unix.SOCK_STREAM)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: "@"}); err != nil {
		if err == unix.EADDRINUSE {
			t.Skip("empty abstract name already occupied")
		}
		t.Fatal(err)
	}
	// x/sys displays this and a truly unnamed endpoint as "@". The raw
	// returned length must distinguish them even before checking a peer.
	if unnamedUnixAddress(fd, unix.SYS_GETSOCKNAME) {
		t.Fatal("empty abstract name accepted as unnamed")
	}
}

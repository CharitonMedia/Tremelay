package mcpstdio

import "golang.org/x/sys/unix"

// Darwin's interested read filter maps EV_EOF to POLLHUP, including buffered
// data; the existing POLLIN/POLLHUP watcher needs no extra event bit.
const ReadHalfClosed = 0

func unnamedUnixPair(fd int) bool {
	local, err := unix.Getsockname(fd)
	if err != nil {
		return false
	}
	peer, err := unix.Getpeername(fd)
	if err != nil {
		return false
	}
	// Darwin has pathname Unix addresses, not Linux's abstract namespace.
	// x/sys's BSD decoder honors sockaddr.Len. XNU returns its zero-data
	// sun_noname sentinel for unnamed endpoints, decoded as an empty name.
	l, localUnix := local.(*unix.SockaddrUnix)
	p, peerUnix := peer.(*unix.SockaddrUnix)
	return localUnix && peerUnix && l.Name == "" && p.Name == ""
}

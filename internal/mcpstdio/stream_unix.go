//go:build linux || darwin

// Package mcpstdio classifies already-owned inherited local MCP descriptors.
// It does not open, bind, connect or listen on a transport.
package mcpstdio

import "golang.org/x/sys/unix"

// ValidInheritedStream accepts FIFOs and connected unnamed Unix stream pairs.
// The caller must own fd throughout this check and all subsequent I/O.
func ValidInheritedStream(fd int) bool {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		return false
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFIFO:
		return true
	case unix.S_IFSOCK:
		kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || kind != unix.SOCK_STREAM {
			return false
		}
		return unnamedUnixPair(fd)
	default:
		return false
	}
}

//go:build linux

package main

import "golang.org/x/sys/unix"

// peerUID reads the kernel's record of the connected peer's credentials.
// Linux reports them through SO_PEERCRED on the accepted socket.
func peerUID(fd int) int {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || cred == nil {
		return -1
	}
	return int(cred.Uid)
}

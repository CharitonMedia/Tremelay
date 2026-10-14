//go:build darwin

package main

import "golang.org/x/sys/unix"

// xucredVersion is XNU's only defined xucred layout version. x/sys does not
// export it. An unknown version means the uid field is not where this build
// expects it, so it fails closed rather than trusting the decoded value.
// See https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ucred.h
const xucredVersion = 0

// peerUID reads the kernel's record of the connected peer's credentials.
// Darwin reports them through LOCAL_PEERCRED, the same source getpeereid uses.
func peerUID(fd int) int {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil || cred == nil || cred.Version != xucredVersion {
		return -1
	}
	return int(cred.Uid)
}

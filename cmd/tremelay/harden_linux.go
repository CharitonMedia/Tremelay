//go:build linux

package main

import "golang.org/x/sys/unix"

// hardenProcess marks this process non-dumpable. Every command holds the
// vault key in memory, the daemon for hours. Without this, another process
// of the same user can read that memory through ptrace or /proc/PID/mem
// wherever the host allows same-user tracing (kernel.yama.ptrace_scope=0),
// and a crash writes it to a core file. Children the process starts, such
// as the alert command, are reset to dumpable by exec.
//
// ponytail: Linux only. macOS has ptrace(PT_DENY_ATTACH) and Windows has
// process mitigation policies; neither is applied. Root is not stopped on
// any platform.
func hardenProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

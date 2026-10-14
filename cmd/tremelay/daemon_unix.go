//go:build linux || darwin

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

const (
	daemonSocketName   = "daemon.sock"
	sshAgentSocketName = "ssh-agent.sock"
)

// daemonDir is the user-only directory that holds the endpoint. XDG_RUNTIME_DIR
// is already a per-user directory the OS clears on logout; the fallback is a
// uid-named directory this process creates and checks itself.
func daemonDir(getenv func(string) string) string {
	if getenv != nil {
		if run := getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(run) {
			return filepath.Join(run, "tremelay")
		}
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("tremelay-%d", os.Getuid()))
}

func daemonEndpoint(getenv func(string) string) string {
	return filepath.Join(daemonDir(getenv), daemonSocketName)
}

// sshAgentDefaultSocket sits beside the daemon endpoint, in the same
// already-verified user-only directory.
func sshAgentDefaultSocket(getenv func(string) string) string {
	return filepath.Join(daemonDir(getenv), sshAgentSocketName)
}

func daemonListen(getenv func(string) string) (net.Listener, string, error) {
	path := daemonEndpoint(getenv)
	listener, err := listenUserSocket(path)
	if err != nil {
		return nil, "", err
	}
	return listener, path, nil
}

// listenUserSocket refuses to serve on anything but a directory and socket
// this uid owns with no group or other access. An existing socket that still
// answers is a running endpoint, not a stale file to replace.
func listenUserSocket(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, errDaemonEndpoint
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, errDaemonEndpoint
	}
	if err := ownedExclusively(dir, os.ModeDir); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := ownedExclusively(path, os.ModeSocket); err != nil {
			return nil, err
		}
		if conn, err := net.Dial("unix", path); err == nil {
			conn.Close()
			return nil, errDaemonRunning
		}
		if err := os.Remove(path); err != nil {
			return nil, errDaemonEndpoint
		}
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, errDaemonEndpoint
	}
	// Bind inherits the process umask. The 0700 parent already excludes other
	// users during that window; this makes the socket itself user-only too.
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, errDaemonEndpoint
	}
	return listener, nil
}

func daemonDial(getenv func(string) string) (net.Conn, error) {
	return net.Dial("unix", daemonEndpoint(getenv))
}

// userOnlyFile refuses a token file any other user can read. Mode 0 is the
// regular-file case of the same ownership and permission rule the endpoint
// directory and socket are held to.
func userOnlyFile(path string) error {
	if ownedExclusively(path, 0) != nil {
		return errAgentToken
	}
	return nil
}

// createUserOnlyFile writes a new token file nothing but this user can read.
func createUserOnlyFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// ownedExclusively requires the exact file type, this uid as owner, and no
// group or other permission bits.
func ownedExclusively(path string, kind os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errDaemonEndpoint
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errDaemonEndpoint
	}
	if info.Mode()&os.ModeType != kind || info.Mode().Perm()&0o077 != 0 {
		return errDaemonEndpoint
	}
	return nil
}

// daemonPeerAllowed requires the connected peer to run as self. A Unix socket
// inside a 0700 directory already restricts who can reach it; this is the
// independent kernel-reported check that does not depend on path permissions.
func daemonPeerAllowed(conn net.Conn) bool { return peerIsSelf(conn, os.Getuid()) }

func peerIsSelf(conn net.Conn, self int) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok || self < 0 {
		return false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}
	uid := -1
	if err := raw.Control(func(fd uintptr) { uid = peerUID(int(fd)) }); err != nil {
		return false
	}
	return uid >= 0 && uid == self
}

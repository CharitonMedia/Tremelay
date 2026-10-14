//go:build linux || darwin

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

// socketDir is a 0700 temporary directory with a short path. A Unix socket
// path is limited to about 104 bytes on macOS, which t.TempDir's test-named
// path can exhaust on its own.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// daemonTestEnv gives one test its own endpoint directory.
func daemonTestEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{"XDG_RUNTIME_DIR": socketDir(t)}
}

// TestDaemonEndpointPermissions covers the refusals that protect the socket.
func TestDaemonEndpointPermissions(t *testing.T) {
	getenv := envGet(map[string]string{"XDG_RUNTIME_DIR": socketDir(t)})
	listener, endpoint, err := daemonListen(getenv)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Dir(endpoint): 0o700,
		endpoint:               0o600,
	} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s has mode %v, want %v (%v)", path, info.Mode().Perm(), want, err)
		}
	}
	if _, _, err := daemonListen(getenv); err != errDaemonRunning {
		t.Fatalf("second daemon on a live endpoint: %v", err)
	}
	// Leave the socket file behind with nothing listening on it.
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	listener.Close()
	if _, err := os.Lstat(endpoint); err != nil {
		t.Fatalf("stale endpoint fixture: %v", err)
	}

	// A stale socket this user owns is replaced; anything else is refused.
	stale, _, err := daemonListen(getenv)
	if err != nil {
		t.Fatalf("stale endpoint was not replaced: %v", err)
	}
	stale.Close()
	if err := os.Chmod(filepath.Dir(endpoint), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := daemonListen(getenv); err != errDaemonEndpoint {
		t.Fatalf("group-readable endpoint directory accepted: %v", err)
	}
	if err := os.Chmod(filepath.Dir(endpoint), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(endpoint); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(endpoint, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := daemonListen(getenv); err != errDaemonEndpoint {
		t.Fatalf("regular file at the endpoint path accepted: %v", err)
	}
	if err := os.Chmod(endpoint, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := daemonListen(getenv); err != errDaemonEndpoint {
		t.Fatalf("world-writable endpoint path accepted: %v", err)
	}
	// Ownership by another uid is not creatable in an unprivileged test; the
	// stat check that rejects it is the same one exercised above.
	if err := ownedExclusively(endpoint, os.ModeSocket); err != errDaemonEndpoint {
		t.Fatalf("wrong file type accepted: %v", err)
	}
}

// TestDaemonPeerUID exercises the kernel peer-credential check on a real
// connection, including refusal when the daemon runs as a different uid.
func TestDaemonPeerUID(t *testing.T) {
	path := filepath.Join(socketDir(t), "peer.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !daemonPeerAllowed(server) || !peerIsSelf(server, os.Getuid()) {
		t.Fatal("a peer running as this user was refused")
	}
	if peerIsSelf(server, os.Getuid()+1) {
		t.Fatal("a peer running as another uid was accepted")
	}
	if peerIsSelf(server, -1) {
		t.Fatal("an unknown daemon identity was accepted")
	}
	if daemonPeerAllowed(&net.TCPConn{}) {
		t.Fatal("a non-Unix connection was accepted")
	}
}

// TestAgentTokenFileMode covers the Unix half of token-file custody: the mode
// the file is written with, and the refusal of one any other user can read.
func TestAgentTokenFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.token")
	if err := writeAgentToken(path, randBytes(t, vault.AgentTokenLen)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v (%v)", info.Mode().Perm(), err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentToken(path); err != errAgentToken {
		t.Fatalf("group-readable token file accepted: %v", err)
	}
}

// TestDaemonUnusableEndpointRefusesPassphrase blocks the endpoint directory
// with a regular file.
func TestDaemonUnusableEndpointRefusesPassphrase(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	assertEndpointRefusesPassphrase(t, map[string]string{"XDG_RUNTIME_DIR": blocked})
}

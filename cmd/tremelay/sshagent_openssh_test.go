//go:build linux || darwin

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// These tests need real OpenSSH binaries, so they are skipped where those are
// absent. They are the only evidence here about a shipping SSH client; the
// in-process tests prove the protocol and the authority rules.

func lookOpenSSH(t *testing.T, names ...string) []string {
	t.Helper()
	var found []string
	for _, name := range names {
		path, err := exec.LookPath(name)
		if err != nil && name == "sshd" {
			// sshd is not on a login shell's PATH on most distributions.
			if info, statErr := os.Stat("/usr/sbin/sshd"); statErr == nil && !info.IsDir() {
				path, err = "/usr/sbin/sshd", nil
			}
		}
		if err != nil {
			t.Skipf("%s is not installed", name)
		}
		found = append(found, path)
	}
	return found
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// sshOptions are the client options both tests share: no user configuration
// and this socket as the only source of identities. Naming one absent
// IdentityFile replaces OpenSSH's default list, which it expands from the
// passwd entry rather than HOME, so the suite cannot reach a developer's own
// keys.
func (f *sshAgentFixture) sshOptions(knownHosts string, port int) []string {
	return []string{
		"-F", "/dev/null",
		"-o", "IdentityFile=" + filepath.Join(f.dir, "absent-identity"),
		"-o", "IdentityAgent=" + f.socket,
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-p", fmt.Sprint(port),
	}
}

func (f *sshAgentFixture) clientEnv() []string {
	home := filepath.Join(f.dir, "home")
	os.MkdirAll(home, 0o700)
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"SSH_AUTH_SOCK=" + f.socket,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	}
}

func (f *sshAgentFixture) knownHosts(t *testing.T, port int) string {
	t.Helper()
	hostKey, err := ssh.ParsePublicKey(f.hostBlob)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "known_hosts")
	line := fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(hostKey))
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startSSHD runs a real OpenSSH server on the host key this grant pins, with
// the granted public key as its only authorized key. It is skipped rather
// than failed when an unprivileged sshd cannot start on this host.
func (f *sshAgentFixture) startSSHD(t *testing.T, sshd string, port int) {
	t.Helper()
	dir := filepath.Join(f.dir, "sshd")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(ed25519.PrivateKey(f.hostKey), "")
	if err != nil {
		t.Fatal(err)
	}
	hostKeyPath := filepath.Join(dir, "host_ed25519")
	if err := os.WriteFile(hostKeyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	userKey, err := ssh.ParsePublicKey(f.userBlob)
	if err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, ssh.MarshalAuthorizedKey(userKey), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "sshd_config")
	contents := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
AuthorizedKeysFile %s
PidFile %s
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PrintMotd no
LogLevel VERBOSE
`, port, hostKeyPath, authorized, filepath.Join(dir, "sshd.pid"))
	if err := os.WriteFile(config, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "sshd.log")
	server := exec.Command(sshd, "-D", "-f", config, "-E", logPath)
	if err := server.Start(); err != nil {
		t.Skipf("sshd could not start: %v", err)
	}
	t.Cleanup(func() {
		server.Process.Kill()
		server.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(logPath)
			t.Skipf("unprivileged sshd did not accept connections: %s", log)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestSSHAgentOpenSSHGitPush is the V1 item 5 acceptance line with shipping
// binaries: a real ssh client authenticates through this socket to a real
// OpenSSH server, and `git push` over that connection succeeds. The private
// key exists only inside the daemon's vault.
func TestSSHAgentOpenSSHGitPush(t *testing.T) {
	tools := lookOpenSSH(t, "ssh", "sshd", "git")
	sshBin, sshdBin, gitBin := tools[0], tools[1], tools[2]
	f := startSSHAgent(t)
	port := freePort(t)
	f.startSSHD(t, sshdBin, port)
	options := f.sshOptions(f.knownHosts(t, port), port)
	env := f.clientEnv()

	login := exec.Command(sshBin, append(options, f.username+"@127.0.0.1", "echo", "authenticated")...)
	login.Env = env
	out, err := login.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "authenticated") {
		t.Fatalf("ssh through the agent socket failed: %v\n%s\nrelay said %q", err, out, f.agentErr.String())
	}

	remote := filepath.Join(f.dir, "remote.git")
	work := filepath.Join(f.dir, "work")
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = dir
		cmd.Env = append(append([]string{}, env...),
			"GIT_SSH_COMMAND="+strings.Join(append([]string{sshBin}, options...), " "),
			"GIT_AUTHOR_NAME=tremelay", "GIT_AUTHOR_EMAIL=agent@example.invalid",
			"GIT_COMMITTER_NAME=tremelay", "GIT_COMMITTER_EMAIL=agent@example.invalid")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
		return string(output)
	}
	git(f.dir, "init", "--bare", "-q", remote)
	git(f.dir, "init", "-q", work)
	git(work, "commit", "-q", "--allow-empty", "-m", "signed through the vault")
	git(work, "push", "-q", fmt.Sprintf("ssh://%s@127.0.0.1:%d%s", f.username, port, remote), "HEAD:refs/heads/main")

	pushed := git(remote, "log", "-1", "--format=%s", "refs/heads/main")
	if !strings.Contains(pushed, "signed through the vault") {
		t.Fatalf("the remote did not receive the push: %q", pushed)
	}
	completed, _ := f.auditCounts(t)
	if completed < 2 {
		t.Fatalf("%d signatures audited for a login and a push", completed)
	}
}

// TestSSHAgentOpenSSHRefusesPlainPublickey points the same real client at a
// server that cannot speak publickey-hostbound-v00@openssh.com. The client
// binds the agent and sees the identity, then asks for an ordinary publickey
// signature, which this agent refuses: authentication fails and no signature
// is released.
func TestSSHAgentOpenSSHRefusesPlainPublickey(t *testing.T) {
	sshBin := lookOpenSSH(t, "ssh")[0]
	f := startSSHAgent(t)
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), f.userBlob) {
				return nil, fmt.Errorf("unauthorized key")
			}
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(f.hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, _, _, err := ssh.NewServerConn(conn, config); err == nil {
			t.Error("a server without host-bound userauth completed authentication")
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	login := exec.Command(sshBin, append(f.sshOptions(f.knownHosts(t, port), port), f.username+"@127.0.0.1", "true")...)
	login.Env = f.clientEnv()
	if out, err := login.CombinedOutput(); err == nil {
		t.Fatalf("ordinary publickey authentication succeeded: %s", out)
	}
	completed, denied := f.auditCounts(t)
	if completed != 0 {
		t.Fatalf("%d signatures released for ordinary publickey", completed)
	}
	if denied == 0 {
		t.Fatal("the refused signing attempt was not audited")
	}
}

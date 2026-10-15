//go:build linux || darwin || windows

package main

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

// TestDaemonHandshakeCompletesWhenAuthSlow proves the server hello read deadline
// does not cut off token authentication and audit under load (issue #110).
func TestDaemonHandshakeCompletesWhenAuthSlow(t *testing.T) {
	const slow = 12 * time.Second
	vault.SetAuthenticateAgentTokenDelay(slow)
	t.Cleanup(func() { vault.SetAuthenticateAgentTokenDelay(0) })

	f := startDaemon(t, time.Hour)
	worker := f.agents[0]
	start := time.Now()
	agent := f.relay(t, worker.tokenFile)
	if code := agent.finish(t); code != 0 {
		t.Fatalf("slow auth handshake exited %d after %s: %q", code, time.Since(start), agent.stderr.String())
	}
	if time.Since(start) < slow {
		t.Fatalf("handshake finished before auth delay elapsed: %s", time.Since(start))
	}
}

// TestDaemonHandshakeTimeoutMessageDoesNotClaimAudit ensures transport timeouts
// are not described as audit-chain denials.
func TestDaemonHandshakeTimeoutMessageDoesNotClaimAudit(t *testing.T) {
	oldWait := daemonHandshakeWait
	daemonHandshakeWait = 50 * time.Millisecond
	t.Cleanup(func() { daemonHandshakeWait = oldWait })

	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	go func() {
		var one [1]byte
		for {
			if _, err := io.ReadFull(server, one[:]); err != nil || one[0] == '\n' {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(server, daemonOK)
		server.Close()
	}()

	err := daemonRequest(client, daemonHello+daemonVerbAuth+strings.Repeat("a", 64)+"\n")
	if err == nil {
		t.Fatal("expected handshake timeout")
	}
	msg := err.Error()
	if !errors.Is(err, errDaemonHandshakeTimeout) {
		t.Fatalf("expected timeout diagnostic, got %q", msg)
	}
	if strings.Contains(msg, "audit chain") {
		t.Fatalf("timeout claimed an audit reason: %q", msg)
	}
}

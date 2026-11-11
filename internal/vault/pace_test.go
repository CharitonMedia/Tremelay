package vault

import (
	"bufio"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestPacerAllowsBurstThenWaitsOutTheWindow(t *testing.T) {
	const window, burst = 300 * time.Millisecond, 5
	var p pacer
	start := time.Now()
	for range burst {
		p.wait(t.Context(), "a", window, burst)
	}
	if d := time.Since(start); d >= window {
		t.Fatalf("burst waited %v", d)
	}
	// Another source has its own budget.
	p.wait(t.Context(), "b", window, burst)
	if d := time.Since(start); d >= window {
		t.Fatalf("an idle source waited %v", d)
	}
	p.wait(t.Context(), "a", window, burst)
	if d := time.Since(start); d < window {
		t.Fatalf("the attempt past the burst returned after %v, want the window, %v", d, window)
	}
}

func TestPacerWaitEndsWithContext(t *testing.T) {
	var p pacer
	start := time.Now()
	for range 100 {
		p.wait(canceledCtx(), "a", time.Hour, 1)
	}
	if d := time.Since(start); d > time.Minute {
		t.Fatalf("cancelled waits took %v", d)
	}
}

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func paceCount(s *Session, source string) int {
	s.pace.mu.Lock()
	defer s.pace.mu.Unlock()
	return s.pace.seen[source].n
}

// Unknown tokens spend one shared budget, every attempt is still audited, and
// a real agent's login is charged to that agent instead.
func TestFailedLoginsSpendTheSharedBudgetAndAreAudited(t *testing.T) {
	env := grantedAttestEnv(t)
	minted, err := env.s.RotateAgentToken(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	token := append([]byte(nil), minted.Token...)
	Wipe(minted.Token)
	before := len(mcpAuditSnapshot(env.s))
	for range loginPaceBurst {
		if _, err := env.s.AuthenticateAgentToken(t.Context(), randBytesT(t, AgentTokenLen)); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("unknown token: %v", err)
		}
	}
	if got := len(mcpAuditSnapshot(env.s)) - before; got != loginPaceBurst {
		t.Fatalf("%d failed logins left %d audit rows", loginPaceBurst, got)
	}
	if got := paceCount(env.s, ""); got != loginPaceBurst {
		t.Fatalf("shared budget counts %d of %d failed logins", got, loginPaceBurst)
	}
	// The shared budget is spent. A real agent must not wait for it.
	start := time.Now()
	if _, err := env.s.AuthenticateAgentToken(t.Context(), token); err != nil {
		t.Fatalf("real agent refused after a flood: %v", err)
	}
	if d := time.Since(start); d >= loginPaceWindow/2 {
		t.Fatalf("real agent waited %v behind unknown tokens", d)
	}
	if paceCount(env.s, "") != loginPaceBurst || paceCount(env.s, env.agent.ID) != 1 {
		t.Fatal("a real agent's login was not charged to that agent alone")
	}
}

// A wait that shutdown cuts short still decides and audits the attempt.
func TestLoginPacingEndsWithContext(t *testing.T) {
	env := grantedAttestEnv(t)
	env.s.pace.seen = map[string]paceWindow{"": {start: time.Now(), n: loginPaceBurst}}
	before := len(mcpAuditSnapshot(env.s))
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := env.s.AuthenticateAgentToken(ctx, randBytesT(t, AgentTokenLen)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unknown token: %v", err)
	}
	if d := time.Since(start); d >= loginPaceWindow/2 {
		t.Fatalf("cancelled login still waited %v", d)
	}
	if got := len(mcpAuditSnapshot(env.s)) - before; got != 1 {
		t.Fatalf("cancelled login left %d audit rows, want 1", got)
	}
}

// Junk frames cost a commit each, so they are paced per agent and all audited.
func TestJunkFramesArePacedAndStillAudited(t *testing.T) {
	env := grantedAttestEnv(t)
	ep := stdioEndpoint(t, bindCap(t, env.s, env.agent.ID))
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	replies := bufio.NewReader(cr)
	done := make(chan error, 1)
	before := len(mcpAuditSnapshot(env.s))
	start := time.Now()
	go func() { done <- ep.Serve(t.Context(), sr, sw) }()
	const n = agentPaceBurst + 6
	for range n {
		if _, err := cw.Write([]byte("\n")); err != nil {
			t.Fatal(err)
		}
		// Take each refusal before sending more: the endpoint hangs up on a
		// peer that lets a third reply queue, and that is not under test here.
		if _, err := replies.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
	}
	for len(mcpAuditSnapshot(env.s)) < before+n {
		time.Sleep(5 * time.Millisecond)
	}
	if d := time.Since(start); d < agentPaceWindow {
		t.Fatalf("%d junk frames took %v, want at least the window, %v", n, d, agentPaceWindow)
	}
	_ = cw.Close()
	<-done
	if got := len(mcpAuditSnapshot(env.s)) - before; got != n {
		t.Fatalf("%d junk frames left %d audit rows", n, got)
	}
}

// Shutdown must not sit out a pacing wait: the daemon joins every connection
// before it zeroises.
func TestFramePacingEndsWithServe(t *testing.T) {
	env := grantedAttestEnv(t)
	ep := stdioEndpoint(t, bindCap(t, env.s, env.agent.ID))
	env.s.pace.seen = map[string]paceWindow{env.agent.ID: {start: time.Now(), n: agentPaceBurst}}
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	defer cw.Close()
	go io.Copy(io.Discard, cr)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ep.Serve(ctx, sr, sw) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(agentPaceWindow / 2):
		t.Fatal("Serve is still pacing after cancel")
	}
}

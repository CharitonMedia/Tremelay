package vault

import (
	"context"
	"sync"
	"time"
)

// Every attempt is audited, and an audit row is a durable commit under the
// session lock. Pacing is what keeps one source from spending that lock for
// everyone: an attempt is delayed, never dropped, so the row is still written.
//
// The budget is a window, not an even drip. A source that floods gets its
// burst and then silence until the window ends. An even drip would land a
// commit inside every human command, and a human command that loses that race
// fails (ADR 0024); the silence is when the owner can revoke.
//
// ponytail: fixed ceilings, not configuration. An agent that legitimately
// sustains more than 20 frames a second needs these made a setting.
const (
	// One agent, across all its connections: logins and MCP frames.
	agentPaceBurst  = 40
	agentPaceWindow = 2 * time.Second
	// Every caller presenting a token no agent holds, taken together.
	loginPaceBurst  = 10
	loginPaceWindow = 10 * time.Second
)

type paceWindow struct {
	start time.Time
	n     int
}

// pacer admits burst attempts per source in each window. The zero value is
// ready.
type pacer struct {
	mu   sync.Mutex
	seen map[string]paceWindow
}

// wait returns at once for the first burst attempts of source's window. A
// later one waits for the window to end, or for ctx. No wait outlasts one
// window, so many parallel connections loosen the bound instead of being held
// open without limit.
func (p *pacer) wait(ctx context.Context, source string, window time.Duration, burst int) {
	now := time.Now()
	p.mu.Lock()
	if p.seen == nil {
		p.seen = map[string]paceWindow{}
	}
	w := p.seen[source]
	if now.Sub(w.start) >= window {
		w = paceWindow{start: now}
	}
	w.n++
	p.seen[source] = w
	p.mu.Unlock()
	if w.n <= burst {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(w.start.Add(window).Sub(now))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// paceAgent spaces out one agent's audited attempts.
func (s *Session) paceAgent(ctx context.Context, agentID string) {
	if s != nil {
		s.pace.wait(ctx, agentID, agentPaceWindow, agentPaceBurst)
	}
}

// paceLogin spaces out logins before they are audited. A token some agent
// holds is charged to that agent, so a flood of unknown tokens never delays a
// real agent's login. The decision itself is made afterwards, under begin.
func (s *Session) paceLogin(ctx context.Context, token []byte) {
	if s == nil {
		return
	}
	s.mu.Lock()
	id := ""
	if i := s.tokenAgent(token); i >= 0 {
		id = s.agents[i].ID
	}
	s.mu.Unlock()
	if id == "" {
		s.pace.wait(ctx, "", loginPaceWindow, loginPaceBurst)
		return
	}
	s.paceAgent(ctx, id)
}

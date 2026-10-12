package vault

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This uses normal, drained MCP pipes and an interrupted synthetic network
// request. It does not block output or observe another process's database.
func TestMCPNetworkCancellation(t *testing.T) {
	for _, revision := range []string{mcpProtocolRevision, mcpStdio20251125} {
		for _, auditFailure := range []bool{false, true} {
			t.Run(revision+map[bool]string{false: "/audited", true: "/audit-failure"}[auditFailure], func(t *testing.T) {
				e := newMCPNetworkEnv(t)
				client := mcpNetworkClient(t, bindCap(t, e.s, e.agent.ID), revision)
				handle := mcpNetworkHandles(t, client)[OpHTTPRequest]
				entered, stopped := make(chan struct{}), make(chan struct{})
				e.s.httpDo = func(req *http.Request) (*http.Response, error) {
					e.calls++
					if req.Header.Get("Authorization") != "Bearer "+string(e.secret) {
						t.Error("protected upstream did not authenticate")
					}
					close(entered)
					select {
					case <-req.Context().Done():
					case <-time.After(3 * time.Second):
						t.Error("MCP cancellation did not reach network context")
					}
					if auditFailure {
						e.s.commitFault = func() error { return errors.New("induced audit failure") }
					}
					close(stopped)
					return nil, req.Context().Err()
				}
				before := len(mcpAuditSnapshot(e.s))
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				finished := make(chan error, 1)
				go func() {
					result, err := client.cs.CallTool(ctx, &mcp.CallToolParams{Name: toolInvoke, Arguments: map[string]any{"handle": handle}})
					if result != nil && result.StructuredContent != nil {
						t.Error("cancelled call returned a success projection")
					}
					finished <- err
				}()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("network request did not start")
				}
				cancel()
				select {
				case err := <-finished:
					if err == nil {
						t.Error("cancelled call succeeded")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("client cancellation did not finish")
				}
				select {
				case <-stopped:
				case <-time.After(3 * time.Second):
					t.Fatal("network request did not stop")
				}
				waitMCPIdle(t, client.ep)
				rows := mcpNetworkBrokerRows(t, e.s, before)
				want := 2
				if auditFailure {
					want = 1
				}
				if e.calls != 1 || len(rows) != want || rows[0].Result != resultAllowed || (want == 2 && rows[1].Result != resultUpstreamError) {
					t.Fatal("cancelled invocation replayed or lost its audit")
				}
				client.ep.mu.Lock()
				stored := client.ep.auditErr
				client.ep.mu.Unlock()
				if auditFailure && !errors.Is(stored, ErrAudit) {
					t.Fatal("cancellation masked the required audit failure")
				}
				e.s.commitFault = nil
				e.assertSurfaces(t, client)
			})
		}
	}
}

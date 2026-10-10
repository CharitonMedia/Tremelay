package vault

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// These are transport/SDK regressions, not calls into output helpers. Channels
// expose the writer's real delivery transitions without changing production code.
func TestMCPOutputLifecycle(t *testing.T) {
	t.Run("complete-frame-and-write-return", func(t *testing.T) {
		env := approvedShared(t)
		ep := lifecycleEndpoint(t, bindCap(t, env.s, env.agent.ID))
		var writer *stagedMCPWriter
		peer := startLifecyclePeer(t, ep, func(w io.WriteCloser) io.WriteCloser {
			writer = newStagedMCPWriter(w, true)
			return writer
		})
		before := len(mcpAuditSnapshot(env.s))
		firstRead := asyncMCPRead(peer.r)
		peer.send(t, rpcFrame(t, 1, "tools/list", map[string]any{"_meta": mcpMeta()}))
		awaitMCPSignal(t, writer.beforeTail)
		peer.send(t, rpcFrame(t, 2, "tools/list", map[string]any{"_meta": mcpMeta()}))
		waitMCPState(t, ep, func() bool { return ep.pending != nil })
		assertMCPAdmitted(t, ep, 1)
		assertSparse(t, env.s, before, actionAgentCap)
		close(writer.allowTail)
		first := awaitMCPRead(t, firstRead)
		if !bytes.Contains(first, []byte(`"tools"`)) {
			t.Fatalf("first response %s", first)
		}
		awaitMCPSignal(t, writer.afterFrame)
		// The complete frame is visible, but Write still has not returned.
		assertMCPAdmitted(t, ep, 1)
		close(writer.allowReturn)
		busy := readFrame(t, peer.r)
		if !bytes.Contains(busy, []byte(`"id":2`)) || !bytes.Contains(busy, []byte(`"code":-31010`)) {
			t.Fatalf("tail-time request was not rejected %s", busy)
		}
		waitMCPIdle(t, ep)
		peer.send(t, rpcFrame(t, 3, "tools/list", map[string]any{"_meta": mcpMeta()}))
		if got := readFrame(t, peer.r); !bytes.Contains(got, []byte(`"tools"`)) {
			t.Fatalf("next call %s", got)
		}
	})

	t.Run("first-busy-write-allows-cancellation", func(t *testing.T) {
		env := approvedShared(t)
		ep := lifecycleEndpoint(t, bindCap(t, env.s, env.agent.ID))
		entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		defer close(release)
		ep.server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				if method != "tools/call" {
					return next(ctx, method, req)
				}
				close(entered)
				<-ctx.Done()
				close(cancelled)
				select {
				case <-release:
				case <-t.Context().Done():
				}
				return nil, ctx.Err()
			}
		})
		peer := startLifecyclePeer(t, ep, nil)
		before := len(mcpAuditSnapshot(env.s))
		peer.send(t, lifecycleInvoke(t, 10))
		awaitMCPSignal(t, entered)
		peer.send(t, rpcFrame(t, 11, "tools/list", map[string]any{"_meta": mcpMeta()}))
		waitMCPState(t, ep, func() bool { return ep.active != nil })
		// Nobody drains output. This is the first busy response, so an inline
		// Write in Read would strand this cancellation forever.
		peer.send(t, cancellationFrame(t, 10))
		awaitMCPSignal(t, cancelled)
		peer.send(t, cancellationFrame(t, 10))  // duplicate
		peer.send(t, cancellationFrame(t, 999)) // unmatched
		waitMCPAuditCount(t, env.s, before+3)
		// Let the SDK produce a cancelled response behind the blocked busy one.
		release <- struct{}{}
		waitMCPState(t, ep, func() bool { return ep.pending != nil && ep.pending.response })
		assertMCPAdmitted(t, ep, 10)
		busy := readFrame(t, peer.r)
		if !bytes.Contains(busy, []byte(`"id":11`)) || !bytes.Contains(busy, []byte("endpoint busy")) {
			t.Fatalf("busy response %s", busy)
		}
		got := readFrame(t, peer.r)
		if !bytes.Contains(got, []byte(`"id":10`)) || bytes.Contains(got, []byte("signature")) {
			t.Fatalf("cancelled response %s", got)
		}
		waitMCPIdle(t, ep)
		rows := mcpAuditSnapshot(env.s)[before:]
		if len(rows) != 4 {
			t.Fatalf("expected busy, duplicate, unmatched, and one admitted denial: %+v", rows)
		}
		for i, row := range rows {
			want := actionAgentCap
			if i == 3 {
				want = actionLocalAttest
			}
			if row.Action != want || row.Result != resultDenied || row.GrantID != "" || row.CredID != "" {
				t.Fatalf("denial %d: %+v", i, row)
			}
		}
		raw, _ := json.Marshal(rows)
		if bytes.Contains(raw, []byte("untrusted-cancellation-reason")) {
			t.Fatal("cancellation reason reached audit")
		}
	})

	t.Run("queued-response-overflow-closes", func(t *testing.T) {
		env := approvedShared(t)
		cap := bindCap(t, env.s, env.agent.ID)
		list, _ := encodeCapList()
		handle := capCall(t, cap, list).entries[0].handle
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		defer releaseOnce.Do(func() { close(release) })
		env.s.attestFault = func() error { close(entered); <-release; return nil }
		ep := lifecycleEndpoint(t, cap)
		writer := &blockedMCPWriter{entered: make(chan struct{}), closed: make(chan struct{})}
		peer := startLifecyclePeer(t, ep, func(io.WriteCloser) io.WriteCloser { return writer })
		before := len(mcpAuditSnapshot(env.s))
		peer.send(t, rpcFrame(t, 20, "tools/call", map[string]any{
			"name": toolInvoke, "_meta": mcpMeta(), "arguments": invokeArgs(base64.StdEncoding.EncodeToString(handle[:]), []byte("overflow-artifact")),
		}))
		awaitMCPSignal(t, entered)
		peer.send(t, rpcFrame(t, 21, "tools/list", map[string]any{"_meta": mcpMeta()}))
		awaitMCPSignal(t, writer.entered)
		releaseOnce.Do(func() { close(release) })
		waitMCPState(t, ep, func() bool { return ep.pending != nil && ep.pending.response })
		assertMCPAdmitted(t, ep, 20)
		peer.send(t, lifecycleInvoke(t, 22))
		awaitMCPSignal(t, peer.stopped)
		if !errors.Is(peer.err, errMCPOutputFull) {
			t.Fatalf("overflow error %v", peer.err)
		}
		writer.mu.Lock()
		frames := append([][]byte(nil), writer.frames...)
		writer.mu.Unlock()
		if len(frames) != 1 || bytes.Contains(frames[0], []byte("signature")) {
			t.Fatalf("queued result was written after close: %q", frames)
		}
		rows := mcpAuditSnapshot(env.s)[before:]
		allowed, completed, denied := 0, 0, 0
		for _, row := range rows {
			switch row.Result {
			case resultAllowed:
				allowed++
			case resultCompleted:
				completed++
			case resultDenied:
				denied++
			}
		}
		if allowed != 1 || completed != 1 || denied != 2 {
			t.Fatalf("overflow changed execution or denial accounting: %+v", rows)
		}
		// The accepted operation completed, but its queued signature was never
		// delivered. Nothing here retries that ambiguous invocation.
	})

	t.Run("idle-transition-does-not-strand-output", func(t *testing.T) {
		env := approvedShared(t)
		peer := startLifecyclePeer(t, lifecycleEndpoint(t, bindCap(t, env.s, env.agent.ID)), nil)
		before := len(mcpAuditSnapshot(env.s))
		for id := 1; id <= 100; id++ {
			// The next rejection is submitted as soon as the previous frame is
			// consumed, racing the writer's atomic pending-to-idle transition.
			peer.send(t, rpcFrame(t, id, "resources/list", nil))
			got := readFrame(t, peer.r)
			var response struct {
				ID int `json:"id"`
			}
			if err := json.Unmarshal(got, &response); err != nil || response.ID != id {
				t.Fatalf("missing or reordered output %s: %v", got, err)
			}
		}
		waitMCPIdle(t, peer.ep)
		if len(mcpAuditSnapshot(env.s)) != before+100 {
			t.Fatal("rejection count changed")
		}
	})
}

func TestMCPTerminalOutputFailures(t *testing.T) {
	t.Run("short-write", func(t *testing.T) {
		env := approvedShared(t)
		peer := startLifecyclePeer(t, lifecycleEndpoint(t, bindCap(t, env.s, env.agent.ID)), func(io.WriteCloser) io.WriteCloser { return shortMCPWriter{} })
		peer.send(t, rpcFrame(t, 1, "tools/list", map[string]any{"_meta": mcpMeta()}))
		awaitMCPSignal(t, peer.stopped)
		if peer.err == nil {
			t.Fatal("short output write was reported as success")
		}
	})
	t.Run("unmatched-cancellation-audit-failure", func(t *testing.T) {
		env := approvedShared(t)
		env.s.commitFault = func() error { return errors.New("test-only cancellation audit fault") }
		peer := startLifecyclePeer(t, lifecycleEndpoint(t, bindCap(t, env.s, env.agent.ID)), nil)
		before := len(mcpAuditSnapshot(env.s))
		peer.send(t, cancellationFrame(t, 99))
		awaitMCPSignal(t, peer.stopped)
		if !errors.Is(peer.err, ErrAudit) {
			t.Fatalf("cancellation audit failure %v", peer.err)
		}
		if len(mcpAuditSnapshot(env.s)) != before {
			t.Fatal("failed denial claimed as stored")
		}
		got, err := peer.r.ReadBytes('\n')
		if len(got) != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("notification received output %q %v", got, err)
		}
	})
	t.Run("input-closes-blocked-audit-error", func(t *testing.T) {
		env := approvedShared(t)
		env.s.commitFault = func() error { return errors.New("test-only audit fault") }
		writer := &blockedMCPWriter{entered: make(chan struct{}), closed: make(chan struct{})}
		peer := startLifecyclePeer(t, lifecycleEndpoint(t, bindCap(t, env.s, env.agent.ID)), func(io.WriteCloser) io.WriteCloser { return writer })
		peer.send(t, rpcFrame(t, 1, "resources/list", nil))
		awaitMCPSignal(t, writer.entered)
		peer.send(t, cancellationFrame(t, 1))
		awaitMCPSignal(t, peer.stopped)
		if !errors.Is(peer.err, ErrAudit) {
			t.Fatalf("audit failure lost on input closure: %v", peer.err)
		}
	})
}

type shortMCPWriter struct{}

func (shortMCPWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func (shortMCPWriter) Close() error                { return nil }

func TestMCPAuditSessionLifecycle(t *testing.T) {
	env := approvedShared(t)
	ep := lifecycleEndpoint(t, bindCap(t, env.s, env.agent.ID))
	auditErr := ErrAudit
	env.s.commitFault = func() error { return errors.New("test-only audit storage failure") }
	writer := &lateMCPWriter{entered: make(chan struct{}), closed: make(chan struct{}), returnNow: make(chan struct{})}
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(writer.returnNow) })
	peer := startLifecyclePeer(t, ep, func(io.WriteCloser) io.WriteCloser { return writer })
	before := len(mcpAuditSnapshot(env.s))
	peer.send(t, rpcFrame(t, 1, "resources/list", nil))
	awaitMCPSignal(t, writer.entered)
	peer.cancel()
	awaitMCPSignal(t, writer.closed)
	// The prior Write is awake but has not returned. A new Serve must neither
	// enter nor erase the audit failure during that interval.
	if err := ep.Serve(context.Background(), io.NopCloser(strings.NewReader("")), &bufWC{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overlapping Serve %v", err)
	}
	ep.mu.Lock()
	stored := ep.auditErr
	ep.mu.Unlock()
	if !errors.Is(stored, auditErr) {
		t.Fatalf("prior audit failure reset early: %v", stored)
	}
	select {
	case <-peer.stopped:
		t.Fatal("Serve returned before its writer terminated")
	default:
	}
	releaseOnce.Do(func() { close(writer.returnNow) })
	awaitMCPSignal(t, peer.stopped)
	if !errors.Is(peer.err, auditErr) || errors.Is(peer.err, context.Canceled) {
		t.Fatalf("Serve cancellation hid audit failure: %v", peer.err)
	}
	if len(mcpAuditSnapshot(env.s)) != before {
		t.Fatal("failed audit was claimed as stored")
	}
	env.s.mu.Lock()
	env.s.commitFault = nil
	env.s.mu.Unlock()
	second := startLifecyclePeer(t, ep, nil)
	second.send(t, rpcFrame(t, 2, "tools/call", map[string]any{"name": toolList, "arguments": map[string]any{}, "_meta": mcpMeta()}))
	if got := readFrame(t, second.r); !bytes.Contains(got, []byte(`"entries"`)) {
		t.Fatalf("healthy sequential Serve %s", got)
	}
	waitMCPIdle(t, ep)
	_ = second.w.Close()
	awaitMCPSignal(t, second.stopped)
	if second.err != nil {
		t.Fatalf("old failure leaked into healthy Serve: %v", second.err)
	}
}

func TestMCPNotificationEnvelopes(t *testing.T) {
	env := approvedShared(t)
	raw := startRaw(t, bindCap(t, env.s, env.agent.ID))
	for _, frame := range []string{
		`{}`, `{"method":"notifications/cancelled"}`, `{"jsonrpc":"wrong","method":"notifications/cancelled"}`,
		`{"jsonrpc":"2.0","method":7}`, `{"jsonrpc":"2.0","method":""}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":null}`,
		`{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled","params":{"requestId":1}}`,
	} {
		before := len(mcpAuditSnapshot(env.s))
		got := raw.round(t, []byte(frame))
		if !bytes.Contains(got, []byte(`"code":-32600`)) || !bytes.Contains(got, []byte(`"id":null`)) {
			t.Fatalf("malformed envelope %s yielded %s", frame, got)
		}
		assertSparse(t, env.s, before, actionAgentCap)
	}
	before := len(mcpAuditSnapshot(env.s))
	for _, frame := range []string{
		`{"jsonrpc":"2.0","method":"notifications/unknown"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":88}}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"invoke_capability"}}`,
	} {
		if _, err := raw.w.Write(append([]byte(frame), '\n')); err != nil {
			t.Fatal(err)
		}
	}
	got := raw.round(t, rpcFrame(t, 44, "tools/list", map[string]any{"_meta": mcpMeta()}))
	if !bytes.Contains(got, []byte(`"id":44`)) || !bytes.Contains(got, []byte(`"tools"`)) {
		t.Fatalf("genuine notification produced a response %s", got)
	}
	rows := mcpAuditSnapshot(env.s)[before:]
	if len(rows) != 4 || rows[3].Action != actionLocalAttest {
		t.Fatalf("notification denials %+v", rows)
	}
}

func TestMCPRejectedNotificationShapes(t *testing.T) {
	env := approvedShared(t)
	raw := startRaw(t, bindCap(t, env.s, env.agent.ID))
	for _, frame := range []string{
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9,"reason":[]}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9,"reason":{"nested":["untrusted"]}}}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"invoke_capability","arguments":{"payload":[]}}}`,
	} {
		before := len(mcpAuditSnapshot(env.s))
		if _, err := raw.w.Write(append([]byte(frame), '\n')); err != nil {
			t.Fatal(err)
		}
		// A real following request proves the rejected notification generated
		// neither output nor a forwarded credential operation.
		got := raw.round(t, rpcFrame(t, 50, "tools/list", map[string]any{"_meta": mcpMeta()}))
		if !bytes.Contains(got, []byte(`"id":50`)) || !bytes.Contains(got, []byte(`"tools"`)) {
			t.Fatalf("notification response %s", got)
		}
		assertSparse(t, env.s, before, actionAgentCap)
	}
	for _, frame := range []string{
		`{"jsonrpc":"2.0","\u006asonrpc":"2.0","method":"notifications/cancelled","params":{"reason":[]}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","\u006dethod":"notifications/unknown","params":{"reason":[]}}`,
		`{"jsonrpc":"2.0","\u0069d":null,"method":"notifications/cancelled","params":{"reason":[]}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"reason":[]}} {}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":[1]}`,
	} {
		got := raw.round(t, []byte(frame))
		if !bytes.Contains(got, []byte(`"code":-32700`)) {
			t.Fatalf("ambiguous or non-profile envelope suppressed error: %s", got)
		}
	}
}

func TestMCPCancellationDecoderFailure(t *testing.T) {
	for _, failAudit := range []bool{false, true} {
		name := "audited"
		if failAudit {
			name = "audit-failure"
		}
		t.Run(name, func(t *testing.T) {
			env := approvedShared(t)
			if failAudit {
				env.s.commitFault = func() error { return errors.New("test-only cancellation decode audit fault") }
			}
			ep := lifecycleEndpoint(t, bindCap(t, env.s, env.agent.ID))
			entered := make(chan struct{})
			ep.server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
				return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
					if method != "tools/call" {
						return next(ctx, method, req)
					}
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				}
			})
			peer := startLifecyclePeer(t, ep, nil)
			before := len(mcpAuditSnapshot(env.s))
			peer.send(t, lifecycleInvoke(t, 71))
			awaitMCPSignal(t, entered)
			// The strict raw scanner accepts trailing whitespace, while this
			// pinned SDK decoder rejects it. The rejected notice is its own audit.
			peer.send(t, append(cancellationFrame(t, 71), ' '))
			awaitMCPSignal(t, peer.stopped)
			if peer.err == nil {
				t.Fatal("decoder failure did not close the session")
			}
			rows := mcpAuditSnapshot(env.s)[before:]
			if failAudit {
				if !errors.Is(peer.err, ErrAudit) || len(rows) != 0 {
					t.Fatalf("decoder audit failure %v %+v", peer.err, rows)
				}
				return
			}
			if len(rows) != 2 || rows[0].Action != actionAgentCap || rows[1].Action != actionLocalAttest {
				t.Fatalf("cancellation/invocation settlement %+v", rows)
			}
			for _, row := range rows {
				if row.Result != resultDenied || row.GrantID != "" || row.CredID != "" {
					t.Fatalf("non-sparse decoder denial %+v", row)
				}
			}
		})
	}
}

func TestMCPVersionProjection(t *testing.T) {
	env := approvedShared(t)
	raw := startRaw(t, bindCap(t, env.s, env.agent.ID))
	for _, tc := range []struct {
		version string
		valid   bool
	}{
		{"2025-11-25", true}, {"2024-11-05", true},
		{"secret-version-token", false}, {"2026-02-30", false},
		{"2026-7-28", false}, {strings.Repeat("Z", 80), false},
	} {
		version := tc.version
		for _, legacy := range []bool{false, true} {
			method := "tools/list"
			params := map[string]any{"_meta": map[string]any{metaProtocolVersion: version, metaClientCapabilities: map[string]any{}}}
			if legacy {
				method, params = "initialize", map[string]any{"protocolVersion": version}
			}
			got := raw.round(t, rpcFrame(t, 1, method, params))
			var wire struct {
				Error struct {
					Code int64           `json:"code"`
					Data json.RawMessage `json:"data"`
				} `json:"error"`
			}
			if err := json.Unmarshal(got, &wire); err != nil {
				t.Fatal(err)
			}
			if !legacy && !tc.valid {
				if wire.Error.Code != jsonrpc.CodeInvalidParams || len(wire.Error.Data) != 0 {
					t.Fatalf("malformed version %s", got)
				}
				continue
			}
			var data mcp.UnsupportedProtocolVersionData
			if err := json.Unmarshal(wire.Error.Data, &data); err != nil {
				t.Fatal(err)
			}
			want := version
			if !tc.valid {
				want = "invalid"
			}
			if wire.Error.Code != mcp.CodeUnsupportedProtocolVersion || len(data.Supported) != 1 || data.Supported[0] != mcpProtocolRevision || data.Requested != want {
				t.Fatalf("unsupported revision projection %s", got)
			}
		}
	}
}

func TestMCPOfficialClientBusyInterval(t *testing.T) {
	env := approvedShared(t)
	ep := lifecycleEndpoint(t, bindCap(t, env.s, env.agent.ID))
	var writer *stagedMCPWriter
	peer := startLifecyclePeer(t, ep, func(w io.WriteCloser) io.WriteCloser {
		writer = newStagedMCPWriter(w, false)
		return writer
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "lifecycle-client", Version: "m10b"}, &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{}, Logger: slog.New(&mcpLog{}), MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
	})
	cs, err := client.Connect(t.Context(), &mcp.IOTransport{Reader: peer.clientRead, Writer: peer.w, MaxLineLength: maxMCPFrame + 1}, &mcp.ClientSessionOptions{ProtocolVersion: mcpProtocolRevision})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if cs.InitializeResult().ProtocolVersion != mcpProtocolRevision {
		t.Fatal("unexpected negotiated revision")
	}
	awaitMCPSignal(t, writer.afterFrame)
	before := len(mcpAuditSnapshot(env.s))
	errc := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: toolList, Arguments: map[string]any{}})
		errc <- err
	}()
	waitMCPState(t, ep, func() bool { return ep.pending != nil })
	assertSparse(t, env.s, before, actionAgentCap)
	close(writer.allowReturn)
	select {
	case err := <-errc:
		var rpcErr *jsonrpc.Error
		if !errors.As(err, &rpcErr) || rpcErr.Code != mcpCodeBusy {
			t.Fatalf("SDK busy result %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SDK call did not finish")
	}
	waitMCPIdle(t, ep)
	// A new, explicit read-only call works after delivery finishes. The SDK
	// never automatically repeated the rejected request.
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: toolList, Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("subsequent SDK request %+v %v", res, err)
	}
	if len(mcpAuditSnapshot(env.s)) != before+2 {
		t.Fatal("unexpected automatic replay")
	}
}

// lifecyclePeer owns a real Serve plus in-memory transport and waits for all
// cleanup. Reading stopped synchronizes access to its terminal error.
type lifecyclePeer struct {
	ep         *MCPEndpoint
	r          *bufio.Reader
	w          *io.PipeWriter
	clientRead *io.PipeReader
	cancel     context.CancelFunc
	stopped    chan struct{}
	err        error
}

func lifecycleEndpoint(t *testing.T, cap *AgentCapability) *MCPEndpoint {
	t.Helper()
	ep, err := BindMCPEndpoint(cap)
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func startLifecyclePeer(t *testing.T, ep *MCPEndpoint, wrap func(io.WriteCloser) io.WriteCloser) *lifecyclePeer {
	t.Helper()
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	var w io.WriteCloser = sw
	if wrap != nil {
		w = wrap(w)
	}
	ctx, cancel := context.WithCancel(t.Context())
	peer := &lifecyclePeer{ep: ep, r: bufio.NewReader(cr), w: cw, clientRead: cr, cancel: cancel, stopped: make(chan struct{})}
	go func() { peer.err = ep.Serve(ctx, sr, w); close(peer.stopped) }()
	t.Cleanup(func() {
		cancel()
		_ = cw.Close()
		_ = cr.Close()
		_ = sw.Close()
		awaitMCPSignal(t, peer.stopped)
	})
	return peer
}

func (p *lifecyclePeer) send(t *testing.T, frame []byte) {
	t.Helper()
	errc := make(chan error, 1)
	go func() { _, err := p.w.Write(append(frame, '\n')); errc <- err }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("input stalled behind output")
	}
}

func lifecycleInvoke(t *testing.T, id int) []byte {
	return rpcFrame(t, id, "tools/call", map[string]any{"name": toolInvoke, "_meta": mcpMeta(), "arguments": invokeArgs(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), []byte("lifecycle-artifact"))})
}

func cancellationFrame(t *testing.T, id int) []byte {
	return mustJSON(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id, "reason": "untrusted-cancellation-reason"}})
}

func assertMCPAdmitted(t *testing.T, ep *MCPEndpoint, id int64) {
	t.Helper()
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if !ep.inCall || !ep.callID.matches(callKey{num: id, isNum: true}) {
		t.Fatal("admission released before complete delivery")
	}
}

func awaitMCPSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("MCP lifecycle transition timed out")
	}
}

func waitMCPAuditCount(t *testing.T, s *Session, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(mcpAuditSnapshot(s)) < n {
		if time.Now().After(deadline) {
			t.Fatal("denial was not audited")
		}
		time.Sleep(time.Millisecond)
	}
}

type mcpReadResult struct {
	frame []byte
	err   error
}

func asyncMCPRead(r *bufio.Reader) <-chan mcpReadResult {
	ch := make(chan mcpReadResult, 1)
	go func() { frame, err := r.ReadBytes('\n'); ch <- mcpReadResult{frame, err} }()
	return ch
}
func awaitMCPRead(t *testing.T, ch <-chan mcpReadResult) []byte {
	t.Helper()
	select {
	case got := <-ch:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.frame
	case <-time.After(5 * time.Second):
		t.Fatal("MCP response timed out")
		return nil
	}
}

type stagedMCPWriter struct {
	w                                                      io.WriteCloser
	split                                                  bool
	once                                                   sync.Once
	closeOnce                                              sync.Once
	beforeTail, allowTail, afterFrame, allowReturn, closed chan struct{}
}

func newStagedMCPWriter(w io.WriteCloser, split bool) *stagedMCPWriter {
	return &stagedMCPWriter{w: w, split: split, beforeTail: make(chan struct{}), allowTail: make(chan struct{}), afterFrame: make(chan struct{}), allowReturn: make(chan struct{}), closed: make(chan struct{})}
}
func (w *stagedMCPWriter) Write(p []byte) (int, error) {
	first := false
	w.once.Do(func() { first = true })
	if !first {
		return w.w.Write(p)
	}
	n := 0
	if w.split {
		var err error
		n, err = w.w.Write(p[:len(p)-2])
		if err != nil {
			return n, err
		}
		close(w.beforeTail)
		select {
		case <-w.allowTail:
		case <-w.closed:
			return n, io.ErrClosedPipe
		}
	}
	written, err := w.w.Write(p[n:])
	n += written
	if err != nil {
		return n, err
	}
	close(w.afterFrame)
	select {
	case <-w.allowReturn:
		return n, nil
	case <-w.closed:
		return n, io.ErrClosedPipe
	}
}
func (w *stagedMCPWriter) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	return w.w.Close()
}

type blockedMCPWriter struct {
	mu              sync.Mutex
	frames          [][]byte
	entered, closed chan struct{}
	once, closeOnce sync.Once
}

func (w *blockedMCPWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.frames = append(w.frames, append([]byte(nil), p...))
	w.mu.Unlock()
	w.once.Do(func() { close(w.entered) })
	<-w.closed
	return 0, io.ErrClosedPipe
}
func (w *blockedMCPWriter) Close() error { w.closeOnce.Do(func() { close(w.closed) }); return nil }

type lateMCPWriter struct {
	entered, closed, returnNow chan struct{}
	once                       sync.Once
}

func (w *lateMCPWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.closed
	<-w.returnNow
	return 0, io.ErrClosedPipe
}
func (w *lateMCPWriter) Close() error { w.once.Do(func() { close(w.closed) }); return nil }

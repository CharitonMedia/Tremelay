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
	"testing"
	"testing/synctest"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func stdioEndpoint(t *testing.T, cap *AgentCapability) *MCPEndpoint {
	t.Helper()
	ep, err := BindStdioMCPEndpoint(cap)
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func startStdioSDK(t *testing.T, cap *AgentCapability, revision string) *mcpSession {
	t.Helper()
	ep := stdioEndpoint(t, cap)
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	errc := make(chan error, 1)
	go func() { errc <- ep.Serve(ctx, serverRead, serverWrite) }()
	t.Cleanup(func() {
		cancel()
		_ = clientWrite.Close()
		_ = clientRead.Close()
		select {
		case <-errc:
		case <-time.After(5 * time.Second):
			t.Error("stdio Serve did not return")
		}
	})
	logs := &mcpLog{}
	client := mcp.NewClient(&mcp.Implementation{Name: "official-stdio-client", Version: "1", Title: "Client"}, &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{
			Form: &mcp.FormElicitationCapabilities{}, URL: &mcp.URLElicitationCapabilities{},
		}},
		Logger: slog.New(logs), MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
	})
	cs, err := client.Connect(ctx, &mcp.IOTransport{Reader: clientRead, Writer: clientWrite, MaxLineLength: maxMCPFrame + 1}, &mcp.ClientSessionOptions{ProtocolVersion: revision})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	waitMCPIdle(t, ep)
	return &mcpSession{ep: ep, cs: cs, clientLog: logs, cancel: cancel}
}

func TestStdioMCPOfficialSDK(t *testing.T) {
	for _, revision := range []string{mcpStdio20250618, mcpStdio20251125, ""} {
		t.Run("version-"+revision, func(t *testing.T) {
			s, cap, grant, pub, resource := newSingleAttestCap(t)
			client := startStdioSDK(t, cap, revision)
			want := revision
			if want == "" { // SDK default first probes modern discovery, then falls back.
				want = mcpStdio20251125
			}
			if got := client.cs.InitializeResult().ProtocolVersion; got != want {
				t.Fatalf("negotiated %s, want %s", got, want)
			}
			tools, err := client.cs.ListTools(t.Context(), nil)
			if err != nil || len(tools.Tools) != 3 {
				t.Fatalf("tools/list: %v", err)
			}
			entries := entriesOf(t, mustCall(t, client, toolList, map[string]any{}))
			if len(entries) != 1 || entries[0]["resource"] != resource || entries[0]["key_id"] != grant.KeyID {
				t.Fatal("unexpected bound catalogue")
			}
			handle := entries[0]["handle"]
			desc := toolObject(t, mustCall(t, client, toolDescribe, map[string]any{"handle": handle}))
			if desc["handle"] != handle || desc["resource"] != resource {
				t.Fatal("describe changed the bound capability")
			}
			payload := []byte("synthetic-stdio-artifact-" + randHex(t, 16))
			result := toolObject(t, mustCall(t, client, toolInvoke, invokeArgs(handle, payload)))
			if !VerifyLocalAttestation(pub, resource, payload, mustB64(t, result["signature"].(string))) {
				t.Fatal("public signature did not verify")
			}
			waitMCPIdle(t, client.ep)
			if err := s.RevokeGrant(grant.ID); err != nil {
				t.Fatal(err)
			}
			denied := mustCall(t, client, toolInvoke, invokeArgs(handle, payload))
			if !denied.IsError || denied.StructuredContent != nil || toolObject(t, denied)["code"] != capDeniedRevoked {
				t.Fatal("revocation did not fail closed")
			}
			rows := mcpAuditSnapshot(s)
			var allowed, completed, revoked int
			for _, row := range rows {
				if row.Action != actionLocalAttest {
					continue
				}
				switch row.Result {
				case resultAllowed:
					allowed++
				case resultCompleted:
					completed++
				case resultDeniedRevoked:
					revoked++
				}
			}
			if allowed != 1 || completed != 1 || revoked != 1 {
				t.Fatalf("audit counts %d/%d/%d", allowed, completed, revoked)
			}
			assertNoSecrets(t, []byte(client.ep.logs.text()+client.clientLog.text()), [][]byte{payload})
		})
	}
}

func stdioInitialize(t *testing.T, peer *lifecyclePeer, revision string) {
	t.Helper()
	peer.send(t, rpcFrame(t, 1, "initialize", map[string]any{
		"protocolVersion": revision, "capabilities": map[string]any{"elicitation": map[string]any{"form": map[string]any{}, "url": map[string]any{}}},
		"clientInfo": map[string]any{"name": "client", "version": "1", "title": "Client"},
	}))
	response := readFrame(t, peer.r)
	if !bytes.Contains(response, []byte(`"protocolVersion":"`+revision+`"`)) || bytes.Contains(response, []byte(`"error"`)) {
		t.Fatalf("initialize failed: %s", response)
	}
	waitMCPIdle(t, peer.ep)
	peer.send(t, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
}

func TestStdioMCPAdmission(t *testing.T) {
	s, cap, _, _, _ := newSingleAttestCap(t)
	ep := stdioEndpoint(t, cap)
	peer := startLifecyclePeer(t, ep, nil)
	before := len(mcpAuditSnapshot(s))
	peer.send(t, rpcFrame(t, 9, "tools/call", map[string]any{"name": toolInvoke, "arguments": invokeArgs(base64.StdEncoding.EncodeToString(make([]byte, 32)), []byte("pre-init"))}))
	if got := readFrame(t, peer.r); !bytes.Contains(got, []byte(`"code":-32600`)) || bytes.Contains(got, []byte("signature")) {
		t.Fatal("pre-init call was not denied")
	}
	assertSparse(t, s, before, actionLocalAttest)
	stdioInitialize(t, peer, mcpStdio20251125)
	for _, tc := range []struct {
		name, frame string
		code        int64
		action      string
	}{
		{"missing-arguments", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"invoke_capability"}}`, jsonrpc.CodeInvalidParams, actionLocalAttest},
		{"extra-authority", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_capabilities","arguments":{"agent":"another"}}}`, jsonrpc.CodeInvalidParams, actionAgentCap},
		{"duplicate", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{},"\u005fmeta":{}}}`, jsonrpc.CodeParseError, actionAgentCap},
		{"modern-metadata", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, jsonrpc.CodeInvalidParams, actionAgentCap},
		{"modern-discovery", `{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{}}`, jsonrpc.CodeMethodNotFound, actionAgentCap},
		{"raw-secret", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_secret","arguments":{}}}`, jsonrpc.CodeInvalidParams, actionAgentCap},
		{"request-authority", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"request_capability","arguments":{}}}`, jsonrpc.CodeInvalidParams, actionAgentCap},
		{"bad-progress", `{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"progressToken":null}}}`, jsonrpc.CodeInvalidParams, actionAgentCap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waitMCPIdle(t, ep)
			before := len(mcpAuditSnapshot(s))
			peer.send(t, []byte(tc.frame))
			response := readFrame(t, peer.r)
			var got struct {
				Error struct {
					Code int64 `json:"code"`
				} `json:"error"`
			}
			if json.Unmarshal(response, &got) != nil || got.Error.Code != tc.code {
				t.Fatalf("error: %s", response)
			}
			assertSparse(t, s, before, tc.action)
		})
	}
	waitMCPIdle(t, ep)
	peer.send(t, rpcFrame(t, 4, "tools/list", map[string]any{"_meta": map[string]any{"traceparent": "advisory-trace", "progressToken": "advisory-progress", "untrusted": map[string]any{"agent": "other"}}}))
	if got := readFrame(t, peer.r); !bytes.Contains(got, []byte(`"tools"`)) || bytes.Contains(got, []byte("advisory-")) {
		t.Fatal("advisory metadata was reflected or altered authority")
	}
	waitMCPIdle(t, ep)
	peer.send(t, []byte(`{"jsonrpc":"2.0","id":5,"method":"ping"}`))
	if got := readFrame(t, peer.r); !bytes.Contains(got, []byte(`"result":{}`)) {
		t.Fatalf("ping: %s", got)
	}
}

func TestStdioMCPInitializedOnce(t *testing.T) {
	s, cap, _, _, _ := newSingleAttestCap(t)
	ep := stdioEndpoint(t, cap)
	peer := startLifecyclePeer(t, ep, nil)
	before := len(mcpAuditSnapshot(s))
	peer.send(t, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	waitMCPAuditCount(t, s, before+1)
	stdioInitialize(t, peer, mcpStdio20250618)
	before = len(mcpAuditSnapshot(s))
	peer.send(t, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	waitMCPAuditCount(t, s, before+1)
	assertSparse(t, s, before, actionAgentCap)
	waitMCPIdle(t, ep)
	peer.send(t, rpcFrame(t, 2, "initialize", map[string]any{"protocolVersion": mcpStdio20250618, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "other", "version": "1"}}))
	if got := readFrame(t, peer.r); !bytes.Contains(got, []byte(`"code":-32600`)) {
		t.Fatal("duplicate initialization accepted")
	}
}

func TestStdioMCPVersionAndBounds(t *testing.T) {
	_, cap, _, _, _ := newSingleAttestCap(t)
	ep := stdioEndpoint(t, cap)
	peer := startLifecyclePeer(t, ep, nil)
	peer.send(t, rpcFrame(t, 1, "initialize", map[string]any{"protocolVersion": mcpProtocolRevision, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "client", "version": "1"}}))
	got := readFrame(t, peer.r)
	if !bytes.Contains(got, []byte(`"supported":["2025-11-25","2025-06-18"]`)) {
		t.Fatal("incorrect supported versions")
	}
	for _, frame := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"x":"` + strings.Repeat("A", maxMCPMeta) + `"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"x":[]}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"x":1.1}}}`,
	} {
		if classifyStdioFrame([]byte(frame)).op == opForward {
			t.Fatal("oversized or unsupported metadata admitted")
		}
	}
}

func TestStdioMCPAuditFailureCloses(t *testing.T) {
	s, cap, _, _, _ := newSingleAttestCap(t)
	ep := stdioEndpoint(t, cap)
	peer := startLifecyclePeer(t, ep, nil)
	stdioInitialize(t, peer, mcpStdio20251125)
	// Exercise the same fail-closed admission audit path using a closed store.
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	peer.send(t, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"invoke_capability","arguments":{}}}`))
	if got := readFrame(t, peer.r); !bytes.Contains(got, []byte(`"code":-32603`)) || bytes.Contains(got, []byte("signature")) {
		t.Fatal("failed audit disclosed output")
	}
	select {
	case <-peer.stopped:
		if !errors.Is(peer.err, ErrAudit) && !errors.Is(peer.err, ErrIO) {
			t.Fatalf("Serve lost audit failure: %v", peer.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failed audit did not close")
	}
}

// Virtual time proves the deadline/cancellation and exact-write conditions
// without relying on sleeps or scheduler timing. No credential is admitted by
// the handoff itself; ordinary admission must be rechecked afterwards.
func TestStdioMCPHandoff(t *testing.T) {
	for _, mode := range []string{"complete", "deadline", "canceled", "nil-context", "modern", "pending", "handler", "busy-error", "error-deadline"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				out := &mcpOutput{response: true, complete: make(chan struct{})}
				ep := &MCPEndpoint{stdio: true, active: out, inCall: true}
				c := &admitConn{ep: ep}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch mode {
				case "modern":
					ep.stdio = false
				case "pending":
					ep.pending = &mcpOutput{}
				case "handler":
					ep.active = nil
				case "nil-context":
					ctx = nil
				case "busy-error":
					out.response = false
				case "error-deadline":
					out.response = false
					ep.inCall = false
				}
				start := time.Now()
				done := make(chan struct{})
				go func() { c.waitStdioHandoff(ctx); close(done) }()
				synctest.Wait()
				if mode == "modern" || mode == "pending" || mode == "handler" || mode == "busy-error" {
					select {
					case <-done:
					default:
						t.Fatal("unrelated work was awaited")
					}
					return
				}
				select {
				case <-done:
					t.Fatal("released a held response early")
				default:
				}
				if c.admit(frameDecision{key: callKey{num: 2, isNum: true}}) {
					t.Fatal("handoff released admission before Write returned")
				}
				switch mode {
				case "complete":
					close(out.complete)
				case "canceled":
					cancel()
				default:
					time.Sleep(stdioHandoffDeadline)
				}
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("handoff did not settle")
				}
				want := time.Duration(0)
				if mode == "deadline" || mode == "nil-context" || mode == "error-deadline" {
					want = stdioHandoffDeadline
				}
				if got := time.Since(start); got != want {
					t.Fatalf("deadline elapsed %s, want %s", got, want)
				}
				if ep.inCall != (mode != "error-deadline") {
					t.Fatal("handoff changed admission")
				}
			})
		})
	}
}

func TestStdioMCPHeldResponseExpires(t *testing.T) {
	s, cap, _, _, _ := newSingleAttestCap(t)
	ep := stdioEndpoint(t, cap)
	var writer *stagedMCPWriter
	peer := startLifecyclePeer(t, ep, func(w io.WriteCloser) io.WriteCloser {
		writer = newStagedMCPWriter(w, false)
		return writer
	})
	peer.send(t, rpcFrame(t, 1, "initialize", map[string]any{"protocolVersion": mcpStdio20251125, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "held-client", "version": "1"}}))
	if got := readFrame(t, peer.r); !bytes.Contains(got, []byte(`"protocolVersion"`)) {
		t.Fatal("initialize failed")
	}
	awaitMCPSignal(t, writer.afterFrame)
	peer.send(t, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	before := len(mcpAuditSnapshot(s))
	peer.send(t, rpcFrame(t, 2, "tools/list", map[string]any{}))
	waitMCPState(t, ep, func() bool { return ep.pending != nil })
	assertMCPAdmitted(t, ep, 1)
	assertSparse(t, s, before, actionAgentCap)
	close(writer.allowReturn)
	if got := readFrame(t, peer.r); !bytes.Contains(got, []byte(`"code":-31010`)) {
		t.Fatalf("held write was admitted: %s", got)
	}
	waitMCPIdle(t, ep)
	peer.send(t, rpcFrame(t, 3, "tools/list", map[string]any{}))
	if got := readFrame(t, peer.r); !bytes.Contains(got, []byte(`"tools"`)) {
		t.Fatalf("next request failed: %s", got)
	}
}

func TestStdioMCPErrorResponseHandoff(t *testing.T) {
	for _, first := range []string{"rejected-request", "modern-discovery"} {
		t.Run(first, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				code := int64(jsonrpc.CodeInvalidRequest)
				if first == "modern-discovery" {
					d := classifyStdioFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"server/discover"}`))
					if d.op != opReject || d.code != jsonrpc.CodeMethodNotFound {
						t.Fatal("modern probe was not rejected")
					}
					code = d.code
				}
				out := &mcpOutput{frame: encodeRPCError([]byte("1"), code, ""), complete: make(chan struct{})}
				ep := &MCPEndpoint{stdio: true, active: out}
				frame := rpcFrame(t, 2, "initialize", map[string]any{"protocolVersion": mcpStdio20251125, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "fallback-client", "version": "1"}})
				c := &admitConn{ep: ep, in: bufio.NewReader(bytes.NewReader(append(frame, '\n')))}
				done := make(chan struct{})
				var msg jsonrpc.Message
				var err error
				go func() { msg, err = c.Read(context.Background()); close(done) }()
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("initialize did not wait for the exact error write")
				default:
				}
				ep.mu.Lock()
				if ep.inCall {
					t.Fatal("initialize admitted before error Write returned")
				}
				// Model the writer's atomic delivery settlement, already tested
				// through the real staged writer in TestStdioMCPHeldResponseExpires.
				ep.active = nil
				close(out.complete)
				ep.mu.Unlock()
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("initialize handoff did not resume")
				}
				req, ok := msg.(*jsonrpc.Request)
				if err != nil || !ok || req.Method != "initialize" {
					t.Fatalf("initialize after error: %v", err)
				}
				assertMCPAdmitted(t, ep, 2)
			})
		})
	}
}

func TestStdioMCPEOFInterruptsAdmittedOutput(t *testing.T) {
	for _, profile := range []string{"stdio", "modern"} {
		for _, ending := range []string{"eof", "read-error", "partial-audit-failure"} {
			t.Run(profile+"-"+ending, func(t *testing.T) {
				s, cap, _, _, _ := newSingleAttestCap(t)
				ep := stdioEndpoint(t, cap)
				frame := rpcFrame(t, 1, "initialize", map[string]any{"protocolVersion": mcpStdio20251125, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "eof-client", "version": "1"}})
				if profile == "modern" {
					ep = lifecycleEndpoint(t, cap)
					frame = rpcFrame(t, 1, "tools/list", map[string]any{"_meta": mcpMeta()})
				}
				writer := &blockedMCPWriter{entered: make(chan struct{}), closed: make(chan struct{})}
				peer := startLifecyclePeer(t, ep, func(io.WriteCloser) io.WriteCloser { return writer })
				peer.send(t, frame)
				awaitMCPSignal(t, writer.entered)
				ep.mu.Lock()
				admitted := ep.inCall && ep.active != nil && ep.active.response
				ep.mu.Unlock()
				if !admitted {
					t.Fatal("test did not block an admitted response")
				}
				switch ending {
				case "read-error":
					if err := peer.w.CloseWithError(io.ErrUnexpectedEOF); err != nil {
						t.Fatal(err)
					}
				case "partial-audit-failure":
					if err := s.db.Close(); err != nil {
						t.Fatal(err)
					}
					if _, err := peer.w.Write([]byte(`{"jsonrpc":"2.0"`)); err != nil {
						t.Fatal(err)
					}
					if err := peer.w.Close(); err != nil {
						t.Fatal(err)
					}
				default:
					if err := peer.w.Close(); err != nil {
						t.Fatal(err)
					}
				}
				// No context cancellation or signal is used to trigger shutdown.
				awaitMCPSignal(t, peer.stopped)
				awaitMCPSignal(t, writer.closed)
				if ending == "partial-audit-failure" && !errors.Is(peer.err, ErrAudit) && !errors.Is(peer.err, ErrIO) {
					t.Fatalf("audit failure was hidden by input loss: %v", peer.err)
				}
				ep.mu.Lock()
				defer ep.mu.Unlock()
				if ep.inCall || ep.active != nil || ep.pending != nil {
					t.Fatal("input loss returned before outstanding work settled")
				}
			})
		}
	}
}

// The raw write has a result, but Close wins before its accounting settles.
// No protocol call or credential operation is involved in this transport test.
type closeSettledMCPWriter struct {
	entered, release chan struct{}
	n                int
	err              error
}

func (w *closeSettledMCPWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.release
	return w.n, w.err
}

func (w *closeSettledMCPWriter) Close() error { close(w.release); return nil }

func TestStdioMCPWriteCompletionAfterClose(t *testing.T) {
	for _, stdio := range []bool{false, true} {
		profile := "modern"
		if stdio {
			profile = "stdio"
		}
		for _, tc := range []struct {
			name string
			n    int
			err  error
			want error
		}{
			{"full", 2, nil, nil},
			{"short", 1, nil, io.ErrShortWrite},
			{"full-with-error", 2, io.ErrClosedPipe, io.ErrClosedPipe},
			{"failed", 0, io.ErrUnexpectedEOF, io.ErrUnexpectedEOF},
		} {
			t.Run(profile+"-"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ep := &MCPEndpoint{stdio: stdio}
					writer := &closeSettledMCPWriter{entered: make(chan struct{}), release: make(chan struct{}), n: tc.n, err: tc.err}
					c := &admitConn{ep: ep, raw: io.NopCloser(bytes.NewReader(nil)), rawW: writer}
					c.startWriter()
					defer func() { _ = c.Close(); <-c.writerDone }()
					out := &mcpOutput{frame: []byte("{}")}
					if err := c.submit(out); err != nil {
						t.Fatal(err)
					}
					<-writer.entered
					pending := &mcpOutput{frame: []byte("{}")}
					if err := c.submit(pending); err != nil {
						t.Fatal(err)
					}
					if err := c.Close(); err != nil {
						t.Fatal(err)
					}
					want := tc.want
					if !stdio && want == nil {
						want = io.ErrClosedPipe
					}
					if got := <-out.done; !errors.Is(got, want) {
						t.Fatalf("settled write = %v, want %v", got, want)
					}
					if got := <-pending.done; !errors.Is(got, io.ErrClosedPipe) {
						t.Fatalf("pending write = %v", got)
					}
					if c.admit(frameDecision{}) {
						t.Fatal("closed connection admitted new work")
					}
					if err := c.submit(&mcpOutput{}); !errors.Is(err, io.ErrClosedPipe) {
						t.Fatalf("post-close output = %v", err)
					}
					<-c.writerDone
					if ep.active != nil || ep.pending != nil || ep.inCall {
						t.Fatal("closed output did not settle")
					}
				})
			})
		}
	}
}

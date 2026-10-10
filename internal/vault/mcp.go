package vault

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// mcpProtocolRevision is the only MCP wire revision this peer accepts.
	mcpProtocolRevision = "2026-07-28"

	// maxMCPFrame is the largest raw NDJSON value accepted or emitted.
	// The delimiter newline is not counted. A longer frame is rejected and
	// is not truncated. 128 KiB covers one 64 KiB payload after canonical
	// base64 (87384 bytes) plus a 4 KiB metadata object and the JSON-RPC
	// envelope; mcpMaxInvokeFrame is that ceiling and stays under this cap.
	maxMCPFrame = 128 << 10
	// maxMCPMeta is the largest raw _meta object accepted. It carries the
	// protocol revision and the caller's advertised identity. It grants nothing.
	maxMCPMeta = 4 << 10
	// maxMCPIDString is the largest string correlation id, in UTF-8 bytes.
	maxMCPIDString = 64
	// maxMCPIDNumber is the largest numeric correlation id this peer accepts.
	// The pinned SDK decodes JSON numbers as float64 before converting them
	// to int64, so a larger integer can round and miss the admission slot.
	// 2^53-1 is the greatest integer that survives that conversion unchanged.
	maxMCPIDNumber int64 = 1<<53 - 1
	maxMCPName           = 64
	maxMCPReason         = 128

	// mcpCodeBusy is the fixed application code for a second request while one
	// call is already inside this endpoint. There is no waiting queue.
	// JSON-RPC reserves -32768 through -32000, and MCP forbids new allocations
	// in the legacy sub-range -32000 through -32019, so this code sits outside
	// both. It is not an MCP-specified code and carries no protocol data.
	mcpCodeBusy = -31010
	// mcpCodeCancelled is the fixed code for a call abandoned before the
	// vault operation starts. It does not recall a signature already released.
	mcpCodeCancelled = -32800

	toolList     = "list_capabilities"
	toolDescribe = "describe_capability"
	toolInvoke   = "invoke_capability"
	toolRequest  = "request_capability"

	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo         = "io.modelcontextprotocol/clientInfo"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

var errMCPSyntax = errors.New("mcp frame rejected")
var errMCPFrame = errors.New("mcp frame exceeds 128 KiB")
var errMCPIdle = errors.New("mcp endpoint is idle")
var errMCPOutputFull = errors.New("mcp output capacity exceeded")

// mcpMaxInvokeFrame is the largest tools/call this profile will admit:
// a 64 KiB payload in canonical base64, a 32-byte handle, a 4 KiB _meta
// object, and a 64-byte string id. It is not a second limit. Frames over
// maxMCPFrame are rejected first, and a decoded payload over MaxAttestPayload
// is rejected even when the frame fits.
func mcpMaxInvokeFrame() int {
	payload := base64.StdEncoding.EncodedLen(MaxAttestPayload)
	handle := base64.StdEncoding.EncodedLen(32)
	args := len(`{"handle":"`) + handle + len(`","payload":"`) + payload + len(`"}`)
	params := len(`{"name":"invoke_capability","arguments":`) + args + len(`,"_meta":`) + maxMCPMeta + len(`}`)
	return len(`{"jsonrpc":"2.0","id":"`) + maxMCPIDString + len(`","method":"tools/call","params":`) + params + len(`}`)
}

// MCPEndpoint is one in-memory MCP peer for one already-bound AgentCapability.
// Messages, clientInfo, ids, metadata, tool arguments, and handles cannot
// replace that capability, its agent, the session, the vault, unlock material,
// the clock, or a host callback.
//
// The host must not use the bound session on another goroutine while Serve is
// running, except from a callback the session invokes after releasing its own
// lock. This process does not enforce that duty for any other process.
// A second request fails closed and does not wait on the response write. The
// one admission slot stays held until that call's response write returns, or
// until terminal connection failure. A writer may return after the peer has
// consumed its bytes; a request in that interval safely receives busy.
// Cancellation and close do not recall a signature already released, and a
// missing response is not a signal to replay the call.
type MCPEndpoint struct {
	cap    *AgentCapability
	server *mcp.Server
	logs   *mcpLog

	mu          sync.Mutex
	serving     bool
	inCall      bool
	callID      callKey
	callInvoke  bool
	callHandled bool
	cancelSent  bool
	auditErr    error
	active      *mcpOutput
	pending     *mcpOutput
}

type callKey struct {
	num   int64
	str   string
	isNum bool
}

func (k callKey) matches(o callKey) bool {
	return k.isNum == o.isNum && k.num == o.num && k.str == o.str
}

// BindMCPEndpoint builds one peer around an adapter the host already bound.
// A nil adapter is refused. The peer does not open a socket or a listener.
func BindMCPEndpoint(cap *AgentCapability) (*MCPEndpoint, error) {
	if cap == nil || cap.broker == nil || safeID(cap.agentID) == "" {
		return nil, ErrUnauthenticated
	}
	logs := &mcpLog{}
	ep := &MCPEndpoint{cap: cap, logs: logs}
	ep.server = mcp.NewServer(&mcp.Implementation{Name: "tremelay-local-mcp", Version: "m10b"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolCapabilities{},
		},
		SupportedProtocolVersions: []string{mcpProtocolRevision},
		Logger:                    slog.New(logs),
	})
	ep.server.AddTool(&mcp.Tool{
		Name:         toolList,
		Description:  "List this endpoint's local attestation capabilities.",
		InputSchema:  json.RawMessage(mcpListInSchema),
		OutputSchema: json.RawMessage(mcpListOutSchema),
	}, ep.onTool)
	ep.server.AddTool(&mcp.Tool{
		Name:         toolDescribe,
		Description:  "Describe one local attestation capability by handle.",
		InputSchema:  json.RawMessage(mcpDescribeInSchema),
		OutputSchema: json.RawMessage(mcpEntrySchema),
	}, ep.onTool)
	ep.server.AddTool(&mcp.Tool{
		Name:         toolInvoke,
		Description:  "Attest one payload with the capability named by handle.",
		InputSchema:  json.RawMessage(mcpInvokeInSchema),
		OutputSchema: json.RawMessage(mcpInvokeOutSchema),
	}, ep.onTool)
	return ep, nil
}

// Serve runs one NDJSON session on r and w. Both are the endpoint side of an
// in-memory pipe. Serve does not listen. The host closes the peer by cancelling
// ctx or by closing the pipe. Concurrent Serve calls are refused. Sequential
// calls are allowed after the previous SDK session and writer have terminated.
// Both pipe ends must support Close concurrently with I/O and unblock that I/O.
func (e *MCPEndpoint) Serve(ctx context.Context, r io.ReadCloser, w io.WriteCloser) error {
	if e == nil || e.server == nil || e.cap == nil || r == nil || w == nil {
		return ErrInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e.mu.Lock()
	if e.serving {
		e.mu.Unlock()
		return ErrInvalid
	}
	e.serving = true
	e.auditErr = nil
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.serving = false
		e.inCall = false
		e.callHandled = false
		e.cancelSent = false
		e.mu.Unlock()
	}()

	conn := &admitConn{
		ep:   e,
		in:   bufio.NewReaderSize(r, 4096),
		raw:  r,
		rawW: w,
	}
	conn.startWriter()
	defer func() {
		_ = conn.Close()
		<-conn.writerDone
	}()
	tr := &admitTransport{conn: conn}
	ss, err := e.server.Connect(context.Background(), tr, nil)
	if err != nil {
		return ErrInvalid
	}
	defer ss.Close()
	errc := make(chan error, 1)
	go func() { errc <- ss.Wait() }()
	var serveErr error
	select {
	case <-ctx.Done():
		// The SDK's graceful close waits until the handler returns. A handler
		// blocked on this pipe would stall that wait, so close the pipe first.
		// Closing the pipe does not recall a signature already released.
		_ = conn.Close()
		_ = ss.Close()
		<-errc
		serveErr = ctx.Err()
	case err := <-errc:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
			serveErr = err
		}
	}
	_ = conn.Close()
	<-conn.writerDone
	// Dispatch and output have stopped. A call cancelled before its handler,
	// or whose response was suppressed because the reader was already gone,
	// still needs one sparse denial. A handler that already audited is skipped.
	if aerr := e.settleOutstanding(); aerr != nil {
		return aerr
	}
	e.mu.Lock()
	stored := e.auditErr
	e.mu.Unlock()
	if stored != nil {
		return stored
	}
	return serveErr
}

// denyOverlap records a sparse denial when a callback reenters this endpoint
// during an outstanding call. It does not wait and it does not take the
// session lock before noticing that the call is outstanding.
func (e *MCPEndpoint) denyOverlap(invoke bool) error {
	if e == nil || e.cap == nil {
		return ErrUnauthenticated
	}
	e.mu.Lock()
	busy := e.inCall
	e.mu.Unlock()
	if !busy {
		return errMCPIdle
	}
	return e.cap.denyBound(invoke)
}

func (e *MCPEndpoint) beginCall(id callKey, invoke bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.beginCallLocked(id, invoke)
}

func (e *MCPEndpoint) beginCallLocked(id callKey, invoke bool) bool {
	if e.inCall {
		return false
	}
	e.inCall = true
	e.callID = id
	e.callInvoke = invoke
	e.callHandled = false
	e.cancelSent = false
	return true
}

// markHandled records that the tool handler now owns this call's audit.
func (e *MCPEndpoint) markHandled() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.callHandled = true
	e.mu.Unlock()
}

// settleDenied records one sparse denial when an admitted call was rejected
// before its handler. A second call is a no-op. A non-nil error means the row
// was not persisted; the attempt is still consumed.
func (e *MCPEndpoint) settleDenied(id callKey) error {
	if e == nil || e.cap == nil {
		return ErrUnauthenticated
	}
	e.mu.Lock()
	if !e.inCall || e.callHandled || !e.callID.matches(id) {
		e.mu.Unlock()
		return nil
	}
	invoke := e.callInvoke
	e.callHandled = true
	e.mu.Unlock()
	return e.cap.denyBound(invoke)
}

func (e *MCPEndpoint) finishCallLocked(id callKey) {
	if e.inCall && e.callID.matches(id) {
		e.inCall = false
		e.cancelSent = false
	}
}

// settleOutstanding records the one admitted attempt whose handler never
// audited. It runs only after the SDK session has stopped, so a late Write
// cannot record the same row. A failed write is returned and is not described
// as persisted.
func (e *MCPEndpoint) settleOutstanding() error {
	if e == nil || e.cap == nil {
		return ErrUnauthenticated
	}
	e.mu.Lock()
	if !e.inCall || e.callHandled {
		e.mu.Unlock()
		return nil
	}
	invoke := e.callInvoke
	e.callHandled = true
	e.inCall = false
	e.cancelSent = false
	e.mu.Unlock()
	err := e.cap.denyBound(invoke)
	if err != nil {
		e.noteAudit(err)
	}
	return err
}

func (e *MCPEndpoint) noteAudit(err error) {
	if e == nil || err == nil {
		return
	}
	e.mu.Lock()
	if e.auditErr == nil {
		e.auditErr = err
	}
	e.mu.Unlock()
}

func (e *MCPEndpoint) acceptCancel(id callKey) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.inCall || e.cancelSent || !e.callID.matches(id) {
		return false
	}
	e.cancelSent = true
	return true
}

func (e *MCPEndpoint) onTool(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	e.markHandled()
	if req == nil || req.Params == nil {
		return e.toolFail(false, jsonrpc.CodeInvalidParams)
	}
	name := req.Params.Name
	invoke := name == toolInvoke
	if ctx != nil && ctx.Err() != nil {
		return e.toolFail(invoke, mcpCodeCancelled)
	}
	msg, payload, err := e.capMessage(name, req.Params.Arguments)
	defer wipe(payload)
	if err != nil {
		return e.toolFail(invoke, jsonrpc.CodeInvalidParams)
	}
	if ctx != nil && ctx.Err() != nil {
		return e.toolFail(invoke, mcpCodeCancelled)
	}
	raw, err := e.cap.Exchange(msg)
	return projectCap(raw, err)
}

func (e *MCPEndpoint) toolFail(invoke bool, code int64) (*mcp.CallToolResult, error) {
	if err := e.cap.denyBound(invoke); err != nil {
		e.noteAudit(err)
		return nil, rpcError(jsonrpc.CodeInternalError)
	}
	return nil, rpcError(code)
}

func (e *MCPEndpoint) capMessage(name string, args json.RawMessage) ([]byte, []byte, error) {
	switch name {
	case toolList:
		if len(bytes.TrimSpace(args)) != 0 {
			v, err := parseJSONValue(args)
			if err != nil || v.kind != 'o' || len(v.obj) != 0 {
				return nil, nil, errMCPSyntax
			}
		}
		msg, err := encodeCapList()
		return msg, nil, err
	case toolDescribe:
		handle, err := toolHandle(args, false)
		if err != nil {
			return nil, nil, err
		}
		msg, err := encodeCapDescribe(handle)
		return msg, nil, err
	case toolInvoke:
		handle, payload, err := toolInvokeArgs(args)
		if err != nil {
			return nil, nil, err
		}
		msg, err := encodeCapInvoke(handle, payload)
		return msg, payload, err
	default:
		return nil, nil, errMCPSyntax
	}
}

func toolHandle(args json.RawMessage, withPayload bool) ([32]byte, error) {
	var handle [32]byte
	v, err := parseJSONValue(args)
	if err != nil || v.kind != 'o' {
		return handle, errMCPSyntax
	}
	if withPayload {
		return handle, errMCPSyntax
	}
	if len(v.obj) != 1 {
		return handle, errMCPSyntax
	}
	raw, ok := v.field("handle")
	if !ok || raw.kind != 's' {
		return handle, errMCPSyntax
	}
	buf, ok := canonicalB64(raw.s, 32)
	if !ok {
		return handle, errMCPSyntax
	}
	copy(handle[:], buf)
	return handle, nil
}

func toolInvokeArgs(args json.RawMessage) ([32]byte, []byte, error) {
	var handle [32]byte
	v, err := parseJSONValue(args)
	if err != nil || v.kind != 'o' || len(v.obj) != 2 {
		return handle, nil, errMCPSyntax
	}
	h, ok := v.field("handle")
	p, pok := v.field("payload")
	if !ok || !pok || h.kind != 's' || p.kind != 's' {
		return handle, nil, errMCPSyntax
	}
	buf, ok := canonicalB64(h.s, 32)
	if !ok {
		return handle, nil, errMCPSyntax
	}
	payload, ok := canonicalB64Range(p.s, 1, MaxAttestPayload)
	if !ok {
		return handle, nil, errMCPSyntax
	}
	copy(handle[:], buf)
	return handle, payload, nil
}

func canonicalB64(s string, n int) ([]byte, bool) {
	return canonicalB64Range(s, n, n)
}

func canonicalB64Range(s string, minN, maxN int) ([]byte, bool) {
	if s == "" || len(s) > base64.StdEncoding.EncodedLen(maxN) {
		return nil, false
	}
	buf, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(buf) < minN || len(buf) > maxN {
		return nil, false
	}
	if base64.StdEncoding.EncodeToString(buf) != s {
		return nil, false
	}
	return buf, true
}

func projectCap(raw []byte, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return nil, rpcError(jsonrpc.CodeInternalError)
	}
	resp, err := decodeCapResponse(raw)
	if err != nil {
		return nil, rpcError(jsonrpc.CodeInternalError)
	}
	switch resp.method {
	case capMethodError:
		return toolClosed(resp.code)
	case capMethodList:
		body := mcpListBody{Entries: make([]mcpEntryBody, 0, len(resp.entries))}
		for _, e := range resp.entries {
			body.Entries = append(body.Entries, entryBody(e))
		}
		return toolValue(body)
	case capMethodDescribe:
		return toolValue(entryBody(resp.entry))
	case capMethodInvoke:
		body := mcpInvokeBody{
			Resource:  resp.att.Resource,
			Signature: base64.StdEncoding.EncodeToString(resp.att.Signature[:]),
			PublicKey: base64.StdEncoding.EncodeToString(resp.att.PublicKey[:]),
			Domain:    resp.att.Domain,
			Purpose:   resp.att.Purpose,
		}
		if body.Domain != AttestDomain || body.Purpose != AttestPurpose || len(resp.att.Signature) != 64 || len(resp.att.PublicKey) != 32 {
			return nil, rpcError(jsonrpc.CodeInternalError)
		}
		return toolValue(body)
	default:
		return nil, rpcError(jsonrpc.CodeInternalError)
	}
}

func entryBody(e capEntry) mcpEntryBody {
	return mcpEntryBody{
		Handle:    base64.StdEncoding.EncodeToString(e.handle[:]),
		Operation: e.operation,
		Resource:  e.resource,
		KeyID:     e.keyID,
		Status:    e.status,
		Expiry:    e.expires.UTC().Format(timeRFC3339Nano),
	}
}

func toolValue(v any) (*mcp.CallToolResult, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > maxMCPFrame {
		return nil, rpcError(jsonrpc.CodeInternalError)
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(raw)}},
		StructuredContent: v,
	}, nil
}

func toolClosed(code string) (*mcp.CallToolResult, error) {
	text, ok := capText(code)
	if !ok {
		code = capDenied
		text, _ = capText(code)
	}
	raw, err := json.Marshal(mcpErrBody{Code: code, Message: text})
	if err != nil || len(raw) > maxMCPFrame {
		return nil, rpcError(jsonrpc.CodeInternalError)
	}
	// The advertised output schemas are the success projections. An IsError
	// result keeps the fixed text and does not add a second structured object.
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}},
		IsError: true,
	}, nil
}

func rpcError(code int64) error {
	code = normalizeCode(code)
	msg, _ := mcpMessage(code)
	return &jsonrpc.Error{Code: code, Message: msg}
}

type mcpListBody struct {
	Entries []mcpEntryBody `json:"entries"`
}

type mcpEntryBody struct {
	Handle    string `json:"handle"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
	KeyID     string `json:"key_id"`
	Status    string `json:"status"`
	Expiry    string `json:"expiry"`
}

type mcpInvokeBody struct {
	Resource  string `json:"resource"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
	Domain    string `json:"domain"`
	Purpose   string `json:"purpose"`
}

type mcpErrBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// timeRFC3339Nano is the canonical timestamp layout used by M10a projections.
const timeRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"

// admitTransport is the server Transport. It implements the SDK interfaces and
// sets IOTransport.MaxLineLength to the same 128 KiB cap enforced on the raw
// frame before that decoder runs.
type admitTransport struct {
	conn *admitConn
}

func (t *admitTransport) Connect(context.Context) (mcp.Connection, error) {
	if t == nil || t.conn == nil {
		return nil, ErrInvalid
	}
	return t.conn, nil
}

func (t *admitTransport) SupportsProtocolVersion(v string) bool {
	return v == mcpProtocolRevision
}

// admitConn validates each raw NDJSON frame before the SDK decodes it.
// Connection.Read on the inner IOTransport already returns one decoded
// envelope, so duplicate keys are rejected here, on the raw bytes.
type admitConn struct {
	ep   *MCPEndpoint
	in   *bufio.Reader
	raw  io.ReadCloser
	rawW io.WriteCloser

	// ep.mu protects admission and all output state. There are exactly two
	// output slots TOTAL: active (including its blocked Write) and pending.
	// One writer owns rawW. No goroutine or output slot is created per denial.
	closed     bool
	terminal   bool
	wake       chan struct{}
	writerDone chan struct{}
	once       sync.Once
}

type mcpOutput struct {
	frame      []byte
	key        callKey
	response   bool
	closeAfter bool
	done       chan error
}

func (c *admitConn) SessionID() string { return "" }

func (c *admitConn) startWriter() {
	c.wake = make(chan struct{}, 1)
	c.writerDone = make(chan struct{})
	go c.writeLoop()
}

func (c *admitConn) Close() error {
	var err error
	c.once.Do(func() {
		c.ep.mu.Lock()
		c.closed = true
		if c.ep.pending != nil {
			c.ep.pending.done <- io.ErrClosedPipe
			c.ep.pending = nil
		}
		c.ep.mu.Unlock()
		c.signalWriter()
		// Neither the endpoint nor the session lock is held over transport I/O.
		err = errors.Join(c.raw.Close(), c.rawW.Close())
	})
	return err
}

func (c *admitConn) signalWriter() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *admitConn) admit(d frameDecision) bool {
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	// Even an error write must finish before new credential work starts:
	// otherwise a broken output stream could execute an unrelated invocation.
	return !c.closed && !c.terminal && c.ep.active == nil && c.ep.pending == nil && c.ep.beginCallLocked(d.key, d.invoke)
}

func (c *admitConn) writeLoop() {
	defer close(c.writerDone)
	for {
		c.ep.mu.Lock()
		out, closed := c.ep.active, c.closed
		c.ep.mu.Unlock()
		if out == nil {
			if closed {
				return
			}
			<-c.wake
			continue
		}
		err := error(io.ErrClosedPipe)
		if !closed {
			var n int
			n, err = c.rawW.Write(out.frame)
			if err == nil && n != len(out.frame) {
				err = io.ErrShortWrite
			}
		}
		c.ep.mu.Lock()
		if c.closed && err == nil {
			err = io.ErrClosedPipe
		}
		if err != nil || out.closeAfter {
			// Refuse admission before unlocking, even if Close has not run yet.
			c.terminal = true
		}
		if out.response {
			c.ep.finishCallLocked(out.key)
		}
		// Taking pending and becoming idle is one atomic transition. A submit
		// can never install a frame between an empty check and going idle.
		c.ep.active, c.ep.pending = c.ep.pending, nil
		out.done <- err
		c.ep.mu.Unlock()
		if err != nil || out.closeAfter {
			_ = c.Close()
		}
	}
}

// submit never waits for output. A third frame fails closed, including when
// the active frame's bytes were consumed but its Write has not returned.
func (c *admitConn) submit(out *mcpOutput) error {
	out.done = make(chan error, 1)
	c.ep.mu.Lock()
	if c.closed || c.terminal {
		c.ep.mu.Unlock()
		return io.ErrClosedPipe
	}
	switch {
	case c.ep.active == nil:
		c.ep.active = out
	case c.ep.pending == nil:
		c.ep.pending = out
	default:
		c.terminal = true
		c.ep.mu.Unlock()
		_ = c.Close()
		return errMCPOutputFull
	}
	if out.closeAfter {
		c.terminal = true
	}
	c.ep.mu.Unlock()
	c.signalWriter()
	return nil
}

func (c *admitConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	for {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		frame, err := c.nextFrame()
		if err != nil {
			return nil, c.failFrame(frame, err)
		}
		d := classifyFrame(frame)
		c.ep.mu.Lock()
		terminal := c.closed || c.terminal
		c.ep.mu.Unlock()
		if terminal {
			// nextFrame already consumed this attempt, even if output failed
			// before Read resumed. Audit its bounded classification without
			// dispatch, output, or settling another admitted request.
			if err := c.drop(d); err != nil {
				return nil, err
			}
			_ = c.Close()
			return nil, io.ErrClosedPipe
		}
		switch d.op {
		case opForward:
			// The slot check never waits for rawW. A call arriving during
			// a blocked write is rejected immediately, even if that write
			// will complete before its rejection can be delivered.
			if !c.admit(d) {
				if err := c.reject(d, mcpCodeBusy); err != nil {
					return nil, err
				}
				continue
			}
			msg, err := decodeAdmitted(ctx, frame)
			if err != nil {
				if err := c.failAdmitted(d, err); err != nil {
					return nil, err
				}
				continue
			}
			return msg, nil
		case opCancel:
			if !c.ep.acceptCancel(d.key) {
				if err := c.drop(d); err != nil {
					return nil, err
				}
				continue
			}
			msg, err := decodeAdmitted(ctx, frame)
			if err != nil {
				// This rejected notice is separate from the admitted request.
				// Close lets SDK shutdown settle that request exactly once.
				if aerr := c.drop(d); aerr != nil {
					return nil, aerr
				}
				_ = c.Close()
				return nil, err
			}
			return msg, nil
		case opDrop:
			if err := c.drop(d); err != nil {
				return nil, err
			}
		default:
			if err := c.reject(d, d.code); err != nil {
				return nil, err
			}
		}
	}
}

func (c *admitConn) reject(d frameDecision, code int64) error {
	if err := c.ep.cap.denyBound(d.invoke); err != nil {
		return c.finishAuditFailure(d, err)
	}
	if err := c.writeCode(d.idRaw, code, d.requested); err != nil {
		_ = c.Close()
		return err
	}
	return nil
}

// drop audits a notification and writes nothing. The peer gets no response.
func (c *admitConn) drop(d frameDecision) error {
	if err := c.ep.cap.denyBound(d.invoke); err != nil {
		c.ep.noteAudit(err)
		_ = c.Close()
		return err
	}
	return nil
}

// failFrame audits a partial or oversized frame, then returns err.
// A denial that was not persisted is returned instead, so the host does not
// treat the attempt as recorded.
func (c *admitConn) failFrame(frame []byte, err error) error {
	if len(frame) == 0 {
		return err
	}
	d := classifyFrame(frame)
	if aerr := c.ep.cap.denyBound(d.invoke); aerr != nil {
		c.ep.noteAudit(aerr)
		_ = c.Close()
		return aerr
	}
	if errors.Is(err, errMCPFrame) {
		_ = c.Close()
	}
	return err
}

// failAdmitted settles a call the decoder rejected before the handler ran.
func (c *admitConn) failAdmitted(d frameDecision, err error) error {
	aerr := c.ep.settleDenied(d.key)
	if aerr != nil {
		return c.finishAuditFailure(d, aerr)
	}
	_ = c.Close()
	return err
}

// finishAuditFailure stops admission and schedules one fixed internal error
// when the id validated. The reader remains independent of that final write:
// further input closes the failed session, and Serve cancellation unblocks it.
// The writer closes after delivery; no response is guaranteed on a broken pipe.
func (c *admitConn) finishAuditFailure(d frameDecision, auditErr error) error {
	c.ep.noteAudit(auditErr)
	if d.idOK && d.op != opDrop {
		out := &mcpOutput{frame: encodeRPCError(d.idRaw, jsonrpc.CodeInternalError, ""), closeAfter: true}
		if err := c.submit(out); err == nil {
			return nil
		}
	}
	_ = c.Close()
	return auditErr
}

func (c *admitConn) Write(ctx context.Context, msg jsonrpc.Message) error {
	auditErr := c.settleWrite(msg)
	frame := frameFor(msg)
	if auditErr != nil {
		c.ep.noteAudit(auditErr)
		frame = encodeRPCError(responseID(msg), jsonrpc.CodeInternalError, "")
	}
	if ctx != nil && ctx.Err() != nil {
		_ = c.Close()
		if auditErr != nil {
			return auditErr
		}
		return ctx.Err()
	}
	out := &mcpOutput{frame: frame, closeAfter: auditErr != nil}
	if resp, ok := msg.(*jsonrpc.Response); ok {
		out.key, out.response = keyFromRPC(resp.ID)
	}
	err := c.submit(out)
	if err == nil {
		// Only the SDK response goroutine waits. Read keeps processing control
		// frames while the sole writer is blocked. Close settles queued output
		// as failure, never as delivery.
		err = <-out.done
	}
	if auditErr != nil {
		return auditErr
	}
	return err
}

// settleWrite records a pre-handler denial for an error response whose handler
// never ran. A successful response, or a handler that already audited, is left
// alone.
func (c *admitConn) settleWrite(msg jsonrpc.Message) error {
	resp, ok := msg.(*jsonrpc.Response)
	if !ok || resp.Error == nil || c.ep == nil {
		return nil
	}
	key, ok := keyFromRPC(resp.ID)
	if !ok {
		return nil
	}
	return c.ep.settleDenied(key)
}

func (c *admitConn) writeCode(id json.RawMessage, code int64, requested string) error {
	return c.submit(&mcpOutput{frame: encodeRPCError(id, code, requested)})
}

func (c *admitConn) nextFrame() ([]byte, error) {
	var buf []byte
	for {
		b, err := c.in.ReadByte()
		if err != nil {
			if len(buf) == 0 {
				return nil, err
			}
			// The peer closed after some bytes and before the delimiter.
			// Return those bytes so the caller can audit a complete value
			// that simply omitted the newline.
			return buf, io.ErrUnexpectedEOF
		}
		if b == '\n' {
			if len(buf) > 0 && buf[len(buf)-1] == '\r' {
				buf = buf[:len(buf)-1]
			}
			if len(buf) > maxMCPFrame {
				return buf, errMCPFrame
			}
			return buf, nil
		}
		if len(buf) >= maxMCPFrame {
			return buf, errMCPFrame
		}
		buf = append(buf, b)
	}
}

const (
	opReject = iota
	opForward
	opCancel
	opDrop
)

type frameDecision struct {
	op        int
	code      int64
	invoke    bool
	key       callKey
	idRaw     json.RawMessage
	idOK      bool
	requested string
}

func classifyFrame(frame []byte) frameDecision {
	deny := frameDecision{op: opReject, code: jsonrpc.CodeParseError, idRaw: []byte("null")}
	v, err := parseJSONValue(frame)
	if err != nil || v.kind != 'o' {
		// A valid notification envelope can contain arguments outside the
		// strict MCP profile (such as a nested array). It must still receive
		// no response. This fallback never admits or decodes a request.
		if rejectedNotificationEnvelope(frame) {
			return frameDecision{op: opDrop}
		}
		return deny
	}
	// An unambiguous tools/call named invoke_capability stays a local_attest
	// denial even when a later envelope or id check rejects the frame.
	// Unparseable input does not reach this assignment.
	deny.invoke = recognizedInvoke(v)
	ver, ok := v.field("jsonrpc")
	method, mok := v.field("method")
	if !ok || !mok || ver.kind != 's' || ver.s != "2.0" || method.kind != 's' || method.s == "" {
		deny.code = jsonrpc.CodeInvalidRequest
		return deny
	}
	id, hasID := v.field("id")
	params, hasParams := v.field("params")
	// Only a valid JSON-RPC notification envelope suppresses a response.
	// Local profile rejections of a genuine notification are still audited.
	// An absent id on a malformed envelope differs from an explicit null id.
	if !hasID {
		if hasParams && params.kind != 'o' {
			deny.code = jsonrpc.CodeInvalidRequest
			return deny
		}
		return classifyNotification(v, deny.invoke)
	}
	for _, kv := range v.obj {
		switch kv.k {
		case "jsonrpc", "id", "method", "params":
		default:
			deny.code = jsonrpc.CodeInvalidRequest
			return deny
		}
	}
	if len(method.s) > maxMCPName {
		deny.code = jsonrpc.CodeInvalidRequest
		return deny
	}
	raw, key, good := correlationID(id)
	if !good {
		deny.code = jsonrpc.CodeInvalidRequest
		return deny
	}
	deny.idRaw = raw
	deny.key = key
	deny.idOK = true
	if method.s == "notifications/cancelled" {
		deny.code = jsonrpc.CodeInvalidRequest
		return deny
	}
	if method.s == "initialize" {
		deny.code = mcp.CodeUnsupportedProtocolVersion
		deny.requested = requestedVersion(params, hasParams)
		return deny
	}
	switch method.s {
	case "server/discover", "tools/list", "tools/call":
	default:
		deny.code = jsonrpc.CodeMethodNotFound
		return deny
	}
	if !hasParams || params.kind != 'o' {
		deny.code = jsonrpc.CodeInvalidParams
		return deny
	}
	meta, mok := params.field("_meta")
	if !mok {
		deny.code = jsonrpc.CodeInvalidParams
		return deny
	}
	switch class, requested := classifyMeta(meta); class {
	case metaVersion:
		deny.code = mcp.CodeUnsupportedProtocolVersion
		deny.requested = requested
		return deny
	case metaOK:
	default:
		deny.code = jsonrpc.CodeInvalidParams
		return deny
	}
	invoke, code, ok := methodParams(method.s, params)
	if !ok {
		deny.code = code
		if invoke {
			deny.invoke = true
		}
		return deny
	}
	return frameDecision{op: opForward, invoke: invoke, key: deny.key, idRaw: deny.idRaw, idOK: true}
}

// rejectedNotificationEnvelope distinguishes a profile-rejected notification
// from malformed JSON/envelopes. Only bounded raw frames reach this standard
// decoder. Top-level duplicates remain invalid; params must be an object.
// Nested values are checked as JSON but never forwarded to the SDK or vault.
func rejectedNotificationEnvelope(frame []byte) bool {
	if len(frame) == 0 || len(frame) > maxMCPFrame || !utf8.Valid(frame) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(frame))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return false
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok || len(fields) >= mcpJSONKeys {
			return false
		}
		if _, duplicate := fields[key]; duplicate {
			return false
		}
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			return false
		}
		fields[key] = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return false
	}
	var extra json.RawMessage
	if !errors.Is(dec.Decode(&extra), io.EOF) {
		return false
	}
	if _, hasID := fields["id"]; hasID {
		return false
	}
	var version, method string
	if json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" ||
		json.Unmarshal(fields["method"], &method) != nil || method == "" {
		return false
	}
	if params, ok := fields["params"]; ok {
		params = bytes.TrimSpace(params)
		if len(params) == 0 || params[0] != '{' {
			return false
		}
	}
	return true
}

// classifyNotification audits later and produces no response. A valid
// notifications/cancelled for one outstanding id is forwarded once.
func classifyNotification(v jv, invoke bool) frameDecision {
	drop := frameDecision{op: opDrop, invoke: invoke}
	ver, ok := v.field("jsonrpc")
	method, mok := v.field("method")
	if !ok || !mok || ver.kind != 's' || ver.s != "2.0" || method.kind != 's' || method.s == "" || len(method.s) > maxMCPName {
		return drop
	}
	for _, kv := range v.obj {
		switch kv.k {
		case "jsonrpc", "method", "params":
		default:
			return drop
		}
	}
	if method.s != "notifications/cancelled" {
		return drop
	}
	params, hasParams := v.field("params")
	if !hasParams {
		return drop
	}
	key, good := cancelledParams(params)
	if !good {
		return drop
	}
	return frameDecision{op: opCancel, key: key}
}

func requestedVersion(params jv, hasParams bool) string {
	if !hasParams || params.kind != 'o' {
		return "invalid"
	}
	pv, ok := params.field("protocolVersion")
	if !ok || pv.kind != 's' || !safeVersionToken(pv.s) {
		return "invalid"
	}
	return pv.s
}

func recognizedInvoke(v jv) bool {
	method, ok := v.field("method")
	if !ok || method.kind != 's' || method.s != "tools/call" {
		return false
	}
	params, ok := v.field("params")
	if !ok || params.kind != 'o' {
		return false
	}
	name, ok := params.field("name")
	return ok && name.kind == 's' && name.s == toolInvoke
}

func correlationID(v jv) (json.RawMessage, callKey, bool) {
	switch v.kind {
	case 'n':
		if !v.okInt || v.raw == "" || v.i > maxMCPIDNumber {
			return nil, callKey{}, false
		}
		return json.RawMessage(v.raw), callKey{num: v.i, isNum: true}, true
	case 's':
		if !safeIDString(v.s) {
			return nil, callKey{}, false
		}
		raw, err := json.Marshal(v.s)
		if err != nil {
			return nil, callKey{}, false
		}
		return raw, callKey{str: v.s}, true
	default:
		return nil, callKey{}, false
	}
}

func safeIDString(s string) bool {
	if len(s) == 0 || len(s) > maxMCPIDString || !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

const (
	metaOK metaClass = iota
	metaInvalid
	metaVersion
)

type metaClass int

// classifyMeta accepts the selected revision's required _meta. A present but
// unsupported protocolVersion is metaVersion. A missing or malformed required
// field is metaInvalid and is not reported as an unsupported version.
func classifyMeta(v jv) (metaClass, string) {
	if v.kind != 'o' || v.rawEnd < v.rawBeg || v.rawEnd-v.rawBeg > maxMCPMeta {
		return metaInvalid, ""
	}
	var sawVersion, sawCaps bool
	var requested string
	var badVersion bool
	for _, kv := range v.obj {
		switch kv.k {
		case metaProtocolVersion:
			if kv.v.kind != 's' || !safeVersionToken(kv.v.s) {
				return metaInvalid, ""
			}
			sawVersion = true
			if kv.v.s != mcpProtocolRevision {
				badVersion = true
				requested = kv.v.s
			}
		case metaClientInfo:
			if !clientInfoAllowed(kv.v) {
				return metaInvalid, ""
			}
		case metaClientCapabilities:
			if !clientCapsAllowed(kv.v) {
				return metaInvalid, ""
			}
			sawCaps = true
		default:
			return metaInvalid, ""
		}
	}
	if !sawVersion || !sawCaps {
		return metaInvalid, ""
	}
	if badVersion {
		return metaVersion, requested
	}
	return metaOK, ""
}

// Protocol revisions are calendar dates. This is the sole non-id caller
// projection in an error, required by UnsupportedProtocolVersionData.Requested.
// Arbitrary tokens and metadata are never copied into that field.
func safeVersionToken(s string) bool {
	if len(s) != len("2006-01-02") {
		return false
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

func clientInfoAllowed(v jv) bool {
	if v.kind != 'o' {
		return false
	}
	var name, version bool
	for _, kv := range v.obj {
		if kv.v.kind != 's' || !safeIDString(kv.v.s) {
			return false
		}
		switch kv.k {
		case "name":
			name = true
		case "version":
			version = true
		default:
			return false
		}
	}
	return name && version
}

func clientCapsAllowed(v jv) bool {
	if v.kind != 'o' {
		return false
	}
	for _, kv := range v.obj {
		if kv.k != "roots" || kv.v.kind != 'o' {
			return false
		}
		for _, inner := range kv.v.obj {
			if inner.k != "listChanged" || inner.v.kind != 'b' {
				return false
			}
		}
	}
	return true
}

func methodParams(method string, params jv) (invoke bool, code int64, ok bool) {
	for _, kv := range params.obj {
		switch kv.k {
		case "_meta", "name", "arguments":
		default:
			return false, jsonrpc.CodeInvalidParams, false
		}
	}
	switch method {
	case "server/discover":
		if params.has("name") || params.has("arguments") {
			return false, jsonrpc.CodeInvalidParams, false
		}
		return false, 0, true
	case "tools/list":
		if params.has("name") || params.has("arguments") {
			return false, jsonrpc.CodeInvalidParams, false
		}
		return false, 0, true
	case "tools/call":
		name, nok := params.field("name")
		if !nok || name.kind != 's' {
			return false, jsonrpc.CodeInvalidParams, false
		}
		args, hasArgs := params.field("arguments")
		switch name.s {
		case toolInvoke:
			if !hasArgs || !invokeArgsOK(args) {
				return true, jsonrpc.CodeInvalidParams, false
			}
			return true, 0, true
		case toolDescribe:
			if !hasArgs || !describeArgsOK(args) {
				return false, jsonrpc.CodeInvalidParams, false
			}
			return false, 0, true
		case toolList:
			if hasArgs && !emptyArgs(args) {
				return false, jsonrpc.CodeInvalidParams, false
			}
			return false, 0, true
		case toolRequest:
			return false, jsonrpc.CodeInvalidParams, false
		default:
			return false, jsonrpc.CodeInvalidParams, false
		}
	default:
		return false, jsonrpc.CodeMethodNotFound, false
	}
}

func emptyArgs(v jv) bool {
	return v.kind == 'o' && len(v.obj) == 0
}

func describeArgsOK(v jv) bool {
	if v.kind != 'o' || len(v.obj) != 1 {
		return false
	}
	h, ok := v.field("handle")
	if !ok || h.kind != 's' {
		return false
	}
	_, good := canonicalB64(h.s, 32)
	return good
}

func invokeArgsOK(v jv) bool {
	if v.kind != 'o' || len(v.obj) != 2 {
		return false
	}
	h, ok := v.field("handle")
	p, pok := v.field("payload")
	if !ok || !pok || h.kind != 's' || p.kind != 's' {
		return false
	}
	if _, good := canonicalB64(h.s, 32); !good {
		return false
	}
	_, good := canonicalB64Range(p.s, 1, MaxAttestPayload)
	return good
}

func cancelledParams(v jv) (callKey, bool) {
	if v.kind != 'o' {
		return callKey{}, false
	}
	var id callKey
	var saw bool
	for _, kv := range v.obj {
		switch kv.k {
		case "requestId":
			_, key, ok := correlationID(kv.v)
			if !ok {
				return callKey{}, false
			}
			id = key
			saw = true
		case "reason":
			if kv.v.kind != 's' || len(kv.v.s) > maxMCPReason {
				return callKey{}, false
			}
		default:
			return callKey{}, false
		}
	}
	return id, saw
}

func decodeAdmitted(ctx context.Context, frame []byte) (jsonrpc.Message, error) {
	if len(frame) == 0 || len(frame) > maxMCPFrame {
		return nil, errMCPFrame
	}
	body := make([]byte, len(frame)+1)
	copy(body, frame)
	body[len(frame)] = '\n'
	r := io.NopCloser(bytes.NewReader(body))
	tr := &mcp.IOTransport{Reader: r, Writer: discardWC{}, MaxLineLength: maxMCPFrame + 1}
	conn, err := tr.Connect(ctx)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	msg, rerr := conn.Read(ctx)
	_ = conn.Close()
	_ = r.Close()
	return msg, rerr
}

type discardWC struct{}

func (discardWC) Write(p []byte) (int, error) { return len(p), nil }
func (discardWC) Close() error                { return nil }

func frameFor(msg jsonrpc.Message) []byte {
	raw, err := jsonrpc.EncodeMessage(msg)
	if err != nil || len(raw) == 0 || !utf8.Valid(raw) {
		return encodeRPCError([]byte("null"), jsonrpc.CodeInternalError, "")
	}
	id, code, isErr := probeRPC(raw)
	if isErr {
		return encodeRPCError(id, code, "")
	}
	if len(raw) > maxMCPFrame || jsonTrailing(raw) {
		return encodeRPCError(id, jsonrpc.CodeInternalError, "")
	}
	out := make([]byte, len(raw)+1)
	copy(out, raw)
	out[len(raw)] = '\n'
	return out
}

func probeRPC(raw []byte) (json.RawMessage, int64, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var head struct {
		ID    json.RawMessage `json:"id"`
		Error *struct {
			Code int64 `json:"code"`
		} `json:"error"`
	}
	if err := dec.Decode(&head); err != nil {
		return []byte("null"), jsonrpc.CodeInternalError, true
	}
	id := safeIDRaw(head.ID)
	if head.Error != nil {
		return id, head.Error.Code, true
	}
	return id, 0, false
}

func jsonTrailing(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var v any
	if err := dec.Decode(&v); err != nil {
		return true
	}
	var extra any
	err := dec.Decode(&extra)
	return !errors.Is(err, io.EOF)
}

func safeIDRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return []byte("null")
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || !safeIDString(s) {
			return []byte("null")
		}
		b, err := json.Marshal(s)
		if err != nil {
			return []byte("null")
		}
		return b
	}
	if n, ok := parseI64(string(raw)); ok && string(raw) != "" && n <= maxMCPIDNumber {
		return append([]byte(nil), raw...)
	}
	return []byte("null")
}

func encodeRPCError(id json.RawMessage, code int64, requested string) []byte {
	if len(id) == 0 {
		id = []byte("null")
	}
	code = normalizeCode(code)
	msg, _ := mcpMessage(code)
	var frame string
	if code == mcp.CodeUnsupportedProtocolVersion {
		if !safeVersionToken(requested) {
			requested = "invalid"
		}
		// supported is the fixed allowlist. requested is a bounded token, not
		// the raw frame, and is not added to supported.
		frame = fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":%d,\"message\":%q,\"data\":{\"supported\":[%q],\"requested\":%q}}}\n", id, code, msg, mcpProtocolRevision, requested)
	} else {
		frame = fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":%d,\"message\":%q}}\n", id, code, msg)
	}
	if len(frame) > maxMCPFrame+1 {
		frame = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"internal error\"}}\n"
	}
	return []byte(frame)
}

func normalizeCode(code int64) int64 {
	switch code {
	case jsonrpc.CodeParseError, jsonrpc.CodeInvalidRequest, jsonrpc.CodeMethodNotFound, jsonrpc.CodeInvalidParams, jsonrpc.CodeInternalError, mcp.CodeUnsupportedProtocolVersion, mcpCodeBusy, mcpCodeCancelled:
		return code
	default:
		return jsonrpc.CodeInternalError
	}
}

func mcpMessage(code int64) (string, bool) {
	switch code {
	case jsonrpc.CodeParseError:
		return "parse error", true
	case jsonrpc.CodeInvalidRequest:
		return "invalid request", true
	case jsonrpc.CodeMethodNotFound:
		return "method not found", true
	case jsonrpc.CodeInvalidParams:
		return "invalid params", true
	case jsonrpc.CodeInternalError:
		return "internal error", true
	case mcp.CodeUnsupportedProtocolVersion:
		return "unsupported protocol version", true
	case mcpCodeBusy:
		return "endpoint busy", true
	case mcpCodeCancelled:
		return "request cancelled", true
	default:
		return "internal error", false
	}
}

func keyFromRPC(id jsonrpc.ID) (callKey, bool) {
	switch v := id.Raw().(type) {
	case int64:
		if v < 0 || v > maxMCPIDNumber {
			return callKey{}, false
		}
		return callKey{num: v, isNum: true}, true
	case string:
		if !safeIDString(v) {
			return callKey{}, false
		}
		return callKey{str: v}, true
	case float64:
		if v < 0 || v > float64(maxMCPIDNumber) || v != float64(int64(v)) {
			return callKey{}, false
		}
		return callKey{num: int64(v), isNum: true}, true
	default:
		return callKey{}, false
	}
}

func responseID(msg jsonrpc.Message) json.RawMessage {
	resp, ok := msg.(*jsonrpc.Response)
	if !ok {
		return []byte("null")
	}
	switch v := resp.ID.Raw().(type) {
	case int64:
		if v < 0 || v > maxMCPIDNumber {
			return []byte("null")
		}
		return strconv.AppendInt(nil, v, 10)
	case float64:
		if v < 0 || v > float64(maxMCPIDNumber) || v != float64(int64(v)) {
			return []byte("null")
		}
		return strconv.AppendInt(nil, int64(v), 10)
	case string:
		if !safeIDString(v) {
			return []byte("null")
		}
		b, err := json.Marshal(v)
		if err != nil {
			return []byte("null")
		}
		return b
	default:
		return []byte("null")
	}
}

// mcpLog records that the SDK logged and drops the message and every attribute.
// Credentials, payloads, frames, handles, and caller text are not written.
type mcpLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (h *mcpLog) Enabled(context.Context, slog.Level) bool { return true }
func (h *mcpLog) Handle(context.Context, slog.Record) error {
	h.mu.Lock()
	h.buf.WriteString("mcp\n")
	h.mu.Unlock()
	return nil
}
func (h *mcpLog) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *mcpLog) WithGroup(string) slog.Handler      { return h }

func (h *mcpLog) text() string {
	if h == nil {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.buf.String()
}

const mcpEntrySchema = `{"type":"object","additionalProperties":false,"required":["handle","operation","resource","key_id","status","expiry"],"properties":{"handle":{"type":"string","minLength":44,"maxLength":44,"contentEncoding":"base64"},"operation":{"type":"string","const":"local_artifact_attest"},"resource":{"type":"string"},"key_id":{"type":"string","minLength":64,"maxLength":64},"status":{"type":"string","enum":["active","revoked","expired"]},"expiry":{"type":"string"}}}`

const mcpListInSchema = `{"type":"object","additionalProperties":false,"properties":{}}`

const mcpListOutSchema = `{"type":"object","additionalProperties":false,"required":["entries"],"properties":{"entries":{"type":"array","maxItems":64,"items":` + mcpEntrySchema + `}}}`

const mcpDescribeInSchema = `{"type":"object","additionalProperties":false,"required":["handle"],"properties":{"handle":{"type":"string","minLength":44,"maxLength":44,"contentEncoding":"base64"}}}`

const mcpInvokeInSchema = `{"type":"object","additionalProperties":false,"required":["handle","payload"],"properties":{"handle":{"type":"string","minLength":44,"maxLength":44,"contentEncoding":"base64"},"payload":{"type":"string","minLength":4,"maxLength":87384,"contentEncoding":"base64"}}}`

const mcpInvokeOutSchema = `{"type":"object","additionalProperties":false,"required":["resource","signature","public_key","domain","purpose"],"properties":{"resource":{"type":"string"},"signature":{"type":"string","minLength":88,"maxLength":88,"contentEncoding":"base64"},"public_key":{"type":"string","minLength":44,"maxLength":44,"contentEncoding":"base64"},"domain":{"type":"string","const":"tremelay/local-artifact-attestation/v1"},"purpose":{"type":"string","const":"local-artifact-attestation"}}}`

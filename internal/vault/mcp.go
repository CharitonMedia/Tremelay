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
	"sync"
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
	maxMCPName     = 64
	maxMCPReason   = 128

	// mcpCodeBusy is the fixed JSON-RPC code for a second request while one
	// call is already inside this endpoint. There is no waiting queue.
	mcpCodeBusy = -32010
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
// A second request fails closed and does not wait. Cancellation and close do
// not recall a signature already released, and a missing response is not a
// signal to replay the call.
type MCPEndpoint struct {
	cap    *AgentCapability
	server *mcp.Server
	logs   *mcpLog

	mu         sync.Mutex
	serving    bool
	inCall     bool
	callID     callKey
	cancelSent bool
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
// ctx or by closing the pipe. A second Serve on the same endpoint is refused.
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
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.serving = false
		e.inCall = false
		e.cancelSent = false
		e.mu.Unlock()
	}()

	conn := &admitConn{
		ep:   e,
		in:   bufio.NewReaderSize(r, 4096),
		raw:  r,
		rawW: w,
	}
	tr := &admitTransport{conn: conn}
	ss, err := e.server.Connect(context.Background(), tr, nil)
	if err != nil {
		return ErrInvalid
	}
	defer ss.Close()
	errc := make(chan error, 1)
	go func() { errc <- ss.Wait() }()
	select {
	case <-ctx.Done():
		_ = ss.Close()
		_ = conn.Close()
		<-errc
		return ctx.Err()
	case err := <-errc:
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
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

func (e *MCPEndpoint) beginCall(id callKey) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inCall {
		return false
	}
	e.inCall = true
	e.callID = id
	e.cancelSent = false
	return true
}

func (e *MCPEndpoint) finishCall(id callKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inCall && e.callID.matches(id) {
		e.inCall = false
		e.cancelSent = false
	}
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
	res, err := toolValue(mcpErrBody{Code: code, Message: text})
	if err != nil {
		return nil, err
	}
	res.IsError = true
	return res, nil
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

// timeRFC3339Nano is time.RFC3339Nano without importing time into every helper.
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
	wmu  sync.Mutex
	once sync.Once
}

func (c *admitConn) SessionID() string { return "" }

func (c *admitConn) Close() error {
	var err error
	c.once.Do(func() {
		err = errors.Join(c.raw.Close(), c.rawW.Close())
	})
	return err
}

func (c *admitConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	for {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		frame, err := c.nextFrame()
		if err != nil {
			if errors.Is(err, errMCPFrame) {
				_ = c.ep.cap.denyBound(false)
				_ = c.Close()
			}
			return nil, err
		}
		d := classifyFrame(frame)
		switch d.op {
		case opForward:
			if !c.ep.beginCall(d.key) {
				c.reject(d, mcpCodeBusy)
				continue
			}
			msg, err := decodeAdmitted(ctx, frame)
			if err != nil {
				c.ep.finishCall(d.key)
				_ = c.Close()
				return nil, err
			}
			return msg, nil
		case opCancel:
			if !c.ep.acceptCancel(d.key) {
				continue
			}
			msg, err := decodeAdmitted(ctx, frame)
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			return msg, nil
		default:
			c.reject(d, d.code)
		}
	}
}

func (c *admitConn) reject(d frameDecision, code int64) {
	if err := c.ep.cap.denyBound(d.invoke); err != nil {
		_ = c.writeCode([]byte("null"), jsonrpc.CodeInternalError)
		return
	}
	_ = c.writeCode(d.idRaw, code)
}

func (c *admitConn) Write(ctx context.Context, msg jsonrpc.Message) error {
	// Release the slot before the peer can read the bytes. The handler has
	// already returned, so the next call does not overlap it. A cancelled
	// write still releases the slot and does not recall a signature.
	c.noteResponse(msg)
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	frame := frameFor(msg)
	c.wmu.Lock()
	_, err := c.rawW.Write(frame)
	c.wmu.Unlock()
	return err
}

func (c *admitConn) noteResponse(msg jsonrpc.Message) {
	resp, ok := msg.(*jsonrpc.Response)
	if !ok || c.ep == nil {
		return
	}
	if key, ok := keyFromRPC(resp.ID); ok {
		c.ep.finishCall(key)
	}
}

func (c *admitConn) writeCode(id json.RawMessage, code int64) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.rawW.Write(encodeRPCError(id, code))
	return err
}

func (c *admitConn) nextFrame() ([]byte, error) {
	var buf []byte
	for {
		b, err := c.in.ReadByte()
		if err != nil {
			if len(buf) == 0 {
				return nil, err
			}
			return nil, io.ErrUnexpectedEOF
		}
		if b == '\n' {
			if len(buf) > 0 && buf[len(buf)-1] == '\r' {
				buf = buf[:len(buf)-1]
			}
			if len(buf) > maxMCPFrame {
				return nil, errMCPFrame
			}
			return buf, nil
		}
		if len(buf) >= maxMCPFrame {
			return nil, errMCPFrame
		}
		buf = append(buf, b)
	}
}

const (
	opReject = iota
	opForward
	opCancel
)

type frameDecision struct {
	op     int
	code   int64
	invoke bool
	key    callKey
	idRaw  json.RawMessage
	idOK   bool
}

func classifyFrame(frame []byte) frameDecision {
	deny := frameDecision{op: opReject, code: jsonrpc.CodeParseError, idRaw: []byte("null")}
	v, err := parseJSONValue(frame)
	if err != nil || v.kind != 'o' {
		return deny
	}
	ver, ok := v.field("jsonrpc")
	method, mok := v.field("method")
	if !ok || !mok || ver.kind != 's' || ver.s != "2.0" || method.kind != 's' || method.s == "" || len(method.s) > maxMCPName {
		deny.code = jsonrpc.CodeInvalidRequest
		return deny
	}
	id, hasID := v.field("id")
	params, hasParams := v.field("params")
	for _, kv := range v.obj {
		switch kv.k {
		case "jsonrpc", "id", "method", "params":
		default:
			deny.code = jsonrpc.CodeInvalidRequest
			return deny
		}
	}
	if hasID {
		raw, key, good := correlationID(id)
		if !good {
			deny.code = jsonrpc.CodeInvalidRequest
			return deny
		}
		deny.idRaw = raw
		deny.key = key
		deny.idOK = true
	}
	if method.s == "notifications/cancelled" {
		if hasID || !hasParams {
			deny.code = jsonrpc.CodeInvalidRequest
			return deny
		}
		key, ok := cancelledParams(params)
		if !ok {
			deny.code = jsonrpc.CodeInvalidParams
			return deny
		}
		return frameDecision{op: opCancel, key: key}
	}
	if !hasID {
		deny.code = jsonrpc.CodeInvalidRequest
		return deny
	}
	if method.s == "initialize" {
		deny.code = mcp.CodeUnsupportedProtocolVersion
		return deny
	}
	switch method.s {
	case "server/discover", "tools/list", "tools/call":
	default:
		deny.code = jsonrpc.CodeMethodNotFound
		return deny
	}
	if method.s == "tools/call" && hasParams && params.kind == 'o' {
		if name, nok := params.field("name"); nok && name.kind == 's' && name.s == toolInvoke {
			deny.invoke = true
		}
	}
	if !hasParams || params.kind != 'o' {
		deny.code = mcp.CodeUnsupportedProtocolVersion
		return deny
	}
	meta, mok := params.field("_meta")
	if !mok || !metaAllowed(meta) {
		deny.code = mcp.CodeUnsupportedProtocolVersion
		return deny
	}
	invoke, code, ok := methodParams(method.s, params)
	if !ok {
		deny.code = code
		deny.invoke = invoke
		return deny
	}
	return frameDecision{op: opForward, invoke: invoke, key: deny.key, idRaw: deny.idRaw, idOK: true}
}

func correlationID(v jv) (json.RawMessage, callKey, bool) {
	switch v.kind {
	case 'n':
		if !v.okInt || v.raw == "" {
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

func metaAllowed(v jv) bool {
	if v.kind != 'o' || v.rawEnd < v.rawBeg || v.rawEnd-v.rawBeg > maxMCPMeta {
		return false
	}
	var sawVersion, sawCaps bool
	for _, kv := range v.obj {
		switch kv.k {
		case metaProtocolVersion:
			if kv.v.kind != 's' || kv.v.s != mcpProtocolRevision {
				return false
			}
			sawVersion = true
		case metaClientInfo:
			if !clientInfoAllowed(kv.v) {
				return false
			}
		case metaClientCapabilities:
			if !clientCapsAllowed(kv.v) {
				return false
			}
			sawCaps = true
		default:
			return false
		}
	}
	return sawVersion && sawCaps
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
		return encodeRPCError([]byte("null"), jsonrpc.CodeInternalError)
	}
	id, code, isErr := probeRPC(raw)
	if isErr {
		return encodeRPCError(id, code)
	}
	if len(raw) > maxMCPFrame || jsonTrailing(raw) {
		return encodeRPCError(id, jsonrpc.CodeInternalError)
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
	if _, ok := parseI64(string(raw)); ok && string(raw) != "" {
		return append([]byte(nil), raw...)
	}
	return []byte("null")
}

func encodeRPCError(id json.RawMessage, code int64) []byte {
	if len(id) == 0 {
		id = []byte("null")
	}
	code = normalizeCode(code)
	msg, _ := mcpMessage(code)
	frame := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":%d,\"message\":%q}}\n", id, code, msg)
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
		return callKey{num: v, isNum: true}, true
	case string:
		if !safeIDString(v) {
			return callKey{}, false
		}
		return callKey{str: v}, true
	case float64:
		if v < 0 || v != float64(int64(v)) {
			return callKey{}, false
		}
		return callKey{num: int64(v), isNum: true}, true
	default:
		return callKey{}, false
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

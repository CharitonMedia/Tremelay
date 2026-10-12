package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpStdio20250618     = "2025-06-18"
	mcpStdio20251125     = "2025-11-25"
	stdioHandoffDeadline = 10 * time.Millisecond
)

const (
	stdioNew = iota
	stdioInitializing
	stdioAwaitInitialized
	stdioReady
)

// BindStdioMCPEndpoint binds the interoperable initialize-based profile to the
// same exact agent capability as the modern reference endpoint. The caller is
// the trusted host, not the MCP client. Serve takes owned, cancellable pipes.
// No frame can replace this binding or select the modern per-request lifecycle.
func BindStdioMCPEndpoint(cap *AgentCapability) (*MCPEndpoint, error) {
	return bindMCPEndpoint(cap, true)
}

func (c *admitConn) classifyFrame(frame []byte) frameDecision {
	if c.ep.stdio {
		return classifyStdioFrame(frame)
	}
	return classifyFrame(frame)
}

// waitStdioHandoff resolves a response-write/admission scheduling race for
// ordinary sequential process clients. It retains only the frame Read already
// holds, waits only for the exact active response, and never admits a new call.
// Fixed errors are included only when no call is admitted (for example, an
// unsupported discovery probe followed by initialize); an error concurrent
// with credential work must not delay control input.
// A blocked writer expires at a 10ms deadline; this is not an OS latency promise.
// The modern reference keeps immediate-busy behavior. Process cancellation
// independently closes both pipes; protocol cancellation remains bounded by this
// one deadline, with no per-input goroutine or unbounded request queue.
func (c *admitConn) waitStdioHandoff(ctx context.Context) {
	if !c.ep.stdio {
		return
	}
	c.ep.mu.Lock()
	active := c.ep.active
	var done <-chan struct{}
	if !c.closed && !c.terminal && active != nil && (active.response || !c.ep.inCall) && c.ep.pending == nil {
		done = active.complete
	}
	c.ep.mu.Unlock()
	if done == nil {
		return
	}
	var canceled <-chan struct{}
	if ctx != nil {
		canceled = ctx.Done()
	}
	timer := time.NewTimer(stdioHandoffDeadline)
	defer timer.Stop()
	select {
	case <-done:
	case <-canceled:
	case <-timer.C:
	}
}

func (c *admitConn) stdioLifecycleAllowed(d frameDecision) bool {
	if !c.ep.stdio {
		return true
	}
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	switch d.method {
	case "initialize":
		return c.legacyPhase == stdioNew
	case "ping":
		return true // The MCP lifecycle permits ping before initialization.
	default:
		return c.legacyPhase == stdioReady || (c.legacyPhase == stdioInitializing && c.initializeNotice)
	}
}

func (c *admitConn) acceptInitialized() bool {
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	if !c.ep.stdio || c.closed || c.terminal || c.initializeNotice || (c.legacyPhase != stdioAwaitInitialized && c.legacyPhase != stdioInitializing) {
		return false
	}
	c.initializeNotice = true
	if c.legacyPhase == stdioAwaitInitialized {
		c.legacyPhase = stdioReady
	}
	return true
}

// The legacy profile reuses the same strict raw scanner. Client capabilities,
// identity and tracing/progress metadata are bounded advisory objects. They do
// not enable callbacks, add tools, change authority or escape into logs/errors.
func classifyStdioFrame(frame []byte) frameDecision {
	d := frameDecision{op: opReject, code: jsonrpc.CodeParseError, idRaw: []byte("null")}
	v, err := parseJSONValue(frame)
	if err != nil {
		if rejectedNotificationEnvelope(frame) {
			return frameDecision{op: opDrop}
		}
		return d
	}
	d.invoke = recognizedInvoke(v)
	d.code = jsonrpc.CodeInvalidRequest
	if v.kind != 'o' {
		return d
	}
	version, vok := v.field("jsonrpc")
	method, mok := v.field("method")
	params, hasParams := v.field("params")
	id, hasID := v.field("id")
	if !vok || version.kind != 's' || version.s != "2.0" || !mok || method.kind != 's' || method.s == "" || (hasParams && params.kind != 'o') {
		return d
	}
	if !hasID {
		d.op = opDrop
	}
	for _, kv := range v.obj {
		switch kv.k {
		case "jsonrpc", "id", "method", "params":
		default:
			return d
		}
	}
	if len(method.s) > maxMCPName {
		return d
	}
	if !hasID {
		if method.s == "notifications/initialized" && (!hasParams || stdioEmptyParams(params)) {
			d.op = opInitialized
			return d
		}
		return classifyNotification(v, d.invoke)
	}
	raw, key, ok := correlationID(id)
	if !ok {
		return d
	}
	d.idRaw, d.key, d.idOK = raw, key, true
	d.method = method.s
	d.code = jsonrpc.CodeInvalidParams
	if !hasParams {
		params = jv{kind: 'o'}
	}
	switch method.s {
	case "initialize":
		if !stdioInitializeParams(params) {
			return d
		}
		pv, _ := params.field("protocolVersion")
		if pv.s != mcpStdio20250618 && pv.s != mcpStdio20251125 {
			d.code, d.requested = mcp.CodeUnsupportedProtocolVersion, pv.s
			return d
		}
	case "ping":
		if !stdioEmptyParams(params) {
			return d
		}
	case "tools/list", "tools/call":
		if meta, present := params.field("_meta"); present && !stdioMetaAllowed(meta) {
			return d
		}
		invoke, code, ok := methodParams(method.s, params)
		if !ok {
			d.code = code
			d.invoke = d.invoke || invoke
			return d
		}
	default:
		// In particular, discovery probes get a supported MCP error, letting
		// modern auto-negotiating clients fall back to initialize explicitly.
		d.code = jsonrpc.CodeMethodNotFound
		return d
	}
	d.op = opForward
	return d
}

func stdioEmptyParams(v jv) bool {
	if v.kind != 'o' {
		return false
	}
	for _, kv := range v.obj {
		if kv.k != "_meta" || !stdioMetaAllowed(kv.v) {
			return false
		}
	}
	return true
}

func stdioMetaAllowed(v jv) bool {
	if v.kind != 'o' || v.rawEnd < v.rawBeg || v.rawEnd-v.rawBeg > maxMCPMeta {
		return false
	}
	for _, kv := range v.obj {
		// These activate the SDK's stateless path, bypassing the initialize
		// contract. Ordinary trace/progress extension metadata stays advisory.
		switch kv.k {
		case metaProtocolVersion, metaClientInfo, metaClientCapabilities:
			return false
		case "progressToken":
			if _, _, ok := correlationID(kv.v); !ok {
				return false
			}
		}
	}
	return true
}

func stdioInitializeParams(v jv) bool {
	if v.kind != 'o' || v.rawEnd-v.rawBeg > maxMCPMeta {
		return false
	}
	var sawVersion, sawCaps, sawInfo bool
	for _, kv := range v.obj {
		switch kv.k {
		case "protocolVersion":
			if kv.v.kind != 's' || !safeVersionToken(kv.v.s) {
				return false
			}
			sawVersion = true
		case "capabilities":
			if kv.v.kind != 'o' {
				return false
			}
			sawCaps = true
		case "clientInfo":
			if !stdioClientInfo(kv.v) {
				return false
			}
			sawInfo = true
		case "_meta":
			if !stdioMetaAllowed(kv.v) {
				return false
			}
		default:
			return false
		}
	}
	return sawVersion && sawCaps && sawInfo
}

func stdioClientInfo(v jv) bool {
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
		case "title", "description", "websiteUrl":
		default:
			return false
		}
	}
	return name && version
}

func (c *admitConn) errorFrame(id json.RawMessage, code int64, requested string) []byte {
	if !c.ep.stdio || code != mcp.CodeUnsupportedProtocolVersion {
		return encodeRPCError(id, code, requested)
	}
	if len(id) == 0 {
		id = []byte("null")
	}
	if !safeVersionToken(requested) {
		requested = "invalid"
	}
	return []byte(fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":%d,\"message\":\"unsupported protocol version\",\"data\":{\"supported\":[%q,%q],\"requested\":%q}}}\n", id, code, mcpStdio20251125, mcpStdio20250618, requested))
}

# ADR 0018: Local MCP capability reference

Status: Accepted

## Context

M10a is the in-process message boundary for `local_artifact_attest` ([ADR 0017](0017-agent-capability-interface.md)). M10b asks for one MCP peer in front of that boundary. The peer must use the official Go SDK, not a private dialect, and the caller must not be able to choose the agent or widen the grant.

The pinned module is `github.com/modelcontextprotocol/go-sdk` v1.8.0, tag commit `3f3b699b2b67e1ed033a63d6651671dab53c2d32`. The only wire revision is MCP `2026-07-28`. The SDK's `negotiatedVersion` answers a legacy `initialize` with `2025-11-25` when the server list contains only `2026-07-28`. Its receiving middleware runs after some parse checks. Its jsonrpc handler queue is an unbounded slice. A handler mutex or a tool-schema validator does not close those gaps. The exported `Transport`, `Connection`, and `IOTransport.MaxLineLength` hooks are enough to reject frames before that queue sees them, so this slice does not fork the SDK.

M9 authentication, recovery, and production shared access stay open. M10 production deployment, remote authentication, a distributed public SDK, and agent-request sponsorship stay open. No production cutover is authorized.

## Decision

### Host binding

`BindMCPEndpoint` accepts one `AgentCapability` the host has already bound. It does not accept a session, a principal id, a vault path, or unlock material. Messages, `clientInfo`, correlation ids, `_meta`, tool names, and handles cannot replace the agent, a human, the session, the vault, the clock, or a callback. The peer does not call `RequestAccess`, mint an assertion, or mutate a grant.

The host must not use that session on another goroutine while `Serve` is running, except from a callback the session invokes after it drops its own lock. This process does not enforce that duty for any other process.

### Wire profile

`Serve` reads and writes newline-delimited JSON on the two ends of an in-memory pipe. There is no socket, listener, or process. The server and the demonstration client are the official SDK. The server's supported list is exactly `2026-07-28`. The client's `ClientSessionOptions.ProtocolVersion` is the same string. The demonstration asserts `ClientSession.InitializeResult().ProtocolVersion` is `2026-07-28` after `Connect`. An advertised preference is not that assertion.

The client opens the session with `server/discover`. Later calls are `tools/list` and `tools/call`. Each of those carries `_meta` with `io.modelcontextprotocol/protocolVersion` equal to `2026-07-28` and `io.modelcontextprotocol/clientCapabilities`. `io.modelcontextprotocol/clientInfo` may be present and is not an authority. `notifications/cancelled` is the cancellation notice the pinned client sends; it does not carry that `_meta` triple.

No other method is forwarded. `initialize` is rejected at the raw-frame gate with JSON-RPC `-32022`, the fixed message `unsupported protocol version`, and `data.supported` set to exactly `["2026-07-28"]`. That list does not include `2025-11-25`. `ping`, subscriptions, sampling, elicitation, logging, resources, and prompts are not implemented. The server advertises tools only, with `listChanged` false. The demonstration client sets empty capabilities and disables multi-round-trip handling.

`tools/list` returns exactly `list_capabilities`, `describe_capability`, and `invoke_capability`, with the object schemas in `mcp.go`. It does not return the caller's grants. Grant discovery is only the bound `list_capabilities` call, which delegates to M10a. `request_capability` is not listed. A `tools/call` that names it is rejected and does not create a request or a grant.

### Admission

`admitTransport` implements `Transport` and `ProtocolVersionSupporter`. `admitConn` reads one NDJSON value, at most 128 KiB not counting the delimiter newline, before any SDK decode. A longer read closes the endpoint and is not truncated. The accepted bytes are then handed to a fresh `IOTransport` whose `MaxLineLength` is 128 KiB plus the newline. That inner `Connection.Read` already returns a decoded envelope, which is why duplicate keys are checked on the raw bytes first.

The raw scanner rejects invalid UTF-8, batches and other arrays, trailing values, non-integer numbers, nulls in required scalars, depth above 8, and more than 32 keys in one object. Object keys are compared after JSON string unescaping, so `\u0068andle` is a duplicate of `handle`. Tool arguments are exact: `list_capabilities` takes an empty object, `describe_capability` takes canonical base64 of 32 bytes, and `invoke_capability` takes that handle plus canonical base64 of 1 through 65536 payload bytes. Canonical base64 is `base64.StdEncoding` with padding; a value that decodes only after ignoring whitespace or a non-alphabet character is rejected. Unknown argument fields are rejected. Nothing is truncated.

`_meta` is at most 4 KiB. The allowlist is the protocol version, client capabilities, and client info described above. Capabilities may be `{}` or a `roots` object whose only field is `listChanged`. That metadata confers no authority.

Correlation ids are an integer from 0 through 2^53−1 without a fraction, an exponent, or a leading zero, or a string of 1 through 64 UTF-8 bytes with no ASCII control character. The ceiling is the largest integer the pinned SDK can round-trip: it decodes a JSON number as float64 and then converts that to int64. A larger id can round and miss the admission slot. A validated id may be copied into a response. An invalid or unknown id is represented by `id: null` in a fixed invalid-request response; its original bytes are never reflected. Explicit `id: null` is an invalid id, not a notification. An absent id suppresses a response only for a genuine notification envelope: `jsonrpc: "2.0"`, a nonempty string method, and object params when present. Malformed envelopes such as `{}`, a missing or wrong `jsonrpc`, or a non-string method retain the fixed invalid-request response. Genuine notifications rejected by the local profile are audited and dropped without a response. If the strict scanner rejects a frame (for example because an object parameter contains a nested array), a standard-library decoder makes a reject-only envelope check within the same 128 KiB frame cap and 32 top-level keys. It rejects duplicate envelope keys after string unescaping, explicit ids, trailing values, and non-object params. The standard decoder checks the nested JSON; the stricter depth, key, number, and array profile limits still prevent all forwarding. This recognition pass never admits the frame or infers an invocation from the rejected argument body; its denial is sparse `agent_capability`.

One forwarded call is outstanding. Its admission slot is taken before the frame reaches the SDK and remains held until its complete response write returns successfully or the connection fails terminally. This includes a response waiting behind a rejection frame, its closing brace, and its delimiter newline. Output is not split to reopen admission early. A generic `io.Writer` may return after the peer has consumed the complete frame, so a request in that interval may safely receive busy. This is a documented transport limit, not permission to replay an ambiguous invocation. The demonstration's host-side sequential fixtures wait for delivery to finish; a separate official SDK client regression verifies the busy interval itself.

One dedicated writer goroutine owns output for each `Serve`. There are exactly two retained output slots in total: one active frame, including any blocked transport write, plus one pending frame. Each includes at most 131072 value bytes and its newline, for at most 262146 retained frame bytes. A third submission fails closed and closes the pipe after its denial is audited. There is no queue of admitted calls and no goroutine per rejection. Taking a pending frame and becoming idle are one atomic transition under the same mutex as admission. That mutex is never held over transport I/O, auditing, or callbacks. The SDK response writer waits for actual completion; merely filling the pending slot is not delivery. Close reports pending output as failed. Short writes, failed writes, and overflow are terminal, and no subsequent credential work is admitted on that stream. New work is also refused while a rejection frame is still being delivered.

A second call gets application code `-31010` and the message `endpoint busy`, when the finite output capacity permits a response. That code is outside the JSON-RPC reserved range `-32768` through `-32000`, including the legacy MCP sub-range `-32000` through `-32019`. The read loop never performs a transport write, including for the first rejection on an otherwise idle output stream. It can therefore consume cancellation while output is blocked. `notifications/cancelled` naming the outstanding id is forwarded once so the SDK can cancel the handler context. Duplicate, unmatched, malformed, and other rejected genuine notifications each receive a sparse denial audit and no response; they do not settle the outstanding call a second time. If a matching cancellation passes the raw gate but fails the pinned SDK decoder, that rejected notification receives its own sparse `agent_capability` denial before closure. Shutdown independently settles the admitted invocation once; an audit failure on either path remains visible to the host.

Cancelling `Serve` closes both pipe ends before the SDK's graceful close. Both ends must support concurrent `Close` and unblock their I/O on close. `Serve` waits for both SDK dispatch (including callbacks) and the dedicated writer to terminate before returning or allowing a new sequential session. Concurrent `Serve` calls are refused without resetting anything. A stored audit failure takes precedence over routine cancellation/shutdown errors; only a later successfully admitted `Serve`, after full termination, clears that prior session's stored error. Closing the pipe does not recall a signature the vault already released.

Vault work and denial auditing use the existing session lock. The admission lock is not held across `Exchange`. A callback that reenters the endpoint sees the outstanding call, records a sparse denial, and returns. It does not wait on the admission lock.

### Authority and audit

Successful list, describe, and invoke build the M10a message and call `Exchange`. Handle binding, exact grant selection, `agentActive`, expiry, revocation, the current key and credential, shared membership generations, the trusted clock, the durable head, `allowed` before signing, and `completed` before output are unchanged. A failed required audit or a locked or stale session returns no signature. The peer does not claim the event was stored.

A recognizable `invoke_capability` rejected before `Exchange` records one sparse `local_attest` / `denied` row for the bound agent, with no grant, credential, handle, or caller text. Recognition is `tools/call` plus a string `params.name` of `invoke_capability`. A later rejection for the envelope, the correlation id, an unknown field, or a bad argument keeps that attribution. A frame that does not parse is not treated as an invocation. Other rejected attempts, including a dropped notification, record one sparse `agent_capability` / `denied` row. A partial NDJSON value whose peer closes before the delimiter is classified the same way and denied before the read error is returned. An admitted call that the SDK cancels, or that the decoder rejects, before the tool handler runs records one sparse denial. If the SDK stops the connection without calling `Write` — its reader is already closed, so it suppresses the response — `Serve` records that same denial once after dispatch has stopped. A denial the handler or `Exchange` already recorded is not recorded again. If that row cannot be written, the host gets the audit error from `Serve` or from the read that rejected the frame. For a failed pre-dispatch denial with a validated id, the endpoint stops admission and schedules one fixed correlated internal error, then closes after delivery. Further input, cancellation, broken output, or output overflow can close that failed session before delivery; no response is promised after terminal transport failure. A notification or an invalid id gets no response when its required denial audit fails. Partial-frame transport failures also close without an error-delivery guarantee. The host still receives the stored audit failure. The peer does not claim the event was stored. `denyBound` is the only new audit helper. It does not accept a caller identity or caller text.

### Errors, logs, and cancellation

Tool handlers are the low-level `Server.AddTool` handlers. The SDK's typed validator is not used, so its validation text cannot reflect raw arguments. Every peer-facing error is rewritten to a closed code and message: parse `-32700`, invalid request `-32600`, method not found `-32601`, invalid params `-32602`, internal `-32603`, unsupported protocol version `-32022`, busy `-31010`, and cancelled `-32800`. Missing or malformed required `_meta` is invalid params. `-32022` rejects legacy `initialize` and a well-formed request whose declared revision is unsupported. Its `error.data` has the fixed shape `{"supported":["2026-07-28"],"requested":"<version>"}`. The selected protocol and the pinned SDK's `UnsupportedProtocolVersionData` require both fields. This is the one narrowly approved caller-field projection beyond correlation ids: `requested` is a validated ten-character calendar date in `YYYY-MM-DD` form. An unparseable or missing legacy initialize revision is projected as the fixed literal `invalid`; a malformed required `_meta` version instead gets invalid params without data. Arbitrary tokens, strings, or metadata are not projected. `supported` is always exactly the fixed current revision and is never extended with the requested value. Other errors have no `data`. `err.Error()`, raw params, and caller tool names are not forwarded. A tool result with `IsError` carries that fixed code and message as text and does not set `structuredContent`. The advertised output schemas are the success projections, and the 2026-07-28 tools contract requires structured content to match `outputSchema`.

Responses are bounded to the same 128 KiB. An oversized or unreadable success is replaced with `internal error` and the original bytes, including any signature, are not written. The SDK logger and the client logger used by the demonstration are a handler that records only the token `mcp`. `LoggingTransport` is not used.

Cancellation observed before `Exchange` records a sparse denial and returns no signature. Cancellation after `Exchange` has returned a signature cannot revoke it. If transport output still succeeds, that public result can be delivered; cancellation or closure of the transport can prevent delivery without undoing the completed operation. Close does not abort the vault call already inside the session lock and does not recall a signature. A caller that does not see a response must not treat that as a recall or as permission to replay automatically. Ed25519 is deterministic, so a later successful call can repeat bytes; the new audit pair is the record of that later call.

### Bounds

| Limit | Value |
| --- | --- |
| Raw NDJSON value, either direction | 131072 bytes, newline excluded |
| Retained output | Two frames total: one active write plus one pending; 262146 bytes including newlines |
| Projected requested revision | Valid ten-character `YYYY-MM-DD` date, or fixed `invalid` for legacy initialize |
| `_meta` object | 4096 bytes |
| String correlation id | 64 UTF-8 bytes |
| Numeric correlation id | 0 through 9007199254740991 (2^53−1) |
| JSON object depth | 8 |
| Keys in one object | 32 |
| Cancellation reason | 128 bytes, not stored |
| Catalogue | 64 entries, denied in full above that |
| Payload | 1 through 65536 bytes |
| Payload base64 | 87384 characters (`4 * ceil(n/3)`) |
| Handle base64 | 44 characters |
| Largest admitted invoke frame | 91721 bytes (`mcpMaxInvokeFrame`) |

A 128 KiB frame can still hold base64 that decodes past 65536 bytes. That payload is rejected by the decoded bound. It is not truncated. The 91721-byte ceiling is a 64 KiB payload, a 32-byte handle, 4 KiB of `_meta`, and a 64-byte string id. It sits under the frame cap, which is why both checks exist.

### Dependency footprint

Direct module: `github.com/modelcontextprotocol/go-sdk` v1.8.0. Go stays 1.26.9. `go mod tidy` records these new indirect modules because the `mcp` package imports them:

- `github.com/google/jsonschema-go` v0.4.3, used by the SDK's typed tool helper. This slice registers raw schemas and does not call that validator.
- `github.com/segmentio/encoding` v0.5.4 and `github.com/segmentio/asm` v1.1.3, the SDK's JSON codec. Admission does not use it; the raw scanner runs first because that codec collapses duplicate keys.
- `github.com/yosida95/uritemplate/v3` v3.0.2, the SDK resource-template parser. No resources are registered.
- `golang.org/x/oauth2` v0.35.0, imported by the SDK's streamable HTTP client. This slice does not construct that transport, open a listener, or accept a token.
- `golang.org/x/sync` v0.23.0, used by the SDK multi-round-trip helper. The demonstration client disables that helper, and handlers do not return input requests.
- `golang.org/x/time` v0.15.0, the SDK log rate limiter. Logging capability is not advertised.

The SDK's own `go.mod` also lists `github.com/golang-jwt/jwt/v5`, `github.com/google/go-cmp`, and `golang.org/x/tools`. They are not imported by the packages this binary reaches, and tidy does not add them. No new cryptographic primitive is introduced. Attestation remains `crypto/ed25519` from [ADR 0012](0012-local-ed25519-attestation.md). `govulncheck ./...` reports no called vulnerability. The module-level findings it prints are in the already-pinned `golang.org/x/crypto` v0.41.0, not in the modules added here.

## Alternatives considered

- **Forward every frame and reject inside the tool handler.** Rejected. The SDK queue would already hold the call, duplicate keys would already be gone, and a legacy `initialize` would be answered as `2025-11-25`.
- **Fork the SDK to bound the handler queue and disable the initialize fallback.** Rejected. The exported transport hooks enforce the contract before dispatch.
- **Use typed `AddTool` so the SDK validates arguments.** Rejected. Its error text includes the raw value.
- **Treat `clientInfo` as the agent id.** Rejected. The host binding is the only identity.

## Security implications

- The peer cannot retrieve a secret, issue a grant, bind a human, or switch the agent.
- A handle still names one grant, credential, key, and resource. Another matching grant is not selected.
- Malformed input, a busy endpoint, and a failed audit do not return a signature.
- Peer errors and logs do not carry payloads, keys, handles, raw parser/error text, or arbitrary metadata. The only caller-field projections in errors are a validated correlation id and the protocol-required, narrowly validated requested revision. Invalid ids use the fixed null correlation value when an invalid-request response is appropriate.
- A signature that left the vault stays valid under Ed25519. Close and cancellation do not recall it.
- The host that holds the process and the passphrase remains the custody boundary. This slice does not authenticate a remote principal.

## Consequences

- The demonstration is an in-memory pipe. Operators do not get a network service or a published SDK.
- M10 remains open for remote authentication, SDK distribution, and `request_capability`.
- M9 remains open for authentication, recovery, and production shared access.
- Callers of `Exchange` and `LocalAttest` keep their existing behavior.

## Tests

`TestMCPSyntheticDemo` approves one shared local attestation, then uses the official SDK client over `IOTransport` to discover the peer, read the three tool schemas, list, describe, invoke, and verify the signature. `TestMCPWireAdmission` covers revision checks, the legacy initialize fallback, duplicate and unknown fields, base64, batches, invalid UTF-8, pre-handler denial, fixed errors, one outstanding call, cancellation, and an oversized frame. `TestMCPReviewFixes` covers a partial frame, trailing whitespace, invoke attribution, the numeric id ceiling, a second call rejected while a response write is blocked, one pre-handler denial, close unblocking that write, dropped notifications, a peer close before the handler finishes, a denial-audit failure returned to the host, and a failed error write stopping the session. `TestMCPOutputLifecycle` exercises incomplete tail delivery, a consumed frame whose write has not returned, cancellation during the first blocked busy write, duplicate and unmatched cancellation audits, a queued accepted response, fail-closed output overflow, and the transition back to idle. `TestMCPTerminalOutputFailures` covers short output, failed cancellation auditing, and input-triggered closure of a blocked terminal audit-error response. `TestMCPAuditSessionLifecycle` verifies audit-error precedence during shutdown and sequential reuse only after writer termination. `TestMCPRejectedNotificationShapes` and `TestMCPCancellationDecoderFailure` exercise rejected nested-array notices, ambiguous envelopes, decoder-rejected cancellation, and audit failure without double settlement. `TestMCPNotificationEnvelopes`, `TestMCPVersionProjection`, and `TestMCPOfficialClientBusyInterval` verify the envelope distinction, SDK-shaped revision data, and the actual official client's busy behavior without automatic replay. `TestMCPCallbackSerialization` revokes the selected grant during the signing callback while another grant matches, and reenters the endpoint without deadlocking. `TestMCPAuthority` carries foreign handles, revocation, expiry, suspension, key replacement, membership invalidation, a stale session, and a locked session through the MCP route. `TestMCPBounds`, `TestMCPJSON`, and `TestMCPOutputGuard` lock the size ceiling, the raw scanner, and the rule that an oversized success does not emit its signature.

## What was demonstrated

The tests above ran against the pinned SDK. The official client's negotiated revision was `2026-07-28`. `server/discover`, `tools/list`, `tools/call`, and `notifications/cancelled` were exercised on the pipe. Legacy `initialize` was rejected and did not return `2025-11-25`. HTTP, SSE, OAuth, sampling, elicitation, subscriptions, and logging were not demonstrated and are not part of the profile.

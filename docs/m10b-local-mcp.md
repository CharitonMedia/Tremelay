# M10b — local MCP capability reference

This is a partial slice of M10. A trusted host binds one agent, then binds one MCP endpoint to that adapter. An official MCP client discovers the endpoint, lists three fixed tools, and lists, describes, and invokes that principal's `local_artifact_attest` grants. The invocation returns the same public attestation M10a returns. The client verifies it with the public key.

This is a synthetic in-memory peer. It does not listen, authenticate a remote principal, or distribute a public SDK. It does not provision access or complete M9 or M10. See [ADR 0018](adr/0018-local-mcp-capability.md).

The SDK is `github.com/modelcontextprotocol/go-sdk` v1.8.0, commit `3f3b699b2b67e1ed033a63d6651671dab53c2d32`. The only protocol revision is `2026-07-28`. The server advertises that revision and the client requests it. After connect, the client's negotiated revision is `2026-07-28`.

`tools/list` describes `list_capabilities`, `describe_capability`, and `invoke_capability`. It does not list grants. Grant discovery is the bound `list_capabilities` call. `request_capability` is absent and is denied if a caller names it. Handles, payloads, and metadata cannot retarget the agent, the session, or the grant.

Each NDJSON value is at most 128 KiB. The attestation payload remains 1 through 64 KiB after canonical base64 decoding, which expands a 64 KiB payload to 87384 characters. A frame that is too large, a duplicate field (including an escaped alias), an unknown argument, or a second call while one is outstanding is rejected and is not truncated or queued. The outstanding call includes its response write, and a second call is rejected while that write is blocked. A notification other than cancellation of that call is audited and gets no response. Numeric correlation ids stop at 2^53−1 because the pinned SDK decodes JSON numbers as float64. One sparse denial is recorded for a rejected attempt that did not reach M10a, including a partial frame and a call cancelled before its handler. A failure to write that denial returns no signature, is returned to the host, and does not mean the event was stored. Tool errors are the fixed text only; they do not add a structured object outside the success schema.

Cancellation and close do not recall a signature that was already released. A caller that does not see a response must not treat that as a reason to replay the call automatically. The host must not use the session on another goroutine during `Serve`, except from a callback the session itself invokes. This process does not enforce that rule for other processes.

## Local demonstration

The demonstration uses a temporary database, a disposable Ed25519 key, synthetic identities, an in-memory pipe, and the official SDK client. It does not open a socket.

```bash
go test ./internal/vault/ -run 'TestMCPSyntheticDemo' -count=1
```

`TestMCPSyntheticDemo` approves one shared local-attestation grant, then discovers the peer, reads the tool schemas, lists, describes, invokes, and verifies the signature. `TestMCPWireAdmission` and `TestMCPAuthority` cover the admission gate and the M10a authority checks on the same route.

## What was demonstrated

The official client negotiated `2026-07-28` and completed discover, tool listing, and tool calls over `IOTransport`. A legacy `initialize` was rejected on that pipe and was not answered as `2025-11-25`. Cancellation during an in-flight call did not drop a signature the vault had already released.

## What was not run

No live service, remote agent, OAuth token, HTTP or SSE transport, or production credential was used. Sampling, elicitation, subscriptions, and logging were not part of the profile. The historical standalone validation probes and the old M7 network probe were not run.

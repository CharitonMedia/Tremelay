# ADR 0020: Human-unlocked local stdio MCP

Status: Accepted

## Context and acceptance

The modern in-memory reference in [ADR 0018](0018-local-mcp-capability.md)
does not launch as a client subprocess. Common deployed clients still use the
initialize lifecycle. A process also cannot read a human passphrase from MCP
stdin. Some clients start children without a controlling terminal or with only
the three standard descriptors inherited.

This slice must demonstrate an actual supported client launching Tremelay,
discovering its three tools, exercising one synthetic attestation, independently
verifying its public signature, and shutting down. Protocol-shaped test JSON
alone is insufficient. No remote service, socket listener, agent authentication,
raw-secret API, password cache, user-host installation, or signed release is added.

## Decision

### Host binding and custody

The trusted human configures `tremelay mcp serve` with one vault path, one exact
agent ID, and an absolute trusted pinentry executable. Those are process launch
settings, never tool arguments. The process obtains a passphrase through that
helper, unlocks once, wipes its passphrase buffer immediately after unlock,
uses logger-free unlock without a retained passphrase redactor copy,
binds `Session.Agent` then `BindAgentCapability`, and serves only that binding.
It owns the session exclusively until dispatch and output have stopped, then
locks it. The process does not issue or change grants. `clientInfo`, metadata,
handles and tool arguments cannot replace the agent or vault.

The helper and its terminal/display stack join the trusted custody boundary.
The executable is invoked directly, with no shell and no caller-provided command
arguments. Its standard input/output are private anonymous pipes, separate from
MCP. Only a small display/locale environment allowlist is inherited. The existing
`TREMELAY_PASSPHRASE` control-plane shortcut is never read by this command or
passed to the helper. Helper stderr is discarded, and helper/parser errors map
to fixed diagnostics. MCP stdout contains only protocol bytes.

The helper speaks the existing pinentry Assuan protocol. Commands are fixed
title/description/prompt setup, optionally a validated host-selected terminal,
`GETPIN`, and `BYE`. Decoded passphrases are capped at 1024 bytes, replies at
16 KiB and 64 lines, and each escaped line at 3076 bytes. Data is percent-decoded
into wipeable storage; arbitrary reply text is never logged or reflected.
`allow-external-password-cache`, `SETKEYINFO`, Emacs delegation, debug and
passphrase-quality inquiries are not enabled. There is no gpg-agent, keychain
credential provisioning, or saved/unattended unlock.

Unlock defaults to two minutes and is configurable only from one second through
five minutes. Cancellation, helper error, unavailable UI, or timeout fails
closed. The helper is terminated and reaped. A separately captured terminal
state is restored after helper exit, including when cancellation killed curses.
Startup watches pipe disconnect without consuming MCP bytes. Nonblocking poll
snapshots request input/output readiness filters but inspect only hangup/error
bits. Each nonterminal iteration, including EINTR, waits on a stoppable 50ms
timer so ordinary readiness cannot cause a busy loop. Joining the watcher
precedes descriptor closure. Explicit readiness registration is required by
[Darwin's poll implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_generic.c#L1656-L1670);
an empty event mask does not install its EOF-reporting filters. A synchronous KDF
already started is allowed to finish; cancellation then prevents service and
locks the session. No protocol requests are dispatched before human unlock and
agent binding.

### Explicit compatibility profile

`BindStdioMCPEndpoint` selects the initialize-based profile supporting exactly
`2025-06-18` and `2025-11-25` with the already-pinned official Go SDK v1.8.0.
The SDK creates the negotiated response. The old `BindMCPEndpoint` modern
`2026-07-28` reference remains separate and unchanged in its wire contract.
There is no untrusted request-time profile switch.

The stdio allowlist is `initialize`, `notifications/initialized`, `ping`,
`tools/list`, `tools/call`, and matching `notifications/cancelled`. Discovery
probes receive fixed method-not-found, allowing auto-negotiating clients to
fall back. Unsupported initialize revisions receive fixed unsupported-version
data listing only the two compatibility revisions. Ping is permitted before
initialization. Other calls require the initialization response and exactly one
initialized notification. Duplicate or premature notifications are audited and
dropped. An initialized notification racing the initialization writer's return
can be remembered once; credential work still cannot pass the outstanding
response's admission slot. An SDK-rejected handshake closes after its fixed
error, and cannot be revived with a reused correlation ID.

The original duplicate-aware scanner, 128 KiB frame limit, depth-eight and
32-key limits, integer-only numbers, array rejection, correlation-ID bounds,
strict canonical base64 and exact tool arguments remain. Initialization params
and advisory `_meta` objects are each at most 4 KiB. Client identity accepts
name/version plus optional title/description/websiteUrl, each a nonempty safe
string of at most 64 bytes. Client capabilities and extension metadata are
bounded objects; standard roots, sampling and elicitation declarations are
advisory. The server registers no callback which uses them. Trace/progress
metadata is neither logged nor reflected; progress tokens must fit the same
safe-ID rules. The three modern per-request identity/version/capability keys are
rejected in legacy `_meta`, preventing the SDK's stateless initialization bypass.
Arrays, fractional metadata and additional implementation identity shapes are
outside this narrow profile; a larger client feature set is not claimed.

Only the same three fixed tools are advertised. The exact-grant and secret-free
projection rules in ADR 0017 remain authoritative. HTTP/SSH grants are not
exposed, and `request_capability` does not sponsor or create authority.

### Audit, output, and process cleanup

The existing admission/audit/output machinery is shared, not bypassed with a
second SDK server. Required denial failures remain terminal; an audit failure
outranks routine cancellation. Allowed/completed attestation rows precede
signature release. Protocol denials remain sparse and attributed only to the
bound agent. Success or cancellation of a transport-only handshake/ping does
not create credential authority.

There is still only one admitted call and two retained output frames, including
an active blocked write. No credential work is admitted while an earlier
response is outstanding. The stdio reader may wait for the exact active response
write's completion with a 10ms deadline before rechecking ordinary admission.
The same wait includes an active fixed-error write only when no call is admitted
and no output is pending, covering discovery fallback and sequential rejection
recovery. An error concurrent with admitted work is never awaited.
This retains only its already-read frame, adds no goroutine or unbounded queue,
and fixes the write-return race observed with unmodified sequential Python MCP
calls. Held output still expires to busy; cancellation interrupts the wait. The
deadline is not a hard OS scheduling-latency promise. The modern reference
retains immediate-busy behavior. Deterministic virtual-time tests cover completed,
held, expired, and canceled handoff, while real clients run without retry.
A busy response is a correlated pre-dispatch denial;
a missing response, timeout, EOF, or cancellation is not evidence the operation
did not occur and must not trigger automatic replay.

The stdio logger discards SDK records rather than retaining even fixed-token
diagnostic history for the lifetime of a process. Responses and errors retain
the existing bounds and closed projections.

On Linux/macOS the command requires stdin/stdout pipes, duplicates them to owned
close-on-exec descriptors, enables nonblocking mode before constructing Go
files, and verifies deadline support. Closing those files interrupts blocked
reads/writes. SIGINT/SIGTERM cancel service, SIGPIPE is handled as an output
failure, and EOF closes the session. Terminal read failure closes owned pipes
independently of SDK Wait, so an admitted response blocked on full output cannot
retain the unlocked session after input disappears. A consumed partial frame is
audited first, and that audit failure outranks shutdown errors. `Serve` joins dispatch and its writer
before session lock. A full successful raw stdio write is not reclassified as
failed solely because close acquires the accounting mutex first. Closed state
still forbids admission; skipped, short, failed and pending writes retain their
errors, as do required audit failures. The modern profile retains its existing
post-close write classification. Other platforms fail closed for this command pending
runtime implementation; the other CLI commands remain buildable.

### Evidence and remaining limits

`TestStdioMCP*` uses the official Go SDK for both supported revisions and modern
auto-fallback, plus bounded rejection/audit/lifecycle regressions. CLI tests
exercise the actual helper/process/signal/pipe paths. The Linux smoke script
uses disposable vaults and fresh Ed25519 keys, official pinentry-curses, the
installed official Python MCP client and the real Codex app-server's direct
MCP API, without a model turn, login, user config, or real credentials.

The runtime evidence and exact client versions are recorded in
[the stdio guide](../local-stdio-mcp.md). Claude Code/Hermes configuration is
source-reviewed where those runtimes are absent, not claimed runtime-tested.
macOS compilation is not macOS terminal/display proof. A GUI pinentry requires
an available local display and is not validated by a curses-only test.
The host still controls the process, helper, vault and launch identity. This
does not confine a compromised host, enforce cross-process single-instance
ownership, recall an already released signature, complete M9/M10 production
authentication, or authorize production cutover.

## Primary references

- [Pinentry protocol and cache rules](https://raw.githubusercontent.com/gpg/pinentry/master/doc/pinentry.texi)
- [Codex 0.159.2 protocol modes](https://raw.githubusercontent.com/openai/codex/rust-v0.159.2/codex-rs/rmcp-client/src/protocol_mode.rs)
- [Claude Code MCP client runtimes](https://code.claude.com/docs/en/mcp#mcp-client-runtimes)
- [Hermes MCP transport negotiation](https://raw.githubusercontent.com/NousResearch/hermes-agent/main/tools/mcp_tool_transport.py)

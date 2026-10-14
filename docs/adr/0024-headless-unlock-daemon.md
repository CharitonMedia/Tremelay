# ADR 0024: Headless unlock daemon

Status: Accepted pending owner veto

## Context

ADR 0020 gives each agent an unlock of its own: the stdio MCP server asks a
trusted pinentry helper for the passphrase when the client launches it. That
suits a human sitting at the terminal and nobody else. The v1 target user runs
Claude Code, Hermes, Codex and bots unattended, where a per-launch prompt means
either no agent runs or the passphrase is parked somewhere an agent can read —
the worse of the two outcomes this project exists to prevent.

V1.md item 3 decides the shape: the human unlocks once in a terminal, and the
agents connect afterwards. This ADR records the trust boundary that decision
moves and the controls that bound it.

## Decision

`tremelay daemon --vault PATH [--idle-timeout DUR]` reads the passphrase
through the existing terminal reader, unlocks one `vault.Session`, and serves
the existing agent-principal MCP surface on a user-only local endpoint. Each
agent authenticates with its own bearer token and receives a principal derived
from that token alone.

## Trust boundary change

Before this ADR, the unlocked DEK existed only inside a process the human had
just launched and authenticated to, for the lifetime of one client's stdio
session. After it, an unlocked DEK sits in a resident process that accepts
connections from anything running as the vault owner's uid.

The accepted tradeoff, quoted from V1.md: *while unlocked, a compromised
machine can use agents' authority, but keys never leave the daemon.* The
boundary is now the uid, not the human's presence at a prompt. That is a real
widening, and the controls below exist to keep it at exactly the uid and not
one inch past it.

What does **not** change: no raw secret crosses the socket, no human
control-plane operation is reachable over it, every attempt is audited, and the
passphrase still never appears in argv, environment, configuration or protocol
input. Invariants 1, 3, 4, 5, 6A, 10 and 12 remain authoritative; THREAT_MODEL
sections on local-process adversaries and agent-controlled input apply
unchanged.

The threat this does not survive, stated plainly: code already executing as the
vault owner while the daemon is unlocked can exercise every granted capability.
It still cannot read a credential, change a grant, or learn the passphrase, and
every use it makes is in the audit chain under the agent token it used.

## Endpoint custody

The endpoint is the only thing standing between an unlocked DEK and the rest of
the machine, so it is checked rather than assumed.

- Unix socket under `$XDG_RUNTIME_DIR/tremelay`, or `tremelay-<uid>` in
  `os.TempDir()` when that variable is unset. The directory is created 0700 and
  then verified: owned by the daemon's uid, actually a directory, and no
  group/other permission bits. The socket itself is chmod 0600 after bind.
- Startup refuses when the directory or an existing socket path is owned by
  another uid, is not the expected file type, or carries wider permissions. A
  socket path that still answers a dial belongs to a live daemon and is refused
  rather than replaced; only a dead socket is unlinked.
- Every accepted connection is checked for peer uid equality before a single
  byte is read: `SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`xucred` on macOS. A
  peer that is not a Unix socket, or whose uid cannot be established, is
  refused. macOS `xucred` with an unexpected version is refused, because x/sys
  does not export `XUCRED_VERSION` and a silent reinterpretation of that struct
  is not an acceptable way to identify a caller.

Permission and ownership checks protect the path; the peer-uid check protects
the connection. Neither is sufficient alone, so both are enforced.

### Windows is deferred and fails closed

V1.md item 3 names a Windows named pipe. This slice does not ship one. On any
platform that is not Linux or macOS, `tremelay daemon`, `tremelay lock` and
`tremelay mcp --daemon` refuse to run with a fixed diagnostic; the ADR 0020
pinentry path remains available there.

This follows the precedent this repository already set: ADR 0020 shipped a
Unix-only stdio profile and ADR 0022 brought Windows custody separately, under
its own native-evidence requirements, because Windows handle and overlapped-I/O
behavior cannot be argued from the Unix implementation. A named pipe holding an
unlocked DEK needs an SDDL granting only the current user SID, correct
`ImpersonateNamedPipeClient` identity checks, and the interruptible-close
analysis ADR 0022 had to do. Shipping that untested, from a Linux host, into
the one process that holds the vault key is not a tradeoff worth taking for a
convenience feature. Per AGENTS.md rule 9 the conflict is documented here
instead of papered over: **the item 3 acceptance line is met on Linux and macOS
only, and Windows headless unlock remains open work.**

## Agent tokens

`tremelay agent create` mints 32 bytes from `crypto/rand`. The vault seals only
the SHA-256 of that token in the agent record; the raw bytes exist in process
memory until the command returns.

- `--token-file PATH` writes the token with `O_EXCL` at 0600 and prints the
  path. Without the flag the only copy is wiped before exit, so an agent
  created for pinentry use gains no daemon authority by accident. The token
  bytes are never printed to stdout or stderr on any path.
- `tremelay mcp --daemon --token-file FILE` refuses a token file that is not a
  regular file or that is readable by group or other.
- `Session.AuthenticateAgentToken` hashes the presented token and compares
  digests with `crypto/subtle`, returning one active `AgentPrincipal`. No
  caller-supplied identifier takes part: the principal is whatever the digest
  resolved to, or the call is refused. An agent record with no digest (created
  before this ADR) cannot authenticate; a digest that is not 32 bytes is
  corruption, not a usable credential.
- No new cryptography: `crypto/rand`, `crypto/sha256`, `crypto/subtle`. The
  token is a bearer secret protected by the same file permissions and uid
  boundary as the endpoint, not a new key hierarchy.

`tremelay agent token rotate` is **not** in this slice. Rotation needs its own
audit action, shape validation and tests, so it is not the trivial addition the
task allowed for. Today an operator revokes an agent and creates a new one,
which is already audited.

## What the socket exposes

Two verbs after a fixed `TREMELAY/1` hello, both length-bounded and
deadline-bounded: `AUTH <hex token>` and `LOCK`. `AUTH` leads to
`BindAgentCapability` → `BindStdioMCPEndpoint` → the existing
`MCPEndpoint.Serve`, which is the same three fixed tools (`list_capabilities`,
`describe_capability`, `invoke_capability`) the pinentry path serves. Over the
socket there is no human control-plane operation and no raw-secret retrieval
path (AGENTS.md rule 1). The daemon never offers credential material,
passphrase material, agent creation, grant changes, or audit export.

The handshake is read a byte at a time up to the delimiter, so that no MCP
payload is swallowed into a handshake buffer and no unbounded read precedes
authentication.

## Audit

A new `daemon_auth` action records every token authentication attempt at audit
version 2, under the existing `knownAction`/`validAuditShape` allowlists:

| Outcome | Result | Fields |
| --- | --- | --- |
| Accepted | `allowed` | `agent_id` |
| Known agent, not active | `denied_agent` | `agent_id` |
| Unknown token | `denied` | none |

An unknown token has no agent to attribute, so the row carries no identity, and
the shape validator rejects an `agent_id` on that outcome. The token never
appears in a row, a log line, or an error: a digest in the audit would be a
verifier for a guessed token. Credential and grant fields are rejected on this
action because authentication touches no credential.

## Locking

`Session.Lock` zeroises, and three things reach it: `tremelay lock` over the
socket, the idle timeout (1s–24h, default 1h, measured only while no connection
is live), and process loss, which includes reboot because the key was only ever
in memory. The daemon stops accepting, closes live connections, joins them, and
only then locks — the transport/dispatch-join-before-lock ordering ADR 0020 and
ADR 0022 require. After a lock, every client call fails closed with a generic
error.

The daemon also locks when its session becomes permanently unusable. A human
control-plane command run against the same vault advances the durable audit
sequence, which makes the daemon's cached session stale; a stale or
audit-failed session can never serve again, so the daemon prints a fixed
diagnostic, zeroises and exits rather than refusing calls indefinitely with no
explanation. **Operational consequence: change agents or grants while the
daemon is locked, or expect to restart it.**

## Concurrency

ADR 0018 states that the host must not use the session on another goroutine
while `Serve` runs. This slice deliberately does, because one daemon serves
several agents at once, and that deviation was reviewed rather than assumed:
every `Session` entry point serializes on `begin`/`end` around the session
mutex, and `duringCallback` is only ever invoked by the goroutine already
holding that mutex. Production configures no vault callbacks. The isolation
claim is tested with two simultaneous agent sessions on one unlocked session,
asserting that neither principal sees the other's grant, and the suite runs
under `-race`.

## Alternatives considered

- **Keep pinentry only.** Rejected by V1.md item 3: the target user's agents
  run unattended, and the practical outcome is a passphrase left somewhere an
  agent can read.
- **Cache the passphrase or the KEK on disk.** Rejected. It converts a
  machine-compromise window into permanent custody loss and breaks the
  property that losing the process locks the vault.
- **Put the agent id on the wire and trust it.** Rejected outright: a
  caller-supplied principal is not authentication. The token resolves the
  principal or the call is refused.
- **Store the token in the vault so it can be re-shown.** Rejected. A
  recoverable bearer token is a second raw secret with no capability check in
  front of it. Only the digest is sealed; a lost token means a new agent.
- **TCP on loopback with the token as the only control.** Rejected. A Unix
  socket gives the kernel's own peer identity and filesystem permissions,
  neither of which loopback offers.
- **One daemon connection per agent process, authenticated once at startup**
  (chosen) versus re-authenticating per MCP call. Per-call authentication would
  multiply `daemon_auth` rows without narrowing anything: the connection is
  already pinned to one principal for its lifetime.
- **Ship a Windows named pipe in this slice.** Rejected; see above.

## Tests and verification

In `internal/vault` (the authentication primitive): digest binding, an accepted
token resolving to the right principal, five refusal cases including a replayed
digest, a suspended agent denied as `denied_agent`, the exact `daemon_auth` row
sequence, a locked session refusing, token and passphrase absent from the
sealed file and from logs, a corrupt digest length rejected as `ErrCorrupt`, and
`VerifyAudit` still valid afterwards.

In `cmd/tremelay` (the daemon, over real sockets and the real CLI): unlock then
a capability call with no prompt; a wrong token refused and audited; two agents
served simultaneously with neither seeing the other's grant; `tremelay lock`
and idle-timeout expiry each making the next call fail closed; a grant revoked
through the human control plane making the daemon fail closed, zeroise and
exit; directory and socket mode/ownership/type refusals including a live
endpoint, a stale socket and a regular file; peer-uid acceptance for this uid
and refusal for another uid, an unknown identity and a non-Unix connection;
token-file mode, `O_EXCL` and malformed-content refusals; handshake bounds; and
the token absent from captured stdout and stderr. The suite runs under `-race`.

Tests are security controls (invariant 13); none of these may be weakened to
make CI pass.

## Consequences

- The item 3 acceptance line is demonstrable on Linux and macOS: an unlocked
  daemon serves capability calls with no prompt, `tremelay lock` and the idle
  timeout make the next call fail closed, and a wrong or inactive agent token
  is refused and audited.
- Pinentry (ADR 0020) stays supported and is the only option on Windows.
- A resident unlocked daemon is a new persistent asset for the M5 detection
  work to reason about. Repeated `daemon_auth` denials are ordinary expected
  denials today, not a detection class; that is marked in the code as a
  deliberate simplification with its upgrade path.
- Token files are a new on-disk secret class. They are 0600, their path is the
  thing that gets printed, and a file with wider permissions is refused on use.

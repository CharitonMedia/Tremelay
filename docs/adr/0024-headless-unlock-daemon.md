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

## Windows named pipe (amended 2026-10-13, V1.md item 3b)

The original slice deferred Windows and failed closed there. Patrick reversed
that: *"we need windows ... it is the largest pool."* `tremelay daemon`,
`tremelay lock` and `tremelay mcp --daemon` now serve the same handshake, the
same two verbs, the same token authentication, the same idle timeout and the
same dispatch-join-before-lock ordering on Windows, over a named pipe. Only the
listener, the dialer and the peer check differ; `daemon.go` is one core both
platforms share, as are the token-file read and write paths.

The endpoint is `\\.\pipe\tremelay-<user SID>`. The SID makes it per-user by
construction, and `TREMELAY_DAEMON_INSTANCE` appends one short label of
`[A-Za-z0-9_-]` for a second daemon or a test. Neither the SID nor the label
can widen anything: an unusable identity or an unsafe label yields no endpoint
at all, the server always creates the first instance itself, and the client
checks the owner before it sends a byte. That environment variable is the
Windows counterpart of `XDG_RUNTIME_DIR` on Unix and carries the same trust.

Custody is enforced four ways, none of them sufficient alone:

- **Owner-only descriptor.** The pipe is created with an explicit descriptor,
  `O:<SID>G:<SID>D:P(A;;GRGW;;;<SID>)`, built by Windows' own SDDL parser from
  the token user: this user owns it, one entry grants this user
  `GENERIC_READ|GENERIC_WRITE`, the DACL is protected so nothing is inherited,
  and Everyone, Authenticated Users, Administrators and SYSTEM appear nowhere.
  Only the same SID can match any of them. `GENERIC_WRITE` carries
  `FILE_CREATE_PIPE_INSTANCE`, which is what lets the owner — and nobody
  else — create the further instances the accept loop needs.
- **`FILE_FLAG_FIRST_PIPE_INSTANCE`.** A squatter who created the name first
  makes startup fail with the existing endpoint-in-use diagnostic rather than
  sharing a name with the process holding the unlocked DEK. The listener then
  holds one unconnected instance at all times, creating the replacement before
  handing over the connected one, so the name never becomes free while the
  daemon runs.
- **`PIPE_REJECT_REMOTE_CLIENTS`.** The pipe namespace is reachable over SMB;
  the pipe itself refuses a remote client. The boundary is this machine's user,
  not a name that happens to resolve.
- **Per-connection peer SID.** Before a single byte is read,
  `GetNamedPipeClientProcessId` plus `OpenProcessToken`/`GetTokenUser` must
  report the same SID as this process. `ImpersonateNamedPipeClient` is the
  race-free identity source but requires client data to have been read first,
  which this handshake will not do; the process-id path keeps the
  "identify before reading" ordering that the Unix `SO_PEERCRED` check has.
  The client holds the connection open across the check, and the descriptor
  already admits only this SID, so the process-id lookup is the independent
  second check rather than the only one.

Anti-squatting also runs in the client's direction: `mcp --daemon` and `lock`
read the owner SID of the pipe they opened and refuse to send the agent token
unless it is this user's. A name that resolved to somebody else's pipe gets no
token and no bytes.

`golang.org/x/sys/windows` carries every call used here, so it moves from an
indirect to a direct dependency and no new module is added. `go-winio` was
considered and rejected: it exists mainly for the overlapped transport Go now
provides, and a new dependency in the process that holds the vault key needs a
better reason than convenience.

The transport is ordinary overlapped I/O. Each instance is created with
`FILE_FLAG_OVERLAPPED` and wrapped by `os.NewFile`, which associates it with
the Go runtime's completion port; that is what makes handshake deadlines work
and makes `Close` interrupt a blocked read, which the daemon needs to join
every connection before it locks. `os.NewFile` falls back to synchronous I/O
when the association fails, so a connection that cannot carry a deadline is
refused when it is accepted rather than discovered mid-handshake.
`Accept` is the one operation Go's poller cannot carry: it uses an explicit
`OVERLAPPED` with its own event, and `Close` repeats `CancelIoEx` at 10ms
intervals until the accept actually ends before releasing the handle, because
a cancellation can reach the kernel before the operation it is meant to stop —
the same reservation discipline ADR 0022 established for the stdio transport.
The native handle is released only under the mutex cancellation also takes, so
no cancellation can reach a recycled handle.

Two shared behaviours had to change for a transport with no half-close. The
relay closes the whole connection when the client's stdin ends, instead of
`CloseWrite`, and does not treat the resulting read failure as an error.
Token-file custody moves from a mode check to a per-platform one: Windows
creates the file with the same owner-only descriptor (a file inheriting a
normal profile's permissions would also admit SYSTEM and Administrators) and
refuses to read a token file whose owner or DACL names anyone else.

### `tremelay ssh-agent` stays closed on Windows

`ssh-agent` is explicitly out of scope here and refuses to run on Windows with
a fixed diagnostic. It would need a listening endpoint and peer check of its
own, and the Windows OpenSSH agent its clients expect speaks a different
named-pipe convention; neither is argued by this slice's evidence. Agents reach
the Windows daemon with `mcp --daemon`. ADR 0026 is unchanged.

### What this slice does not establish

Windows CI exercises the daemon end to end on `windows-latest`. It does not
establish behavior with a real MCP client on a real Windows desktop; V1.md item
3b keeps that as separate evidence. The relay's own inherited stdin and stdout
are ordinary synchronous process pipes, as in ADR 0022; the relay holds only a
bearer token, no vault state. A process running as this user while the daemon
is unlocked can still use every granted capability, exactly as on Unix — the
boundary moved platform, not width.

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
- **Add `go-winio` for the Windows transport.** Rejected; `x/sys/windows` and
  `os.NewFile` cover it, and a new dependency inside the process holding the
  vault key needs a stronger reason.
- **Identify the Windows peer by `ImpersonateNamedPipeClient`.** Rejected as
  the primary check: it needs client data read first, which would break the
  identify-before-reading ordering the Unix check holds to.
- **A fixed pipe name with no per-user component.** Rejected: the name would
  be contended on a multi-user machine, and `FILE_FLAG_FIRST_PIPE_INSTANCE`
  would turn an ordinary second user into a denial of service.

## Tests and verification

In `internal/vault` (the authentication primitive): digest binding, an accepted
token resolving to the right principal, five refusal cases including a replayed
digest, a suspended agent denied as `denied_agent`, the exact `daemon_auth` row
sequence, a locked session refusing, token and passphrase absent from the
sealed file and from logs, a corrupt digest length rejected as `ErrCorrupt`, and
`VerifyAudit` still valid afterwards.

In `cmd/tremelay` (the daemon, over real endpoints and the real CLI): unlock then
a capability call with no prompt; a wrong token refused and audited; two agents
served simultaneously with neither seeing the other's grant; `tremelay lock`
and idle-timeout expiry each making the next call fail closed; a grant revoked
through the human control plane making the daemon fail closed, zeroise and
exit; directory and socket mode/ownership/type refusals including a live
endpoint, a stale socket and a regular file; peer-uid acceptance for this uid
and refusal for another uid, an unknown identity and a non-Unix connection;
token-file mode, `O_EXCL` and malformed-content refusals; handshake bounds; and
the token absent from captured stdout and stderr. The suite runs under `-race`.

Those daemon tests are one suite both platforms run. The endpoint-custody
tests are the half that cannot be shared. On Linux and macOS they are the
directory/socket mode, ownership, type and peer-uid cases above. On Windows,
run by the `windows-latest` jobs in `ci.yml` and `test-windows.yml`: the
descriptor the pipe is created with, read back entry by entry (this user owns
it, exactly one entry, `GENERIC_READ|GENERIC_WRITE`, this user's SID, and no
well-known principal named anywhere); a second daemon refused on a name the
first still holds, and that name reusable once released; instance labels that
are not plainly safe producing no endpoint, and an unformable endpoint
refusing before the passphrase is read; a token file widened to Everyone
refused; and `ssh-agent` failing closed. The end-to-end acceptance — unlock,
an agent capability call with no prompt, a wrong token refused and audited,
`lock` making the next call fail closed — is the shared test, running over a
real named pipe.

Tests are security controls (invariant 13); none of these may be weakened to
make CI pass.

## Consequences

- The item 3 acceptance line is demonstrable on Linux, macOS and Windows: an
  unlocked daemon serves capability calls with no prompt, `tremelay lock` and
  the idle timeout make the next call fail closed, and a wrong or inactive
  agent token is refused and audited.
- Pinentry (ADR 0020) stays supported on every platform, as the option it was.
- `tremelay ssh-agent` is the one daemon command Windows does not carry.
- A resident unlocked daemon is a new persistent asset for the M5 detection
  work to reason about. Repeated `daemon_auth` denials are ordinary expected
  denials today, not a detection class; that is marked in the code as a
  deliberate simplification with its upgrade path.
- Token files are a new on-disk secret class. They are 0600, their path is the
  thing that gets printed, and a file with wider permissions is refused on use.

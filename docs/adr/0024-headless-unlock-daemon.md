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
- The client (`tremelay mcp --daemon`, `tremelay ssh-agent`) makes the same
  peer-uid check on the daemon before sending its token, so a socket another
  user created first at the temp-dir fallback path never receives one.

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
refuses to read a token file whose owner or DACL names anyone else. A
descriptor passed to `CreateFile` is a request, not a result: a volume without
ACL support — FAT, exFAT, some network redirectors — accepts it and ignores
it, which would leave the token world-readable. So the creator reads the
descriptor back from the open handle through the same check the reader uses,
before any token byte is written, and deletes the still-empty file and names
the filesystem requirement rather than returning a file it cannot protect.

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
  resolved to, or the call is refused. An agent record with no digest cannot
  authenticate — that is an agent created before this ADR, or one whose token
  was revoked, and either can be given a token without being recreated (see
  the 2026-10-13 amendment). A digest that is not 32 bytes is corruption, not
  a usable credential.
- No new cryptography: `crypto/rand`, `crypto/sha256`, `crypto/subtle`. The
  token is a bearer secret protected by the same file permissions and uid
  boundary as the endpoint, not a new key hierarchy.

Token custody — issue, rotate and revoke — was not in the original slice and
is added by the 2026-10-13 amendment below.

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

The daemon also locks when its session becomes permanently unusable: a
document, chain or audit head it cannot verify with the key it holds. It prints
a fixed diagnostic, zeroises and exits rather than refusing calls indefinitely
with no explanation. A human control-plane command is no longer one of those
cases; see the 2026-10-13 amendment.

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
  front of it. Only the digest is sealed; a lost token means a new token for
  the same agent, which the 2026-10-13 amendment adds.
- **TCP on loopback with the token as the only control.** Rejected. A Unix
  socket gives the kernel's own peer identity and filesystem permissions,
  neither of which loopback offers.
- **One daemon connection per agent process, authenticated once at startup**
  (chosen) versus re-authenticating per MCP call. Presenting the token again
  on every call would multiply `daemon_auth` allowed rows and put the bearer
  secret back on the wire repeatedly. The connection is pinned to one
  principal for its lifetime, and the per-call generation check in the
  2026-10-13 token-custody amendment is what gives that pinning an expiry.
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
and idle-timeout expiry each making the next call fail closed; grants created
and revoked through the human control plane taking effect on the daemon's next
call; directory and socket mode/ownership/type refusals including a live
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
refused; the creator's own read-back of the descriptor it just set, accepting
the owner-only file it creates on NTFS and refusing a deliberately permissive
descriptor, which is the effective state an ACL-less volume leaves behind and
is reproducible without admin rights or a second volume; and `ssh-agent`
failing closed. The end-to-end acceptance — unlock,
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

## Amendment 2026-10-13: the daemon reloads instead of dying (V1.md item 3d)

Status stays Accepted pending owner veto.

The original slice turned every human control-plane commit into the end of the
daemon. That is a denial of service the operator inflicts on themselves by
using the product as documented, and the workaround the docs gave — lock the
daemon before touching grants — is the opposite of the "unlock once" property
item 3 exists to deliver.

An unlocked session now adopts the vault it is already holding the key to. At
every `Session` entry point, under the same mutex the dispatch discipline
above describes, the session compares the durable authenticated sequence and
the audit table's actual tip with its own. A locked-state denial suffix
therefore takes the same reload path: a valid suffix is incorporated before
the resident operation appends after it, while a forged suffix retires the
session. When the file has moved forward it re-reads the header and the whole
chain in one transaction and re-verifies them with `Unlock`'s own code — one
verifier, not a second one: `readVaultState` checks the header shape, the hash
chain and the locked-denial suffix, and `openDocument` authenticates the sealed
document under the plaintext audit head and checks the detection mirror, the
health mirror and the stored credential, agent and grant shapes. Only a
document that passes all of it is swapped in, and the swap happens with the
mutex held, so no in-flight call sees half of it.

What this changes for an operator: grants created while the daemon serves are
usable on the agent's next call, and revoked grants, suspended agents and
retired tokens are refused on the next call. Existing agent connections stay
up. Nothing re-prompts for the passphrase.

What it does not change: a reload that fails verification is fatal exactly as
before. A tampered document, a broken chain, a rolled-back audit head or a
vault id that is not this vault retires the session, and the daemon zeroises
and exits with the same fixed diagnostic. Rollback detection is the session's
memory of the tip it already served — an older authentic copy verifies on its
own terms, so only a live session can notice the substitution.

A sequence that merely moved forward does not establish a continuation, and
that distinction is the whole of the rollback defence. An attacker who can
write the file can restore an older authentic copy and then let the owner's
own later commands push it past the sequence this session served: every check
above passes, because the fork is this vault, just not this history, and the
revocations and retired tokens the session had already adopted would come
back. So the re-read chain must contain the tip itself — one event whose
sequence is the session's durable sequence and whose hash is the session's
audit head — and a chain that forks below it is refused as corruption, which
retires the session and locks the daemon.

Two security expectations changed shape and were reviewed against invariant 13
rather than quietly dropped:

- A session that loses a race no longer refuses every later call. The property
  that mattered was never the refusal, it was that no call is served from an
  unverified view, and that is what the re-verification enforces. The tests
  that asserted the refusal now assert the verification: a withdrawn grant is
  refused on the grant's own merits and audited, an unchanged grant keeps
  working, and an unverifiable file still fails closed.
- A passphrase change committed by another holder is adopted like any other
  commit, so the session's later writes use the new wrap. The old passphrase
  stays dead: a rewrap presented with it is refused as unauthenticated, and
  `VerifyAudit` accepts only the new one.

A reload appends no audit row. The commit being adopted is already in the
chain, written by whoever made it, and re-reading a file with a key already
held is not a credential-backed operation (invariant 4 is about attempted
operations, and no capability is exercised here).

Concurrency ceiling, recorded rather than hidden: commits stay optimistic. A
writer compares and swaps on the audit sequence, and the comparison sits
outside the write transaction, so a human command racing a continuous stream
of agent calls can lose repeatedly and must be re-run. A lost race is now
reported as a stale session rather than as corruption, nothing of it is
written, and neither side locks. Measured, a human command is unaffected at a
working agent's call rate and loses outright against roughly a hundred agent
calls per second. The upgrade path is in the code next to the check: take the
write transaction first and re-run the caller's mutation against the state
read inside it, which requires every mutating method to be a redoable closure.
The loss could also be `ErrIO` rather than a stale session when SQLite's busy
wait starved a writer past the 5 s `busy_timeout` (seen on slow disks and
Windows CI). V1 item 3f (ADR 0003 amendment 2026-10-14) addresses that for
daemon-scale concurrency: process-wide write serialization plus bounded retry on
`SQLITE_BUSY` at transaction boundaries. Stale-session races from optimistic
compare-and-swap outside the write transaction remain; cross-process writers
still depend on busy timeout and the bounded retry rather than a cluster-wide
queue.

## Amendment 2026-10-13: agent token custody (V1.md item 3c)

Status stays Accepted pending owner veto.

The original slice left one way to change a token: delete the agent and make
another. That takes the agent's id and all of its grants with it, so the
operator has to reissue every grant and edit the client's MCP configuration,
and an agent created before this ADR could not reach the daemon at all. The
practical result is that nobody rotates, which is the opposite of what a
bearer token needs.

Three commands now manage the token and nothing else:

| Command | Precondition | Effect |
| --- | --- | --- |
| `tremelay agent token issue --path P --agent ID --token-file F` | the agent holds no token and `F` does not exist | mints one, writes `F` |
| `tremelay agent token rotate --path P --agent ID --token-file F` | the agent holds a token | replaces it, rewrites `F` in place |
| `tremelay agent token revoke --path P --agent ID` | the agent holds a token | clears the digest, writes no file |

The agent's id, label, state and every grant survive all three, so a client's
configuration never changes and no grant is reissued. `issue` refuses an agent
that already holds a token rather than silently retiring a working client, and
`rotate` refuses one that holds none; each refusal names the other command.

The replaced token stops authenticating immediately, including in a daemon
that is already serving, because that daemon re-reads the vault (see the
amendment above). The two halves of V1.md item 3 are one feature: rotation
without the reload would still mean a restart.

Immediately means on the next call, not on the next connection. A daemon
connection authenticates once by design (see the alternative considered
below), so refusing the handshake is not enough on its own: the authenticated
principal is bound to the pair (agent id, token generation), and every later
call it makes — list, describe, invoke, broker, attest, and an SSH
conversation at its entry point — re-checks that pair against the state the
reload brought in. A digest that is gone, a generation that has moved, or an
agent record that is no longer there refuses the call with the session's
fixed unauthenticated error, releases nothing, and appends one `daemon_auth`
row under the shapes the table above already allows: `denied_agent` with the
agent id when the record is still there, `denied` with no attribution when it
is not. The generation is not in the row, and neither is anything else
derived from the token.

`agentRecord` gains `token_gen`, the count of tokens this agent has held.
Issue and rotate raise it; revoke clears the digest and keeps the count, so a
token minted after a revocation is never the generation of the one it
replaced and a record cannot be rolled back to an earlier custody period
without that being visible in the sealed document. A record sealed before the
field existed reads as generation 1 while it holds a digest. Authentication
is unchanged: the digest resolves the principal or the call is refused.

Three new audit actions, `agent_token_issue`, `agent_token_rotate` and
`agent_token_revoke`, at audit version 2 under the existing
`knownAction`/`capabilityAction`/`validAuditShape` allowlists:

| Outcome | Result | Fields |
| --- | --- | --- |
| Minted or cleared | `allowed` | `agent_id` |
| Refused, agent identified | `denied_agent` | `agent_id` |
| Unknown or malformed agent id | `denied` | none |

A row carries no credential, grant or operation, and nothing derived from the
token: not the material, not its digest, not its length, and not the
generation. The shape validator rejects each of those, and rejects an
`agent_id` on the unattributed outcome. A digest in the chain would be an
offline verifier for a guessed token, and the generation would narrow a
guess at which file is current.

File custody: the vault commits before the file is written, so there is never
a token on disk that the vault has already stopped accepting. The other
direction is the recoverable one — a commit whose file write then fails
leaves the operator rotating again — and it is the only ordering available,
because the commit is what mints the token.

A rotation creates its temporary file in the target's own directory, under a
random name, through the same platform owner-only creator `agent create`
uses: `O_EXCL` at 0600 on Unix, `CREATE_NEW` with the owner-only descriptor
on Windows. It is flushed, closed, and renamed over the target, which
replaces it atomically on both platforms (`rename(2)`, and `MoveFileEx` with
`MOVEFILE_REPLACE_EXISTING`), so a reader gets the whole old token or the
whole new one and the temporary file is never wider than the file it becomes.
`os.CreateTemp` plus `Chmod` is not that creator and was the original
mistake: 0600 is a Unix mode, and on Windows the file keeps the directory's
inherited ACL, which the token-file read then refuses — with the vault
already committed, which left the agent with no usable token and no command
that would fix it. The directory entry itself is not fsynced; the failure
that leaves behind is recoverable the same way, and that ceiling is marked in
the code.

`rotate` is the only verb that replaces a file. `issue` refuses an existing
path exactly as `agent create` does, because that path may be another agent's
live token file and overwriting it would retire a working client; a file a
revoked token left behind is removed by the operator before reissuing to the
same path, which is the path a client is configured with either way. A
`rotate --token-file` path that exists and is not already a readable token
file is refused before the vault commits, so a mistyped argument cannot
overwrite an unrelated file.

Tests: in `internal/vault`, custody end to end on an agent with no digest
(issue, authenticate, rotate, old token refused, revoke, reissue) with grants
unchanged throughout and generations strictly increasing; every refusal with
its exact audit row; the shapes the validator must reject; the stored
generation surviving a seal and unlock; a principal that authenticated before
a rotation and before a revocation refused on list, describe, invoke,
capability listing and its SSH entry point, each refusal audited and carrying
no token material, with the replacement token serving the same grant; and no
token, digest or passphrase in the file or the logs. The forked chain above
has its own test: a session adopts a revocation, an older copy of the file is
restored and pushed past that tip by ordinary unlocks, and the session is
retired rather than serving a view in which the revoked grant is active.

In `cmd/tremelay`, the same custody over the real CLI on every platform, and
over a live daemon on Unix: a superseded token refused at the handshake and
audited as an unattributed `daemon_auth` denial, connections opened before a
rotation and before a revocation refused on their next listing and their next
invocation with each refusal audited and attributed, a rotated token file
still owner-only with no temporary file left beside it, `issue` refusing to
overwrite another agent's token file without committing, and the daemon
locking on a forked chain. These are security controls under invariant 13.

## Amendment 2026-10-14: DEK rotation handoff for resident reload (V1.md item 3e)

Status stays Accepted pending owner veto.

Passphrase change now rotates the vault DEK in one transaction (ADR 0019,
amendment of 2026-10-14). A running daemon must adopt that rotation through
the reload path without re-prompting, but the handoff must not be readable
with an old backup and passphrase: sealing the new DEK under the previous DEK
would let anyone who derived the old DEK from a snapshot read the handoff
while it remains on disk.

On unlock, before serving connections, the daemon generates an ephemeral
X25519 key pair (`golang.org/x/crypto/nacl/box`), seals the public key into
the encrypted credential document on an audited `daemon_reload_pubkey /
allowed` commit, and keeps the private key in memory until lock or exit. The
legacy `dek_reload_pubkey` SQLite column may remain for migration but is
cleared on write and is never trusted for handoff. When another holder runs
`change-passphrase` and the authenticated document carries a reload public
key, the change commit may store `dek_handoff` as: inner AES-256-GCM of the
new DEK under the **session's previous DEK** with AAD binding the vault id
and that commit's audit head and sequence; outer anonymous box to the reload
public key over `inner nonce||inner ciphertext`. If no reload key is in the
document, no handoff is written. Reload adoption opens the outer box with the
in-memory private key, opens the inner with the resident DEK and binding,
swaps in the new DEK, and runs the same `openDocument` verification as any
other reload; failure retires the session and the daemon locks. This stops
(1) a same-uid agent planting a reload public key in plaintext and steering
the handoff to its own key, and (2) a same-uid writer forging a handoff with
`SealAnonymous` alone using an attacker-chosen DEK without the old DEK.
Ordinary commits clear the handoff; if it is cleared before reload, the
resident session fails closed, which is acceptable.

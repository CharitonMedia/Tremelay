# ADR 0026: SSH agent socket for agents

Status: Accepted pending owner veto

## Context

[ADR 0013](0013-ssh-userauth.md) signs one host-bound SSH userauth request
with a vault-held Ed25519 key, gated by an `ssh_userauth` grant that pins a
username and a server host key. It is a codec on an `io.ReadWriter`, with no
listener. [ADR 0023](0023-mcp-ssh-userauth.md) carried that codec over MCP,
which no SSH client speaks. [ADR 0024](0024-headless-unlock-daemon.md) put the
unlocked vault in one resident daemon behind a user-only Unix socket.

V1.md item 5 asks for the missing piece: an ssh-agent-protocol socket that
`ssh` and `git` can use through `SSH_AUTH_SOCK`, so that `git push` works and
revoking the grant stops it. Nothing here changes what may be signed; it
changes who can ask, over what transport.

## Decision

`tremelay ssh-agent --token-file FILE [--socket PATH]` publishes an
ssh-agent-protocol Unix socket. It holds no vault state. For each accepted
client connection it opens its own connection to the running daemon,
authenticates with that agent's bearer token, and copies protocol bytes it
never inspects.

The daemon handshake gains one verb beside `AUTH` and `LOCK`:
`SSHAGENT <hex token>`. It resolves a principal exactly as `AUTH` does, through
`Session.AuthenticateAgentToken` and the same `daemon_auth` audit row, and then
answers SSH agent frames for that principal's own grants. The vault, the DEK,
the grants and the private key stay inside the daemon, as they do for MCP. No
second vault-holding process is introduced.

`AgentPrincipal.SSHAgent()` is the one new agent-facing method. It enumerates
that principal's active `ssh_userauth` grants and owns one existing ADR 0013
stream per grant:

- `SSH_AGENTC_REQUEST_IDENTITIES` is asked of every stream and the answers are
  merged, so the list is exactly the public keys of the grants that currently
  pass their own checks. Duplicate keys appear once.
- `session-bind@openssh.com` is offered to every stream, because each grant
  pins its own host key and needs its own proof. A stream whose pinned key did
  not sign the session identifier stays unbound.
- Everything else, `SSH_AGENTC_SIGN_REQUEST` included, stops at the first
  stream that answers with something other than a failure byte. One request
  therefore releases at most one signature, and every grant that refused
  recorded its own denial.

The multiplexer adds no authority. Grant shape, expiry, revocation, credential
generation, the host-key binding requirement, the host-bound preimage rules,
the release checks and every audit row remain ADR 0013's, unchanged. A frame
cannot choose the principal, a grant, a credential, the clock, or a host key.

### What is served and what is refused

The served subset is ADR 0013's and is not widened: identities, the session
bind, and a signature over one `publickey-hostbound-v00@openssh.com` preimage
whose username matches the grant and whose session identifier and host key
match the verified binding. Ordinary `publickey`, any other preimage, add,
remove, lock, unlock, other extensions including `query`, and every other
opcode are refused from the opcode byte.

The ssh-agent protocol does not carry the host key, so a connection with no
verified `session-bind@openssh.com` has no destination to authorize against
and is refused before any signature: deny by default. OpenSSH 8.9 and later
send that binding immediately before fetching identities, which is why the
listing is empty until it arrives.

Each client connection gets a fresh conversation. A binding is never shared
between connections, and grants issued after a connection opened are not in
it.

### Endpoint custody

The socket reuses ADR 0024's rules, in the same implementation: a 0700
directory this uid owns with no group or other bits, a 0600 socket, a socket
path that still answers a dial treated as a live endpoint rather than
replaced, and a kernel peer-uid check on every connection before a byte is
read. The default path sits beside the daemon endpoint
(`$XDG_RUNTIME_DIR/tremelay/ssh-agent.sock`); `--socket` moves it, and its
parent directory must pass the same checks. Token files keep ADR 0024's
treatment: a regular file only this user can read, refused otherwise.

Linux and macOS only. Elsewhere, including on the Windows daemon ADR 0024
later added, this command fails closed with a fixed diagnostic of its own.

### No new dependency, and no `agent.ServeAgent`

`golang.org/x/crypto` v0.56.0 is already required, and nothing is added.
`golang.org/x/crypto/ssh/agent` appears in tests only, as the client peer.

The task that produced this ADR suggested using that package for server-side
protocol framing. It is not used that way, for the reason ADR 0013 already
recorded: `ServeAgent` logs parser errors with `log.Printf` and parses
key-insertion material before the `Agent` callback runs, so Tremelay's refusal
boundary would sit behind a parser and a log line it does not control. The
existing codec is both smaller here and strictly safer, and reusing it keeps
one implementation of the rules rather than two.

## Trust boundary

ADR 0024 moved the boundary from the human's presence at a prompt to the
owner's uid. This ADR does not move it again, and widens reach rather than
authority: anything running as the owner that can reach the socket can ask for
a signature, just as it can already drive MCP with the token file. What it can
obtain is still only an authentication signature for the pinned username on
the connection whose host key the grant pins, it still cannot read the private
key, change a grant, or learn the passphrase, and every attempt is in the
audit chain.

Two properties carry the weight, and both are enforced per grant by existing
code: the required host-key binding, which stops a caller from redirecting the
credential to another destination, and the exact username and preimage checks,
which stop it from authenticating as another account or signing arbitrary
data. A caller that relays bytes from a genuine session is outside what this
process can observe — ADR 0013's limits section still applies in full, and
this socket is a local transport for it, not a new guarantee.

A signature already released cannot be recalled, and an SSH session that
already authenticated is not closed by a later revocation.

## Interoperability ceiling, and a conflict with the requested test

This agent only works with servers that implement
`publickey-hostbound-v00@openssh.com`, which means OpenSSH 8.9 or later. A
server without it makes the client request an ordinary `publickey` signature,
which is refused, and authentication fails. That is a deliberate consequence
of ADR 0013's threat model, not a defect, but it does mean the socket cannot
be used with every hosted git provider.

Per AGENTS.md rule 9 the following conflict is recorded rather than resolved
in code: the acceptance test requested for this work was an in-process
`golang.org/x/crypto/ssh` server completing publickey authentication through
the socket. That library implements no host-bound userauth method on either
side, so such a server can only complete authentication if this agent signs an
ordinary `publickey` request, which ADR 0013 denies and which this slice will
not loosen. The acceptance evidence is therefore a real OpenSSH server, and
the in-process Go server is used for the adversarial case instead: it proves
that a real `ssh` client, pointed at a server that cannot speak the host-bound
method, is refused and obtains nothing.

## Audit

No new action and no new field. Signing attempts remain `ssh_userauth` rows
with the existing results, written by the existing stream. Each client
connection additionally produces one `daemon_auth` row for its token
authentication and one `cap_list` row for the grant enumeration that builds
the conversation. Usernames, host keys, session identifiers, preimages,
signatures, tokens and private keys stay out of rows, logs and errors.

## Alternatives considered

- **A second process holding the vault.** Rejected. It would double the number
  of places an unlocked DEK lives, for no capability the daemon cannot serve.
- **`agent.ServeAgent` with a restrictive `Agent` implementation.** Rejected,
  as in ADR 0013: the library parses and logs before the callback.
- **One socket per grant.** Rejected. SSH clients expect one agent, and the
  binding already selects the grant cryptographically; per-grant sockets would
  add paths and configuration without narrowing anything.
- **Disclose identities before a binding.** Rejected. It would hand every
  local caller the agent's key inventory with no destination proof, and ADR
  0013's listing rule exists for that reason. The operator installs the public
  key from the grant's `key_id`, which the control plane already prints.
- **Hold one daemon connection for the whole agent process.** Rejected. One
  connection per client keeps each SSH session's binding isolated and makes a
  fresh grant enumeration the default.
- **Let the relay cache or inspect frames.** Rejected. It holds a bearer token
  and nothing else; a parser there would be a second place to get the rules
  wrong.

## Consequences

- The operator installs the granted public key on the server. It is the hex
  `key_id` from `tremelay capability list`; [the guide](../ssh-agent.md) gives
  the one-line conversion to an `authorized_keys` entry. `ssh-add -L` lists
  nothing before a binding, by design.
- Changing grants while the daemon runs is served by the daemon re-reading the
  vault (ADR 0024, amendment of 2026-10-13). Revocation stops signing on the
  client's existing connection, which is the V1 item 5 acceptance behavior,
  and the daemon keeps running.
- Each SSH connection adds three audit rows beyond the signing rows. A busy
  repository produces a visible, but bounded, audit volume.
- `tremelay ssh-agent` is one process per agent token. Two agents need two
  sockets, hence `--socket`.

## Tests

In `internal/vault` (the conversation and its rules): the official
`ssh/agent` client over an in-memory transport lists nothing and signs nothing
before a binding; a binding by an unpinned host key is refused and leaves the
conversation unbound; after the pinned binding the one granted key is listed
and one signature verifies; another username, another host key, another
session, ordinary publickey and non-userauth data are each refused and
audited; add, remove, remove-all, lock, unlock and an unknown extension are
refused; a revoked grant stops the next signature and hides the identity; two
grants with different users, keys and hosts stay separate in both directions;
a principal with no SSH grant discloses and signs nothing; private key
material appears in neither the wire bytes, the logs, the vault file nor the
audit rows.

In `cmd/tremelay` (the socket, the relay and the daemon verb): the published
socket is 0600 and serves the bind, list and sign sequence end to end through
the daemon; a second connection does not inherit a binding; the token and the
passphrase appear in no output; exactly one signature is released and the
refusals are audited; revoking the grant stops the next signature; a live
endpoint, a group-readable directory, a world-readable token file and a
missing daemon are each refused. With real OpenSSH binaries present, `ssh`
authenticates to a real `sshd` through the socket and `git push` succeeds with
the key never leaving the vault; pointed at a server without the host-bound
method, the same client is refused and no signature is released. Those two are
skipped where the binaries are absent or an unprivileged `sshd` cannot start.
The suite runs under `-race`.

Tests are security controls (invariant 13); none of these may be weakened to
make CI pass.

## Amendment — 2026-10-14: hosted forges, and the recorded conflict resolved

V1.md item 5b (Patrick, 2026-10-13: "S1 yes") lifts the interoperability
ceiling above. [ADR 0013's amendment of the same date](0013-ssh-userauth.md)
adds one signed encoding: the ordinary `publickey` userauth preimage, released
only when its session identifier is byte-equal to that of a
`session-bind@openssh.com` the same connection already verified against that
grant's pinned host key, with `is_forwarding` false. Unbound plain requests, a
session identifier matching no verified bind, binds for another host key, binds
whose host-key signature does not verify, and forwarded binds stay refused and
audited.

Nothing in this ADR's own decision changes. The relay still parses nothing and
holds only a bearer token; the daemon verb, the per-connection conversation,
the per-grant streams, the merged identity listing, the broadcast bind, the
one-signature rule, the endpoint custody rules and the audit rows are all as
above. Each grant still pins its own host key and still needs its own proof on
each connection. The served subset grows by that one preimage and by nothing
else: add, remove, lock, unlock, other extensions and every other opcode are
refused from the opcode byte as before.

### What this changes in practice

`ssh` and `git` now work against servers that do not implement
`publickey-hostbound-v00@openssh.com`, which includes github.com and other
hosted forges. The requirement moves from the server to the client: OpenSSH
8.9 or later, because a client that sends no `session-bind@openssh.com` gets no
identity and no signature. The operator must pin the provider's host key from
its published fingerprints; [the guide](../ssh-agent.md) says so explicitly and
warns against trusting `ssh-keyscan` output without that comparison.

The trust boundary does not move. What a local caller as the owner can obtain
is still one authentication signature on a connection that provably reached the
grant's pinned host key, for the grant's username, with no access to the
private key, the grant or the passphrase, and with every attempt in the audit
chain.

### The conflict recorded above is resolved

The section "Interoperability ceiling, and a conflict with the requested test"
recorded, per AGENTS.md rule 9, that the requested acceptance test — an
in-process `golang.org/x/crypto/ssh` server completing publickey
authentication through the socket — could not be satisfied, because that
library implements no host-bound userauth method and ADR 0013 denied the plain
one. Item 5b resolves the conflict in the direction Patrick chose, so that test
now exists: `TestSSHAgentOpenSSHPlainPublickey` has a real `ssh` client
authenticate to such a server through this socket, with exactly one signature
released. Its adversarial twin, `TestSSHAgentOpenSSHUnpinnedHostKey`, points
the same client at the same kind of server presenting a host key the grant does
not pin, with the client's own `known_hosts` trusting it so the refusal has to
come from the agent: the binding is refused, no identity is disclosed,
authentication fails, no signature is released and the refusal is audited.
`TestSSHAgentOpenSSHGitPush` keeps the real-`sshd` host-bound evidence. The
in-vault conversation tests cover the same release and refusals through the
official agent client.

# ADR 0023: Bounded host-bound SSH authentication over local MCP

Status: Proposed; local source and synthetic acceptance only

## Decision and scope

Extend the same three tools from ADRs 0017, 0018, 0020 and 0021 to the existing
ADR 0013 SSH authentication-signing broker. No listener, remote SSH connection,
command runner, raw-secret API, generic signer, account, or crypto dependency is
added. This is a host-bound authentication-signing bridge, not a completed SSH
login or remote command workflow. Shared vaults remain attestation-only.

Security invariants 1–6, 11–13 govern this boundary. Relevant threats are secret
extraction, scope escalation, credential forwarding, replay, excessive use and
audit suppression. The trusted host still selects the principal, vault, clock
and helper. Client metadata and handles are not authentication. The host must
not use the Session concurrently outside its established callback contract;
independent endpoints do not enforce cross-endpoint or cross-process ownership.

SSH discovery accepts only single-user, sole-operation, canonical, exact
Ed25519 credential-ID grants. Each private handle pins the principal and exact
grant, operation, credential ID and generation, public key ID, resource,
username and canonical server host key. Rediscovery never retargets a handle.
Catalogue and describe disclose only handle, operation, resource, status and
expiry. In particular SSH omits key_id and public key until the broker verifies
host binding. Credential IDs, generations, usernames and host keys remain private
binding details. Status is advisory; every invocation checks current authority.

The constructor for the direct SSH adapter also pins the same authority and
credential generation. Identical-byte replacement intentionally retains the
existing generation under the vault lifecycle rules. A changed key followed by
restoring the original key is a new generation and does not revive a handle or
stream. Another matching grant cannot rescue a revoked or expired selection.

## Wire contract

The tool catalogue remains list_capabilities, describe_capability and
invoke_capability. SSH invoke accepts exactly a handle and payload: canonical
padded standard base64 of one unframed SSH-agent message body, 1–4096 bytes.
It does not accept the four-byte transport length prefix. The existing narrow
codec handles identities, session-bind@openssh.com and hostbound Ed25519
userauth. All other operations retain the existing fixed SSH denial behavior.
Ordinary publickey authentication, forwarding, rebinds and generic signing stay
denied. The host proof and preimage limits of ADR 0013 are unchanged.

A successful MCP tool result has exactly ssh_response, canonical padded base64
of the unframed SSH response. Capability TLV version 1 adds byte field 20 for this
closed result. The adapter independently validates the response: one fixed
success/failure byte; exactly zero or one canonical Ed25519 identity with empty
comment; or one canonical Ed25519 signature. There are no trailing bytes, and
the maximum decoded response is 88 bytes. A protocol failure byte is a handled
SSH attempt, not evidence of successful authentication.

## Stream ownership and cancellation

Each successful Serve owns a fresh private epoch. An epoch retains at most 64
lazy exact-handle slots, including retired tombstones. There is no eviction,
reset or automatic replay. One slot has at most one stream and one active call.
A stream is unbound, bound to one checked proof, or permanently retired for that
epoch. Independent endpoints never share an SSH stream. Sequential Serve starts
fresh, so identities remain hidden until a new binding even for an old handle.

Raw AgentCapability.Exchange has no transport-owned epoch. SSH invocation there
fails closed with a resolved SSH audit denial; it cannot create or borrow MCP
state. Its catalogue/describe remain advisory. No public adapter Close or
immortal raw stream map is introduced.

Admission resolves the SSH handle before dispatch so a matching cancellation
can retire it even before lazy creation. Only the exact admitted request ID can
retire its handle. Duplicate, malformed and unmatched cancellations follow the
existing sparse-denial rules and cannot retire another handle. Cancellation
also retires an invocation whose operation has finished but whose response is
still pending. A bind with an ambiguous response is never silently reusable.

Retirement marks a bounded tombstone immediately. An idle stream is detached
and wiped after the endpoint and epoch locks are released. An active stream is
owned by its handler until roundTrip returns; handler cleanup then detaches and
wipes it outside those locks. The read loop never waits for an active stream's
Close before forwarding cancellation. No worker is spawned per retirement.
Transport teardown stops epoch admission, closes idle streams, joins dispatch
and output, closes any remaining streams, and discards the epoch. No endpoint
or map lock is held over vault work, callbacks, stream Close, or transport I/O.

Cancellation can withhold a result but cannot undo a signature already approved
for release. The host proof can be replayed on a genuinely fresh stream; it is
not proof of server liveness or global single use. Missing output never grants
permission for automatic replay. Already-authenticated SSH sessions are outside
this bridge's control.

## Authority, audit and locking

The existing SSH broker now serializes initial judgment and denial/extension
audit calls with Session.begin/end. Internal Unlocked helpers avoid nested
locking in identity/sign paths. After unlocked callbacks it checks the live,
current session, exact grant scope, principal state, expiry, revocation,
credential lifecycle/generation and public key before signing and before release.
Private key bytes are reacquired only after the pre-sign check and are never
held across the signing callback. Stale/locked sessions and audit/storage
failures are fatal and withhold output.

Outer malformed shapes and unknown handles use sparse agent_capability rows.
Resolved SSH frames and retired/no-epoch SSH attempts use existing ssh_userauth
rows. A successful bind durably records allowed; signing records allowed before
Sign and completed before release. Revoked attempts retain existing replay
response controls. Audit failures dominate cancellation. No host key, username,
session identifier, preimage, signature, handle, or private-key bytes are added
to audit. The agent_capability describe allowlist adds ssh_userauth with Ed25519
metadata; hash encodings and formats are unchanged.

## Acceptance and evidence limits

The synthetic tests use disposable keys, private in-memory pipes and the official
Go MCP SDK. They verify both stdio revisions and the modern reference profile,
independently verify an Ed25519 hostbound signature, and cover pre-bind identity
hiding, wrong host/session/user/method/flags, exact authority changes between
requests, generation replacement, outer shape/isolation, raw Exchange denial,
closed response/state limits, exact cancellation retirement and sequential epochs.
Cancellation ownership is exercised without blocked output or custom callbacks.
Source review covers callback ordering and output-pending retirement; no bespoke
callback, persistence, audit-observer, or blocked-output probes are introduced.

Package compilation, vet and ordinary selected suites are reported separately
from whole-suite/native CI. A local passing subset is not a full/race or platform
acceptance claim. A separate [named-client SSH fixture](../named-client-ssh-tests.md)
now demonstrates actual Linux Codex, Claude Code and Hermes runtime integration
with synthetic host proof and vault-held keys. Shipping-CLI custody remains a
separate lane. Remote SSH login and production credentials are not demonstrated.

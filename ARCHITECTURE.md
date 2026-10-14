# Architecture

## Architectural rule

**The broker possesses secrets. Agents possess capabilities.**

## Initial logical components

### Control plane
Human-facing management plane for vaults, credentials, principals, policies, grants, credential health, lifecycle, alerts, and audit review.

### Secret store
Encrypted credential persistence behind a replaceable interface. The initial implementation should favor a simple local self-hosted backend. External backends can be added later.

### Identity
Humans, agents, services, and devices are distinct principal types. Agent identity must not be modeled as a human user with a different label.

### Capability service
Issues, validates, expires, and revokes narrowly scoped authority. Capabilities describe permitted operations; they do not grant generic secret-read authority.

### Policy engine
Makes explicit allow/deny decisions from principal, capability, credential, requested action, resource, context, and risk constraints.

### Credential broker
Performs authorized operations using protected credentials. Initial focus: HTTP/API requests.

### Audit subsystem
Creates append-oriented, tamper-evident records for every credential-backed operation attempt and security-relevant administrative change.

### Detection and notification
Classifies suspicious behavior, raises findings, notifies owners, and may invoke configured containment actions.

### Credential health/lifecycle
Evaluates password compromise/strength/reuse and machine-credential health, expiration, rotation schedules, and revocation state.

## Replaceable storage

The secret-store interface should permit future implementations such as local encrypted databases, OpenBao, Infisical, Bitwarden Secrets Manager, cloud KMS/secret services, and HSM/PKCS#11-backed stores.

The broker/capability model remains the product even when storage changes.

## Initial deployment shape

Early development may ship as one server binary plus a web UI and CLI. Logical boundaries should be represented by interfaces/packages so broker, audit, notification, or storage components can later be split into independent processes without redesigning the trust model.

## Initial data-store approach

M1 uses one local SQLite database as the transactional store for encrypted credential state and the audit chain ([ADR 0003](docs/adr/0003-custody-audit-hash-chain.md)). M2 stores agent principals and capability grants in that same encrypted document, so a grant change and its audit event commit together ([ADR 0004](docs/adr/0004-agent-capability-grants.md)). Agents are not human users, and a grant does not authorize raw-secret retrieval. M3 brokers one authorized `http_request` through that grant ([ADR 0005](docs/adr/0005-http-credential-broker.md)): the agent names the credential and the target, and the broker holds the secret. M4 checks that request against an explicit origin, method, path, and action policy and refuses destination confusion before the credential is sent ([ADR 0006](docs/adr/0006-http-request-policy.md)). M5 classifies those rows, verifies the chain from a human audit view, and can notify or contain from the class without putting a secret in the alert ([ADR 0007](docs/adr/0007-audit-detection-notification.md)). M6 stores credential health in that same document and appends version-4 health rows in the same transaction ([ADR 0010](docs/adr/0010-credential-health.md)). Health is advisory: it does not rotate, revoke, or enlarge a grant. M7 brokered one GitHub issue-state read on a separate `github_issue_state` grant; V1 item 4 removed that special case and replaced it with a prefix-scoped broker on a separate `http_broker` grant ([ADR 0025](docs/adr/0025-http-broker-v1.md), superseding [ADR 0011](docs/adr/0011-github-issue-state.md)). That grant names an origin, an allowed method set, a path prefix and one credential-injection style, and its response carries the status, an allowlisted set of response headers and a capped body with every spelling of the credential redacted. `BrokerHTTP` remains status-only. M8 signs one local artifact attestation with a vault-held Ed25519 key on a separate `local_artifact_attest` grant and returns a fixed signature plus public verification metadata ([ADR 0012](docs/adr/0012-local-ed25519-attestation.md)). The same milestone also serves a bounded SSH-agent subset on a separate `ssh_userauth` grant ([ADR 0013](docs/adr/0013-ssh-userauth.md)): one selected grant, one host-bound session, and one Ed25519 userauth signature. The private key stays in the vault. M9b copies that same file with the driver's online backup API and restores it only when the host supplies a matching checkpoint kept outside the artifact ([ADR 0016](docs/adr/0016-local-checkpoint-backup.md)). An old checkpoint is not detected as stale. M10a adds an in-process byte interface on an already-bound agent principal ([ADR 0017](docs/adr/0017-agent-capability-interface.md)). It discovers and invokes only that principal's `local_artifact_attest` grants by an exact handle. It is not a socket. M10b places that adapter behind one in-memory MCP peer for protocol `2026-07-28` ([ADR 0018](docs/adr/0018-local-mcp-capability.md)). That peer is not a network service, a distributed SDK, or remote authentication. M10 remains open. Multiple humans, organizations and approvals are out of v1; the M9a reference that explored them was removed and ADR 0015 is superseded. PostgreSQL support may follow for multi-user or clustered deployments.

## Cryptography

Use envelope encryption with authenticated encryption and mature libraries. Exact primitives and key-derivation choices require an ADR before implementation. The design must allow future external root protection through TPM, HSM, KMS, or OpenBao Transit-style services. Local artifact attestation and SSH userauth both use `crypto/ed25519` and the canonical PKCS#8 encoding from `crypto/x509`. Attestation bytes are specified in [ADR 0012](docs/adr/0012-local-ed25519-attestation.md). The SSH signature is the host-bound userauth preimage from [ADR 0013](docs/adr/0013-ssh-userauth.md), not the attestation domain.


## Local stdio process boundary

[ADR 0020](docs/adr/0020-local-stdio-mcp.md) adds a human-unlocked MCP subprocess
around the same bound capability adapter. A trusted host selects the vault,
agent and absolute pinentry executable; a private helper pipe obtains unlock
material without touching protocol stdin/stdout. The explicit initialize-based
profile supports `2025-06-18` and `2025-11-25`, while the modern reference remains
separate. Admission, exact-grant rechecks and fail-closed audit are shared.
A stdio-only 10ms response-write handoff deadline avoids spurious busy for normal
sequential clients without releasing admission early. Linux/macOS use owned,
close-interruptible inherited pipes or connected unnamed Unix stream pairs;
cleanup joins dispatch/output before locking the
session. No listener, callback, remote identity proof or new grant is added.
See [the client guide](docs/local-stdio-mcp.md) for measured runtime support.


## Exact network capabilities

[ADR 0021](docs/adr/0021-mcp-credential-brokers.md) extends the same capability
adapter and both MCP profiles to existing HTTP and GitHub issue brokers. Network
handles bind one agent, grant, operation, credential generation and canonical
resource. Invocation carries only the handle; the host-derived grant supplies
the request. Existing destination policy, fixed projections, audit and M5
response controls remain in force. SSH's
stateful host-proof contract is not represented by these one-shot invocations.

## Bounded SSH capability streams

[ADR 0023](docs/adr/0023-mcp-ssh-userauth.md) proposes carrying the existing
hostbound SSH authentication-signing broker through the same local MCP tools.
Exact private bindings include credential generation, username and host key;
public discovery omits SSH key identity. One private, bounded stream epoch belongs
to each Serve, with cancellation retirement and joined wiping. Raw Exchange cannot
borrow that state. This adds no listener, remote SSH connection or command runner.

## Headless unlock

[ADR 0024](docs/adr/0024-headless-unlock-daemon.md) adds `tremelay daemon`, the
one resident process that holds an unlocked session for unattended agents. The
human unlocks it once in a terminal; agents authenticate with per-agent bearer
tokens whose SHA-256 the vault seals, over a user-only local endpoint whose
peer is identified on every connection: a Unix socket with peer-uid enforcement
on Linux and macOS, an owner-only named pipe with a client-SID check on
Windows. It serves the same capability adapter and the same stdio MCP profile,
adds `daemon_auth` audit rows, and exposes no human operation and no raw
secret. The boundary becomes the owner's account rather than the owner's
presence at a prompt.

## SSH agent socket

[ADR 0026](docs/adr/0026-ssh-agent-socket.md) gives that daemon one more
handshake verb and `tremelay ssh-agent`, a relay that publishes an
ssh-agent-protocol socket under the same endpoint custody. The relay holds no
vault state. Inside the daemon, one conversation owns one ADR 0013 stream per
active `ssh_userauth` grant: identities are merged, a session binding is
offered to each grant that may pin a different host key, and any other message
stops at the first stream that does not refuse it. No grant check, preimage
rule, audit row or dependency changes, and ordinary `publickey` stays denied,
so the socket works only with servers that offer
`publickey-hostbound-v00@openssh.com`.

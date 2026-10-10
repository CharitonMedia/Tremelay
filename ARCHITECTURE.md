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

M1 uses one local SQLite database as the transactional store for encrypted credential state and the audit chain ([ADR 0003](docs/adr/0003-custody-audit-hash-chain.md)). M2 stores agent principals and capability grants in that same encrypted document, so a grant change and its audit event commit together ([ADR 0004](docs/adr/0004-agent-capability-grants.md)). Agents are not human users, and a grant does not authorize raw-secret retrieval. M3 brokers one authorized `http_request` through that grant ([ADR 0005](docs/adr/0005-http-credential-broker.md)): the agent names the credential and the target, and the broker holds the secret. M4 checks that request against an explicit origin, method, path, and action policy and refuses destination confusion before the credential is sent ([ADR 0006](docs/adr/0006-http-request-policy.md)). M5 classifies those rows, verifies the chain from a human audit view, and can notify or contain from the class without putting a secret in the alert ([ADR 0007](docs/adr/0007-audit-detection-notification.md)). M6 stores credential health in that same document and appends version-4 health rows in the same transaction ([ADR 0010](docs/adr/0010-credential-health.md)). Health is advisory: it does not rotate, revoke, or enlarge a grant. M7 brokers one GitHub issue-state read on a separate `github_issue_state` grant and returns four validated fields ([ADR 0011](docs/adr/0011-github-issue-state.md)). `BrokerHTTP` remains status-only. M8 signs one local artifact attestation with a vault-held Ed25519 key on a separate `local_artifact_attest` grant and returns a fixed signature plus public verification metadata ([ADR 0012](docs/adr/0012-local-ed25519-attestation.md)). The same milestone also serves a bounded SSH-agent subset on a separate `ssh_userauth` grant ([ADR 0013](docs/adr/0013-ssh-userauth.md)): one selected grant, one host-bound session, and one Ed25519 userauth signature. The private key stays in the vault. M9a adds one local shared-vault reference in that same document ([ADR 0015](docs/adr/0015-local-shared-vault-authorization.md)): a host-asserted member requests an exact local attestation, a different owner approves it, and the existing broker uses the resulting grant. It is not authentication, recovery, or production shared access. M9b copies that same file with the driver's online backup API and restores it only when the host supplies a matching checkpoint kept outside the artifact ([ADR 0016](docs/adr/0016-local-checkpoint-backup.md)). An old checkpoint is not detected as stale. M10a adds an in-process byte interface on an already-bound agent principal ([ADR 0017](docs/adr/0017-agent-capability-interface.md)). It discovers and invokes only that principal's `local_artifact_attest` grants by an exact handle. It is not a socket. M10b places that adapter behind one in-memory MCP peer for protocol `2026-07-28` ([ADR 0018](docs/adr/0018-local-mcp-capability.md)). That peer is not a network service, a distributed SDK, or remote authentication. M9 and M10 remain open. PostgreSQL support may follow for multi-user or clustered deployments.

## Cryptography

Use envelope encryption with authenticated encryption and mature libraries. Exact primitives and key-derivation choices require an ADR before implementation. The design must allow future external root protection through TPM, HSM, KMS, or OpenBao Transit-style services. Local artifact attestation and SSH userauth both use `crypto/ed25519` and the canonical PKCS#8 encoding from `crypto/x509`. Attestation bytes are specified in [ADR 0012](docs/adr/0012-local-ed25519-attestation.md). The SSH signature is the host-bound userauth preimage from [ADR 0013](docs/adr/0013-ssh-userauth.md), not the attestation domain.

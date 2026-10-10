# Tremelay Milestones

Milestones define outcomes and acceptance criteria, not detailed implementation prescriptions.

## M0 — Repository, specification, and executable skeleton

**Goal:** Establish the public project, security contract, contribution rules, and CI before substantive credential code exists.

Acceptance:
- vision, architecture, threat model, security invariants, contribution/security policies present
- minimal executable builds
- CI builds/tests on Linux, Windows, and macOS
- race/static/vulnerability checks established where applicable
- no production credential-handling code yet

## M1 — Encrypted single-user vault

**Goal:** A human can create/unlock a local vault and securely store/retrieve a credential through the human-authorized interface.

Acceptance includes authenticated encryption using mature libraries, ADR-documented unlock design, corruption/wrong-key tests, no plaintext persistence, redaction tests, and credential lifecycle metadata.

## M2 — Agent identity and capability grants

**Goal:** Create an agent principal and issue a revocable, expiring, scoped capability without granting raw-secret read access.

Acceptance includes distinct agent identity, grant creation/revocation/expiry, deny-by-default authorization, capability enumeration without secrets, and audit events.

## M3 — Generic HTTP credential broker

**Goal:** An agent can call a test HTTP service using a stored credential without receiving the credential.

Acceptance includes broker-only credential insertion, constrained destination, secret-free agent surfaces, success/denial audit events, working integration test, and adversarial extraction tests.

## M4 — Policy enforcement and network hardening

**Goal:** Limit credential-backed requests by service, host, method, resource/path, lifecycle, and context.

Acceptance includes redirect defense, SSRF/private-address defense, destination/origin validation, method/path/action policy tests, abuse-control hooks, and suspicious-denial classification.

## M5 — Audit, detection, and notification

**Goal:** Produce complete tamper-evident credential-use history and promptly surface risky behavior.

Acceptance includes every allowed/denied attempt logged, append-oriented integrity verification, no secrets in audit payloads, credential and agent audit views, risk classification, notification interfaces, full-record references in alerts, and optional containment hooks.

## M6 — Credential health and lifecycle

**Goal:** Evaluate credentials at entry/change and continuously track health and rotation state.

Acceptance includes password strength assessment, compromised-password checking without plaintext disclosure, internal reuse detection, credential health states, configurable rotation schedules/reminders, and health-change audit events.

## M7 — GitHub reference integration

**Goal:** Demonstrate a real-world capability model for GitHub without exposing the underlying credential.

The reference capability is a scoped issue-state read. An agent with an expiring `github_issue_state` grant for one repository issue receives the issue number, open or closed state, lock flag, and comment count. The broker inserts the credential. An `http_request` grant does not authorize that response. Acceptance is demonstrated by the synthetic tests in [ADR 0011](docs/adr/0011-github-issue-state.md) and [docs/m7-github-issue.md](docs/m7-github-issue.md). Live GitHub calls are not part of that demonstration.

## M8 — SSH/signing broker

**Goal:** Allow authorized signing operations while keeping private key material inside Tremelay.

The local slice is one Ed25519 attestation. An agent with an expiring `local_artifact_attest` grant for one credential and one resource receives a 64-byte signature and the public verification metadata for a bounded payload. The private key stays in the vault. A `sign`, `http_request`, or `github_issue_state` grant does not authorize it, including after the vault is reopened. Replacing the key bytes under the same credential id does not move the grant onto the new key. Revoking or expiring the grant stops later signatures and does not revoke a signature already returned. Acceptance is the synthetic test in [ADR 0012](docs/adr/0012-local-ed25519-attestation.md) and [docs/m8-local-attest.md](docs/m8-local-attest.md). That demonstration uses a disposable key and does not call a network.

The SSH slice is one host-bound user authentication signature. An already-bound principal with an expiring `ssh_userauth` grant can obtain an SSH Ed25519 signature through an in-memory agent stream. The signature covers one approved username, one grant-pinned server host key, and one session identifier whose host signature was checked. The private key stays in the vault. `sign`, `local_artifact_attest`, `http_request`, and `github_issue_state` do not authorize it, and it does not authorize them. The grant authorizes authentication to that account on that host-key identity. It does not enforce a remote command, path, repository, SFTP session, shell, or forwarding channel. Destinations that share the host key and username are not distinguished. A binding can be replayed on a new stream. Revocation stops later signatures and does not invalidate a signature already released or an SSH session already authenticated. Acceptance is the synthetic in-memory test in [ADR 0013](docs/adr/0013-ssh-userauth.md) and [docs/m8-ssh-userauth.md](docs/m8-ssh-userauth.md). It does not log in to a server, open a socket, or read live keys.

## M9 — Multi-user and shared vaults

**Goal:** Support organizations, ownership, shared vaults, recovery, role separation, and approvals without weakening earlier invariants.

M9 is not complete. M9a is the local shared-vault authorization reference in [ADR 0015](docs/adr/0015-local-shared-vault-authorization.md) and [docs/m9a-shared-vault.md](docs/m9a-shared-vault.md). A bound member requests one exact local attestation, a different bound owner approves the stored request, and the designated agent uses the grant through the existing broker. Revocation or membership removal stops later use. Real authentication, recovery, independent custody, and production shared access remain open.

## M10 — Agent SDK / MCP integration

**Goal:** Give agents a first-class interface to discover and invoke capabilities, never generic secret retrieval.

Representative operations: `list_capabilities`, `describe_capability`, `invoke_capability`, and `request_capability`.

## M11 — Hardened v1

**Goal:** Produce a documented, reproducible, security-reviewed v1 suitable for serious self-hosting, including threat-model review, dependency audit, SBOM, signed releases, backup/recovery documentation, migration tests, hardened defaults, and independent security review where practical.

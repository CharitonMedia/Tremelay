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

## M9 — Local backup

**Goal:** Let the single passphrase holder take and restore a consistent local snapshot without weakening earlier invariants.

Multiple humans, organizations, ownership roles and approval workflows are out of v1 ([V1.md](V1.md)); they stay on the community roadmap. The M9a authorization reference that explored them was removed, and ADR 0015 is superseded.

M9b is the remaining slice: a local checkpoint-bound snapshot of a single-user vault ([ADR 0016](docs/adr/0016-local-checkpoint-backup.md), [docs/m9b-local-backup.md](docs/m9b-local-backup.md)). The host supplies the existing unlock material and a checkpoint kept outside the artifact. An old backup paired with its own old checkpoint is not detected as stale. Lost-secret recovery, independent custody, freshness services, and cross-machine cutover remain open.

## M10 — Agent SDK / MCP integration

**Goal:** Give agents a first-class interface to discover and invoke capabilities, never generic secret retrieval.

Representative operations: `list_capabilities`, `describe_capability`, `invoke_capability`, and `request_capability`.

M10 is not complete. M10a is the in-process boundary in [ADR 0017](docs/adr/0017-agent-capability-interface.md) and [docs/m10a-agent-capability.md](docs/m10a-agent-capability.md). A trusted host binds one already-bound agent principal to a versioned byte interface. That interface lists, describes, and invokes only that principal's `local_artifact_attest` grants, each through a handle for one exact grant. `request_capability` is rejected and creates nothing. M10a is not a public SDK or a network listener. M10b is the accepted in-memory MCP peer for that same adapter ([ADR 0018](docs/adr/0018-local-mcp-capability.md), [docs/m10b-local-mcp.md](docs/m10b-local-mcp.md)). It uses the official MCP Go SDK v1.8.0 and protocol revision `2026-07-28`. It is not a network service, remote authentication, or a distributed SDK. [The local stdio slice](docs/local-stdio-mcp.md) adds a human-unlocked process,
a trusted pinentry helper, and an explicit initialize-based two-version profile
([ADR 0020](docs/adr/0020-local-stdio-mcp.md)). Actual supported-client subprocess
evidence covers synthetic local attestation. [The headless daemon](docs/headless-daemon.md)
adds the one-unlock-many-agents path for unattended clients: per-agent bearer
tokens whose SHA-256 the vault seals, a user-only Unix endpoint with peer-uid
enforcement, and `daemon_auth` audit rows ([ADR 0024](docs/adr/0024-headless-unlock-daemon.md)).
Agent authentication to the daemon is token-bound; Windows named-pipe custody,
broader transport support and production deployment assurance remain open.

## M11 — Hardened v1

**Goal:** Produce a documented, reproducible, security-reviewed v1 suitable for serious self-hosting, including threat-model review, dependency audit, SBOM, signed releases, backup/recovery documentation, migration tests, hardened defaults, and independent security review where practical.

M11 is not complete. M11a is one unsigned linux/amd64 build of the existing `tremelay` human CLI, with a validated CycloneDX SBOM, checksums, pinned build inputs, and dated govulncheck evidence ([docs/m11a-unsigned-linux-candidate.md](docs/m11a-unsigned-linux-candidate.md)). It is not a published release, a signed artifact, or a production-credential claim. Threat-model review, signed releases, and independent security review remain open. M10 remains incomplete.

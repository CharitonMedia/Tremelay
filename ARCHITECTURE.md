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

M1 uses one local SQLite database as the transactional store for encrypted credential state and the audit chain ([ADR 0003](docs/adr/0003-custody-audit-hash-chain.md)). M2 stores agent principals and capability grants in that same encrypted document, so a grant change and its audit event commit together ([ADR 0004](docs/adr/0004-agent-capability-grants.md)). Agents are not human users, and a grant does not authorize raw-secret retrieval. M3 brokers one authorized `http_request` through that grant ([ADR 0005](docs/adr/0005-http-credential-broker.md)): the agent names the credential and the target, and the broker holds the secret. M4 checks that request against an explicit origin, method, path, and action policy and refuses destination confusion before the credential is sent ([ADR 0006](docs/adr/0006-http-request-policy.md)). M5 classifies those rows, verifies the chain from a human audit view, and can notify or contain from the class without putting a secret in the alert ([ADR 0007](docs/adr/0007-audit-detection-notification.md)). M6 stores credential health in that same document and appends version-4 health rows in the same transaction ([ADR 0010](docs/adr/0010-credential-health.md)). Health is advisory: it does not rotate, revoke, or enlarge a grant. PostgreSQL support may follow for multi-user or clustered deployments.

## Cryptography

Use envelope encryption with authenticated encryption and mature libraries. Exact primitives and key-derivation choices require an ADR before implementation. The design must allow future external root protection through TPM, HSM, KMS, or OpenBao Transit-style services.

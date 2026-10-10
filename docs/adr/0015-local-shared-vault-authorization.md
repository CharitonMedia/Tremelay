# ADR 0015: Local shared-vault authorization reference

Status: Accepted

## Context

M9 calls for organizations, shared vaults, role separation, and approvals. This ADR records only the local reference slice, M9a. It is not authentication, independent custody, recovery, or production shared access. Those stay open under M9.

M1–M8 already store one encrypted document in one SQLite database and append a hash-chained audit row in the same transaction ([ADR 0003](0003-custody-audit-hash-chain.md)). Agents are not humans ([ADR 0004](0004-agent-capability-grants.md)). Local attestation pins a key identity ([ADR 0012](0012-local-ed25519-attestation.md)). Audit versions 1–4 and their preimages stay as published.

## Decision

### Trusted-host identity

One encrypted database holds one vault immutably bound to one organization. Organization identity, memberships, generations, roles, requests, grant provenance, labels, and resource text live in that document.

The host that holds the process and the vault passphrase supplies synthetic identity assertions and calls `BootstrapShared` and `BindHuman`. Those calls are not authentication. A bound `HumanPrincipal` cannot switch actor, recover `*Session`, call bootstrap or bind, unwrap the DEK, set the clock, or mint assertions. There is no `--human-id` flag. Agent records stay `kind=agent`.

Two synthetic records do not establish two real people and do not protect against that host.

### Roles and approval

Shared mode is the presence of a valid organization in the authenticated document. It is not a request flag. Opening a legacy vault does not invent an owner or a membership.

Roles are `owner` and `member`, deny by default.

- An owner attaches or removes members, assigns roles, manages credential inventory and agent registration through actor-attributed methods, inspects the audit, approves another person's request, and revokes grants.
- A member sees credential id and type, and agent id, creates a request, and inspects only their own requests and the resulting grant status.

Both may request. Only a different active owner may approve. The last active owner cannot be removed or demoted. Membership records a host-supplied identity. It does not create, authenticate, or impersonate that person. Members cannot approve, issue a grant directly, change roles, read another person's request, register identities, or configure callbacks.

Approval accepts only `local_artifact_attest` for one exact credential, one existing agent, one exact resource, the credential's current Ed25519 key identity, and a future expiry. Credential classes, wildcards, mixed operations, HTTP, and SSH are rejected in this flow. Existing attestation and verification are reused.

A request stores the requester and generation, organization and vault, exact grant scope, credential, key identity, and a deadline at most 24 hours ahead. `Approve` takes only the request id. It rechecks membership, owner authority, distinct identities, deadline, key, and the stored scope with the session clock. Callers cannot supply that clock.

The pending request is consumed, exactly one grant is created, and the approval row, grant row, and owner-notification decision commit in one transaction. A retry cannot create a second grant. Rejected, cancelled, expired, consumed, invalidated, malformed, and foreign requests create no authority. Those states survive reopen.

### Generations

Each membership has a generation. Removal, re-enrollment, demotion, and promotion increment it and invalidate that human's pending requests. A shared grant stores the requester generation and the approver generation from approval time. Later use requires the requester to still be active at that generation and the approver to still be an active owner at that generation. Re-enrollment and re-promotion do not revive the old grant. This is a conservative reference rule, not a production offboarding policy.

Legacy grants have no provenance. Shared mode rejects them at load and at use. Conversion of a vault that already contains grants is refused. Ordinary single-user grants are unchanged.

### Bypass prevention

In shared mode, unbound `Session` methods that issue grants, retrieve plaintext, mutate membership, or administer inventory are denied and audited. The bound human methods call the same validation and transaction path. `BootstrapShared` is the retained system operation: the passphrase holder, audited as the fixed actor `00000000000000000000000000000000`, and unreachable from `HumanPrincipal` and `AgentPrincipal`. Process-local notifier, containment, abuse, and compromise-checker installation stay on `Session` because they are host custody, not a human capability.

There is no shared-mode plaintext retrieval. Agents still have no raw-secret retrieval.

### Audit version 5

Shared actions use audit version 5. The preimage is the version-1 preimage plus length-prefixed actor, organization, target, request, decision, and grant id. Versions 1–4 are unchanged. A version 1–4 row that carries any of those new columns fails verification, including a locked-state denial suffix. Unknown caller strings are not written as actor, target, or request ids. Labels, resource text, keys, passphrases, secrets, payloads, signatures, and caller error strings stay out of plaintext audit, notifications, logs, and errors.

Successful approval also appends the existing version-3 `respond` / `notify` row with class `approval`. Delivery uses the in-memory notifier. There is no external recipient. Containment policy is not applied to that approval row.

### Atomicity

`commitBatch` is still the only encrypted-document writer. It seals the current organization, memberships, and requests unless the caller passes a replacement snapshot. A credential, health, grant, agent, or audit commit therefore cannot drop shared state. The snapshot and its audit rows commit in the existing SQLite transaction. A fault leaves both unapplied. A failed approval does not leave a grant. A failed required audit does not return a signature. The locked-state denial suffix contract is unchanged.

Load and verify check owner count, human/agent separation, organization/vault binding, generations, request status, and grant provenance. Authenticated ciphertext alone is not a valid state machine. Missing shared fields mean a legacy vault. Malformed or partial shared fields fail closed and are not read as legacy mode.

### Serialization and reentry

One session mutex serializes authorization, shared transitions, and release decisions. Overlapping calls on that session wait. Notifier, compromise-checker, abuse-guard, attestation-fault, SSH-fault, and broker transport callbacks run outside the mutex, then the session rechecks its state. A callback that commits causes `ErrConflict` on the in-flight evaluation, which is the existing health rule.

A second unlocked session is not covered by that mutex. Its update matches the durable `audit_seq`. A miss leaves the previous document in place, returns the existing corrupt-update error, and marks the stale session so later calls do not release authority from the cache. SQLite serialization alone is not treated as sufficient.

### Legacy compatibility

The file format version stays 1 so a new binary can still open a legacy vault. Shared documents add JSON fields. Previous readers use strict JSON decoding, so those fields fail closed instead of being ignored as single-user state. New readers do not treat a missing organization as shared mode, and they do not treat a present but malformed organization as a legacy vault.

### What this does not decide

Real authentication, SSO, enrollment, access provisioning, recovery, reset, independent key custody, plaintext sharing, production migration, external notification, live credentials, network serving, multi-vault transactions, clustering, PostgreSQL, generic RBAC, and M10 transport are out of scope. Authenticated shared access, recovery, and production offboarding policy remain open under M9.

## Alternatives considered

- **Role structs or an approval table that does not issue a grant.** Rejected. The reference has to be a grant the existing broker will use.
- **A `--human-id` flag.** Rejected. It would look like authentication.
- **Letting owners call `Get`.** Rejected. Shared mode has no plaintext retrieval path.
- **Extending audit versions 1–4 with actor columns.** Rejected. Those preimages are published. New columns on old rows would be unauthenticated.
- **A process-wide lock held across notifier and health callbacks.** Rejected. Those hooks reenter the vault. The lock is dropped for the callback and state is rechecked.
- **Bumping the vault format version for every file.** Rejected. That would make older binaries reject new single-user vaults. Only shared documents must fail closed on an older reader.
- **Inferring an owner when shared fields are absent.** Rejected. Legacy vaults stay single-user.

## Security implications

- Extraction: agents and bound humans still cannot retrieve a raw secret. Shared `Session.Get` is denied.
- Scope escalation: approval cannot substitute scope, and a grant dies when the requester or approver generation changes. Another organization's request id is not authority here.
- Replay: revocation, expiry, removal, and demotion stop later signatures. A signature already returned is not recalled.
- Audit tampering: version-5 fields are in the preimage. Old rows reject the new columns. Broken request/grant linkage fails load.
- Notification suppression: approval records a notify decision in the same transaction as the grant. A sink failure does not remove the grant.
- Host trust: the passphrase holder remains the custody authority. This reference does not defend against that host.

## Consequences

- Operators do not get a shared-mode CLI. The synthetic demonstration is in-process.
- M9 remains open for authentication, recovery, and production policy.
- Older binaries fail closed on a shared vault because strict document decoding rejects the new fields.

## Tests

`TestSharedSyntheticDemo` and the other `TestShared*` tests in `internal/vault/shared_test.go` cover the M9a acceptance list: approval and broker use, denials, isolation, single-use approval, generation invalidation, stale sessions, fault rollback, tamper and old-reader rejection, document writers, sentinel absence, and callback reentry under the race detector.

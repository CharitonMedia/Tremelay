# ADR 0004: Agent identity and capability grants

Status: Accepted

## Context

M2 requires a software-agent principal and narrowly scoped, revocable, expiring capability grants. [ADR 0001](0001-initial-product-boundary.md) makes a scoped capability the agent abstraction. [ADR 0002](0002-single-user-vault-key-hierarchy.md) makes the passphrase the human control plane and says the M1 CLI has no agent subcommand. [ADR 0003](0003-custody-audit-hash-chain.md) fixes the version-1 audit preimage and requires credential-state mutations to commit with their audit events.

M2 does not add an HTTP broker, OAuth refresh, SSH signing, or a raw-secret retrieval path. Authorization here is a decision. It does not perform the authorized operation.

## Decision

Agents are rows in the encrypted vault document, separate from credentials and from the human who holds the passphrase. An agent record stores a stable random id, a label, kind `agent`, and state `active`. Kind `human` or any other kind fails closed on load. The human is not represented as a row with a different label.

A grant stores the agent id, exactly one of a credential id or a credential class, an allowlisted operation set, an exact resource string, creation time, expiration time, and an optional revocation time. The operation allowlist is `http_request` and `sign`. Secret retrieval is not an operation. Resource match is exact string equality. `*` is rejected so a later matcher cannot treat a stored grant as a glob. A grant is active only when it is unrevoked and the evaluation time is strictly before expiration. Revocation wins when a full-scope grant is both revoked and expired.

The human session issues, revokes, and binds an `AgentPrincipal` to one id. That principal can list capabilities for its id and request an authorization decision. It does not hold `*Session`, and its method set has no credential retrieval, grant issuance, or principal switch. Listing or authorizing another id requires the human session to bind that id. A principal cannot enumerate another principal's grants.

Capability and grant metadata that an agent must see — ids, operations, resource, expiry, revocation — is returned by enumeration. Credential plaintext, credential labels, and agent labels are not. Resource strings are caller-controlled and may embed secret bytes, so they stay inside the encrypted document. They are not written to the audit chain, process logs, or error strings. Audit records the decision class instead.

Audit actions `agent_create`, `grant_create`, `grant_revoke`, `capability_authorize`, and `capability_list` use hash version 2. The version-1 preimage is unchanged. The version-2 preimage appends three length-prefixed fields to the version-1 preimage:

```
agent_id || grant_id || operation
```

`operation` is empty or a sorted comma-joined subset of the allowlist. Version-1 rows must keep those three columns empty; a value there is unauthenticated relative to the version-1 hash and fails verification. Authorization denials use fixed result codes: `denied_agent`, `denied_credential`, `denied_operation`, `denied_scope`, `denied_expired`, `denied_revoked`, and `denied_missing`. Malformed input uses `denied` and does not copy the caller string into the audit row.

Agent, grant, and credential state remain one encrypted document. `commitState` writes that document and the audit row in the existing SQLite transaction. Grant expiry and capability status use a clock on the unlocked session. Agent-facing authorize and list methods do not accept a time, so a compromised agent cannot present a historical timestamp and keep an expired grant allowed. Tests replace the session clock; production uses the process clock. Issuance and revocation stamp creation and revocation with the process clock.

The M1 statement that the CLI has no agent subcommand is superseded only for these human administrative commands. `agent get-secret`, `capability get-secret`, and any raw-secret agent command remain rejected. `credential get` is still the human retrieval path and still requires the passphrase.

## Alternatives considered

- **Plaintext grant tables.** Rejected. Free-form resource strings would sit unencrypted next to the hash chain, and a second write path would recreate the atomicity problem ADR 0003 closed.
- **Folding the new fields into the version-1 hash.** Rejected. That would change the M1 preimage and the published hash vector.
- **Encoding the resource string in the audit result.** Rejected. The resource is caller-controlled and is a secret-disclosure path if it is stored in plaintext.
- **Agent bearer tokens.** Deferred. M2 has no network agent transport. The host unlocks the vault and hands the agent an `AgentPrincipal`. A second secret for agent authentication belongs with the later agent interface, not with this grant model.
- **Wildcard or prefix scopes.** Rejected. M2 is exact match and deny by default.

## Security implications

- An agent principal cannot call `Get` or any raw-secret retrieval method. Adding one to `AgentPrincipal` is a failed test.
- Expiry is decided by the session clock. An agent principal cannot supply the evaluation time. A grant at or after its expiration is denied.
- Authorization fails closed when no active grant matches the agent, credential or class, operation, and resource. An unknown operation, including `get_secret`, is denied before grant matching and is not copied into the audit row.
- A grant mutation that fails its audit transaction leaves neither the grant nor the audit event durable.
- A document that rewrites an agent as a human, or a grant as a secret-read operation, fails unlock. The authenticated audit head does not advance.
- Version-1 audit rows cannot carry agent, grant, or operation values. Those columns are authenticated only by the version-2 preimage.
- Enumeration and errors return policy metadata and fixed denial codes. Tests use a sentinel secret to show it does not flow into the database file, audit columns, logs, errors, or capability JSON.

## Consequences

- M3 can treat an allowed `http_request` decision as the gate for brokering. This ADR does not perform that request.
- M10 can replace in-process principal binding with an authenticated agent transport without changing the grant fields.
- External audit checkpoints see decision codes and generated ids. They do not see resource strings; the vault owner reads those from the encrypted document.
- The CLI gains `agent`, `grant`, and `capability` commands. They require the vault passphrase.

## Tests

- Distinct agent ids persist across lock and unlock and are not human records.
- Grant create, revoke, expire, and authorize commit with audit events, and an induced commit failure rolls both back.
- Deny-by-default decisions cover the wrong agent, wrong credential, wrong class, wrong operation, wrong resource, expiry, revocation, and a missing grant.
- The agent principal's authorize and list methods take no time argument. Moving the session clock to the grant expiration denies the same request the process clock still allows.
- An active grant authorizes only its own operation, credential binding, and resource. Two active matches select the lowest grant id.
- An agent principal lists only its grants, and the list has no credential plaintext.
- A sentinel secret does not appear in the vault file, audit fields, logs, errors, or capability JSON. A secret-shaped scope on a denied authorize is not stored.
- Corrupt agent kind, secret-read grant operations, and a version-1 audit row with an agent id fail closed.
- Existing M1 vault tests remain green, including the version-1 hash vector.

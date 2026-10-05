# ADR 0003: Transactional SQLite audit and custody persistence

Status: Accepted

## Context

M1 requires encrypted local credential custody plus a tamper-evident audit history for every credential operation. The first implementation attempted to coordinate three related states across two independently bounded files: an encrypted vault document containing a sealed audit suffix, plaintext header fields binding the authenticated audit head, and a separate append-only `.audit` sidecar containing the full chain.

Three remediation cycles exposed repeated failure windows around sidecar append errors, suffix overlap, file-size ceilings, crash recovery, and reserving space for future unlock events. The implementation was converging on a custom two-file transactional protocol. That complexity is not justified for M1 security infrastructure.

## Decision

Use a single local SQLite database as Tremelay's M1 persistence boundary.

SQLite is the transactional storage engine, not the cryptographic trust boundary. Credential material remains encrypted with the existing envelope-encryption design from ADR 0002.

The database contains, conceptually:

- vault metadata and KDF parameters;
- wrapped DEK and encrypted credential document;
- authenticated audit head and sequence;
- an append-oriented audit table containing the full hash chain.

The audit chain keeps the existing SHA-256 version-1 preimage and event schema unless a later ADR changes it.

For any credential-state mutation, the encrypted-state update and corresponding audit row MUST commit in one SQLite transaction. Either both become durable or neither does.

A credential read that is required to be audited MUST append its allowed audit event transactionally before returning the secret. If the audit transaction fails, the secret is not returned.

Locked-state authentication denials are the one intentional asymmetry: the process does not possess the DEK after a rejected passphrase, so it may append a `vault_unlock / denied` audit row without updating encrypted credential state. On the next valid unlock, Tremelay MUST verify that every row after the authenticated audit head is a valid hash-linked locked-state denial suffix, then advance the authenticated audit head in the same transaction as the successful unlock event and updated encrypted state.

## Audit hash

Hash function: SHA-256 from the Go standard library.

The version-1 preimage remains:

```
H_n = SHA-256(
  H_{n-1} ||
  seq as uint64 big-endian ||
  length-prefixed time ||
  length-prefixed action ||
  length-prefixed vault_id ||
  length-prefixed credential_id ||
  length-prefixed credential_type ||
  length-prefixed result
)
```

`H_0` is 32 zero bytes. Sequence starts at 1. Records contain `prev`, `hash`, and `v = 1`. Audit records MUST NOT contain credential secrets, passphrases, decrypted payloads, authorization headers, or equivalent material.

## SQLite schema direction

The exact schema may evolve, but M1 needs at least:

```
vault
  id
  format_version
  kdf metadata
  wrapped_dek
  encrypted_document
  data_nonce
  audit_head
  audit_seq

audit
  seq
  time
  action
  vault_id
  credential_id
  credential_type
  result
  prev_hash
  hash
```

SQLite should use durable transactional settings appropriate for a local security store. Schema details and driver choice must use a mature, actively maintained implementation and must not weaken portability tests.

The driver is `modernc.org/sqlite`, a pure-Go SQLite build, so Linux, Windows, and macOS CI do not need cgo. `go.mod` pins the newest release that supports the repository Go toolchain. Each connection sets `busy_timeout`, `foreign_keys=ON`, `journal_mode=DELETE`, `synchronous=FULL`, and SQLite defensive mode. Credential-state writes use `BEGIN IMMEDIATE`. The toolchain is a current Go release whose `net/url` is outside GO-2026-4341, because opening a database reaches query-string parsing.

## Verification semantics

`tremelay audit verify` iterates the authoritative audit rows in sequence, validates the version-1 hash chain, and confirms that the authenticated vault head exists in the chain. Rows after that head are accepted only when they are valid locked-state denial events permitted by this ADR.

The audit tip remains suitable for later external checkpointing.

## Removed design

M1 no longer uses:

- a separate `VAULT_PATH.audit` sidecar;
- duplication of the audit chain or a suffix inside the encrypted document;
- sealed-prefix dropping;
- overlap reconciliation between sidecar and encrypted suffix;
- file-size reservation for one or two future unlock events;
- custom recovery for partial sidecar writes.

These mechanisms should be deleted rather than preserved as dormant compatibility code because M1 has not shipped a stable storage format.

## Security implications

- SQLite transactions provide the atomic durability boundary for credential-state mutations plus their audit events.
- SQLite does not replace encryption. Credential plaintext remains protected by the existing DEK/KEK design.
- The authenticated audit head remains bound into encrypted-state authentication so unauthorized history rewrites are detected on unlock.
- Locked-state denial suffixes remain distinguishable from authenticated state changes and are incorporated only after verification.
- M5 may add off-host checkpoints, SIEM export, signed checkpoints, retention, or archival without changing the M1 transaction invariant.

## Alternatives considered

- **Continue hardening the two-file protocol.** Rejected after three remediation cycles showed recurring consistency and capacity edge cases. This would amount to building a custom transactional storage layer.
- **Defer audit to M5.** Rejected because current security invariants require credential operations to be auditable now.
- **Store plaintext credentials in SQLite.** Rejected. SQLite is persistence, not secrecy.
- **Keep the sidecar only for audit while putting credentials in SQLite.** Rejected because it recreates the atomicity problem between authoritative credential state and audit state.

## Consequences

- M1 storage format changes before release; no migration compatibility is required yet.
- Existing M1 code for crypto, credential models, redaction, audit hashing, CLI behavior, and most tests should be retained where sensible.
- Dual-file synchronization and suffix-recovery code should be removed, reducing bespoke failure-handling logic.
- Future clustering or remote storage remains outside M1.

## Required tests

- credential mutation and audit event commit atomically;
- induced transaction failure leaves neither mutation nor allowed audit event durable;
- audited credential read does not return a secret when its audit transaction fails;
- wrong passphrase appends a secret-free denial event;
- valid unlock verifies and incorporates an outstanding denial suffix;
- forged or non-denial rows after the authenticated head fail unlock;
- hash-chain tampering fails verification;
- secret and passphrase bytes are absent from audit rows and ordinary error/log output;
- database corruption produces a safe failure;
- Windows and Linux CI remain green.

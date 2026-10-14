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

Locked-state authentication denials are the one intentional asymmetry: the process does not possess the DEK after a rejected passphrase, so it may append a `vault_unlock / denied` audit row without updating encrypted credential state. The denial sequence is allocated inside that write transaction so concurrent denials cannot reuse one sequence and drop an attempt. On the next valid unlock, Tremelay MUST verify that every row after the authenticated audit head is a canonical locked-state denial — `vault_unlock` / `denied` with empty credential id and credential type, and a timestamp in the UTC RFC3339Nano form event creation writes that is not before the previous event and not after the check — then advance the authenticated audit head in the same transaction as the successful unlock event and updated encrypted state.

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

The driver is `modernc.org/sqlite`, a pure-Go SQLite build, so Linux, Windows, and macOS CI do not need cgo. `go.mod` pins the newest release that supports the repository Go toolchain. Each connection sets `busy_timeout(5000)`, `foreign_keys(ON)`, `journal_mode(DELETE)`, and `synchronous(FULL)` through repeated `_pragma` query parameters, which is the syntax that driver applies when the connection opens. `_defensive=1` enables SQLite defensive mode. Opening the database reads those pragma values back from that connection and refuses the file when any required value is absent. Credential-state writes use `BEGIN IMMEDIATE` via `_txlock=immediate`. The toolchain is a current Go release whose `net/url` is outside GO-2026-4341, because opening a database reaches query-string parsing.

## Verification semantics

`tremelay audit verify` reads the vault passphrase the same way as other commands. It iterates the authoritative audit rows in sequence, validates the version-1 hash chain, and authenticates the encrypted document under the plaintext `audit_head` and `audit_seq`. Those columns are associated data on the credential ciphertext, so pointing them at a truncated chain fails authentication and verify does not report success. Rows after that head are accepted only when they are canonical locked-state denials: `vault_unlock` / `denied`, with empty credential id and credential type, and a timestamp in that same form that is not before the previous event and not after the check. Any other suffix fails verification and is not incorporated on unlock.

Verify does not append an audit event. The audit tip remains suitable for later external checkpointing.

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
- The authenticated audit head remains bound into encrypted-state authentication. Unlock and `audit verify` both reject a plaintext head that does not match that binding.
- Locked-state denial suffixes remain distinguishable from authenticated state changes. Only a canonical denial (empty credential fields and a chronological canonical timestamp) is incorporated, and only after verification.
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
- a hash-linked unlock denial that carries a credential id or type fails unlock and is not incorporated;
- a hash-linked unlock denial with a malformed, backdated, or future timestamp fails unlock and is not incorporated;
- concurrent denied unlocks each receive a distinct audit sequence and remain verifiable;
- rewriting the plaintext audit head onto a truncated chain fails verify;
- hash-chain tampering fails verification;
- a unique sentinel secret and passphrase are absent from audit rows and ordinary error/log output; equality with a fixed literal is not disclosure;
- database corruption produces a safe failure;
- Windows and Linux CI remain green.

## Read-only verification correction — 2026-10-12

`audit verify` opens SQLite with `mode=ro` and `query_only(ON)`, without a journal-mode setter, migration, or audit append, even when authentication or verification fails. For legacy audit tables it projects only the columns that the existing migration would add: empty strings and zero numeric defaults, and the existing action-derived version when `v` is absent. Present values and all chain, suffix, encrypted-document, detection, health, and shared-history checks are unchanged. Original M1 columns remain required. This preserves synthetic M1, M2–M4, and M5 schema compatibility without modifying the input.

The strict read-only backup-artifact reader remains strict. Ordinary `Unlock` keeps its migration and failed-authentication denial behavior; changing that ordering is outside this correction. `TestCLIAuditVerifyReadOnly` verifies unchanged file bytes and no new sidecars for success, wrong/invalid passphrases, and tampered rows. `TestVerifyAuditReadOnlyCompatibility` checks the write-disabled connection, legacy version projection, strict artifact reader, and ordinary unlock denial. These are synthetic compatibility fixtures, not historical-binary interoperability claims.

## Amendment 2026-10-14: fair SQLite writers (V1.md item 3f)

Status stays Accepted pending owner veto.

Concurrent holders of the same vault file (daemon plus control plane, or many goroutines each with its own connection) could starve one another past the 5 s `busy_timeout` because SQLite's busy wait is not fair. A writer that commits back to back could make another connection fail with `ErrIO` even though no credential state changed and neither side should lock.

Every mutating store path (`writeTx`, `appendDenial`, and audit migration) now runs under a process-wide write mutex so only one write transaction is prepared at a time in that process, still using `BEGIN IMMEDIATE` via `_txlock=immediate` so the reserved lock is taken at transaction start. When `BEGIN` or `COMMIT` returns `SQLITE_BUSY` after the connection's busy wait, the store retries the whole write with bounded exponential backoff; exhaustion still returns `ErrIO` and callers remain fail-closed. `readVaultSnapshot` (unlock and daemon reload) runs in the same queue: with `_txlock=immediate` its `BEGIN` takes the reserved lock exactly like a writer, so leaving it outside would let back-to-back writers starve it. The read-only `audit verify` connection does not take the mutex.

Required tests include concurrent denial and session-commit stress that assert no `ErrIO` from lock starvation, plus unit checks that audit faults are not retried and busy exhaustion maps to `ErrIO`.

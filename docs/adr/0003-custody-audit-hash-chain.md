# ADR 0003: Hash-chained audit log for human custody operations

Status: Accepted

## Context

Security invariants require every attempted credential operation to be auditable, audit records to exclude secrets, and the audit design to be append-oriented and tamper-evident, with a path to external checkpointing. The initial implementation should hash-chain events. The chain format itself needs an ADR.

M5 still owns detection, notification, review views, and containment. M1 only records human custody operations that this milestone actually performs: vault creation, unlock success and failure, credential store, credential retrieval, and credential list.

## Decision

Each vault has an append-only sidecar, `VAULT_PATH.audit`, of JSON lines. A copy of the same chain is stored inside the encrypted vault document. The authenticated tip of that chain is also stored in the plaintext header as `audit_head` and `audit_seq`, and those values are bound into the AES-256-GCM additional data of the credential document (ADR 0002). Changing the header tip makes an honest unlock fail authentication.

Hash function: SHA-256 from the Go standard library. No custom hash.

The version-1 preimage for event hash `H_n` is:

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

`H_0` is 32 zero bytes. Each length prefix is a uint32 big-endian byte count of the UTF-8 field that follows. `seq` starts at 1. `time` is `time.RFC3339Nano` in UTC. The stored record keeps `prev` and `hash` as hex, plus `v` = 1. The hash does not cover JSON punctuation, so encoding whitespace cannot change it.

Actions: `vault_create`, `vault_unlock`, `credential_put`, `credential_get`, `credential_list`. Results: `allowed` or `denied`. The first event must be `vault_create` / `allowed`. Records may contain the credential's stable id and type. They do not contain the secret, the passphrase, or the free-form label. A retrieval probe that is not a 32-character hex id is not copied into the log.

While the vault is locked, a failed unwrap appends `vault_unlock` / `denied` to the sidecar only. The next successful unlock accepts a sidecar suffix made only of those denial events, seals that suffix into the encrypted document, and advances the authenticated head. Any other sidecar divergence (broken hash, forged allow, mismatched prefix) fails the unlock closed. If the sidecar is missing, or is a strict prefix of the sealed chain, unlock restores the missing suffix from the encrypted copy. That restore is crash recovery, not a routine rewrite.

`tremelay audit verify` checks that the sidecar is a valid chain, that it contains the header's authenticated head, and that any newer suffix is only unlock denials. It prints the sidecar tip. That tip is the external checkpoint value. Offline verify does not have the passphrase, so an attacker who rewrites both the header tip and the sidecar can fool offline verify; unlock still fails GCM because the tip is inside the additional data.

Ceiling: denial events that are not yet sealed can be removed by someone who can edit the sidecar before the next successful unlock. Modification of sealed history cannot. The upgrade path is an off-host checkpoint of the tip printed by `audit verify`, which M5 can automate. Single-writer, same as the vault file.

A credential read that cannot append its audit event returns an error and does not return the secret.

## Alternatives considered

- **Defer all audit to M5.** Conflicts with the invariant that the operations introduced here are auditable and tamper-evident.
- **HMAC the chain with a key stored in the vault file.** A key sitting next to the log can forge events. The GCM-bound head is the authenticator we already have.
- **Hash the JSON line.** Fragile under encoding changes. The length-prefixed preimage is the canonical form.

## Security implications

- Audit files are mode `0600` on systems that honor it, same as the vault.
- Failed unlocks of a healthy vault produce a denial event. The event has no passphrase material.
- Sealed history is tamper-evident against an editor who does not know the passphrase.
- Unsealed denial suffixes are tamper-evident only against editors who cannot rewrite the sidecar. Operators who need that detection checkpoint the printed tip outside the host.
- Audit failure on an otherwise authorized read denies the secret.

## Consequences

- M5 may add event types only by extending this format under a new ADR. Version-1 preimages stay verifiable.
- The encrypted document grows with the chain. That is acceptable for a single-user vault; a later store can split the log without changing the preimage.
- `audit verify` is safe to run without the passphrase because the sidecar contains no secrets.

## Tests

- Known SHA-256 vector for the version-1 preimage.
- Bit flip in the sidecar fails verification.
- A forged allowed event after the sealed head fails unlock and does not return a secret.
- A locked-vault denial is present after the next successful unlock and is then covered by the sealed head.
- A missing sidecar is restored from the sealed chain.
- Secret and passphrase bytes are absent from the sidecar.

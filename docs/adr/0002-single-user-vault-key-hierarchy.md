# ADR 0002: Single-user vault unlock and key hierarchy

Status: Accepted

## Context

M1 requires a human to create and unlock a local vault and to store and retrieve a credential without persisting plaintext. [ARCHITECTURE.md](../../ARCHITECTURE.md) requires envelope encryption, authenticated encryption, mature libraries, and a design that can later move the root of trust to a TPM, HSM, KMS, or OpenBao Transit-style service. The exact primitive, KDF, key hierarchy, and unlock model must be recorded before the implementation is treated as complete.

M1 does not issue agent capabilities and does not expose a broker. Agent identity is M2. Network brokering is M3.

## Decision

The vault is a single SQLite database file. ADR 0003 defines that persistence boundary. The human unlock secret is a passphrase. Knowledge of that passphrase is the only authorization to create, unlock, list, store, or retrieve credentials in this milestone. The CLI is the human control plane. It is not an agent interface: there is no agent subcommand, no HTTP API, and no exported `GetSecret` operation.

Key hierarchy:

1. **Unlock secret.** The passphrase. It is never written to the vault, the audit log, or an error. Minimum length is 8 bytes. The CLI reads it from `TREMELAY_PASSPHRASE` or from a terminal prompt without echo (`golang.org/x/term` v0.34.0). It is not accepted as a command-line argument.
2. **Key-encryption key (KEK).** Argon2id (RFC 9106) via `golang.org/x/crypto/argon2` v0.41.0. Production parameters are the RFC 9106 second recommended set: 64 MiB memory, 3 iterations, parallelism 4, 16-byte random salt, 32-byte output. Parameters are stored with the vault so later defaults can change without stranding existing files. Untrusted files are rejected before the KDF runs if the parameters fall outside a fixed bound (memory 8 MiB–1 GiB, time 1–10, threads 1–8, key length 32).
3. **Master key (DEK).** A random 32-byte data key generated at vault creation from `crypto/rand`. The passphrase does not encrypt credential bytes directly.
4. **Wrapping.** AES-256-GCM from the Go standard library encrypts the DEK under the KEK. The associated data is the domain separator `tremelay/v1/dek` plus the vault id. A wrong passphrase and a tampered wrap both fail GCM authentication. They are not distinguished.
5. **Data encryption.** AES-256-GCM under the DEK encrypts one document containing every credential record. The audit chain is not copied into that document. Associated data binds the vault id and the authenticated audit head. Each seal uses a fresh random 12-byte nonce.

Credential records inside the document include a type from a fixed allowlist and lifecycle metadata: state, created time, updated time, and optional expiry, review, and rotation times. The secret itself exists in plaintext only in process memory after a successful unlock.

A future external root replaces the wrap and unwrap step. Per-credential ciphertext stays under the DEK. The file records `root: passphrase` so a later root can use a different identifier. No provider interface is introduced until a second root exists.

Nonce ceiling: random 96-bit GCM nonces are acceptable for a single-user vault. Before a vault approaches 2^32 seals under one DEK, the construction must move to a counter nonce or an XChaCha20-Poly1305 construction under a new ADR.

Go's garbage collector can retain copies of key and secret bytes. `Lock` zeroes the session's DEK, secret buffers, and redactor copies. That is best-effort, not a promise against host compromise. Host compromise that can read process memory is out of scope for this milestone, matching the threat model.

## Alternatives considered

- **scrypt or PBKDF2.** Available and reviewed, but Argon2id is the current password-hashing recommendation in RFC 9106.
- **bcrypt.** Not a general KDF for a 32-byte key, and it truncates long passphrases.
- **XChaCha20-Poly1305.** Stronger nonce margin, and available in `golang.org/x/crypto`, but it adds a second construction. Standard-library AES-256-GCM is enough at single-user volume if nonce handling stays as specified above.
- **age or a SQLCipher-style database.** Heavier dependency for the same envelope outcome. A JSON file keeps the encrypted document replaceable later by SQLite or another store without changing the hierarchy.
- **A stored passphrase verifier separate from the wrap.** Redundant. The GCM tag on the wrapped DEK is the verifier.

## Security implications

- Raw credentials are not written to the vault file. Tests compare file bytes with a unique secret and passphrase. A secret that merely equals a fixed literal (action name, result, credential type, KDF id, root label) is not treated as disclosure.
- Errors returned by the vault are fixed sentences. Callers redact log lines with the passphrase and any secret the session has seen.
- An attacker who can edit the file can deny availability. They cannot produce a document that decrypts under the honest DEK without breaking GCM.
- Parameters in the file are untrusted input. Bounds are enforced before Argon2id runs so a hostile file cannot request an unbounded allocation.
- The same-user threat of `TREMELAY_PASSPHRASE` in the process environment is accepted for non-interactive use. Interactive use prefers a no-echo terminal read. Agents are not given this environment by this milestone.
- No agent-facing raw-secret retrieval function is added. Retrieval requires the unlock passphrase and the human CLI (or the in-process session that CLI holds).

## Consequences

- Vault creation is intentionally slow (Argon2id, 64 MiB). Tests use the production parameters rather than a weaker test KDF.
- Passphrase change is rewrap-of-DEK work and is not implemented.
- The vault format version is 1. Readers reject any other version.
- Single-writer. SQLite serializes transactions. Concurrent processes are not an M1 workflow.
- Credential-state changes and their audit events commit in one SQLite transaction. A locked unlock denial is appended without the DEK and incorporated on the next valid unlock (ADR 0003).

## Tests

- Create, unlock, put, list, and get round-trip, including type and lifecycle fields.
- Wrong passphrase fails closed and does not reveal the passphrase.
- Tampered data ciphertext fails authentication and does not return a secret.
- Tampered DEK wrap fails authentication.
- Ciphertext from one vault does not decrypt under another vault's key.
- Hostile KDF memory parameters are rejected without running the KDF.
- A unique secret and passphrase do not appear in vault or audit bytes. Equality with a fixed non-secret literal is not disclosure.
- Log lines and error strings are redacted.
- No `GetSecret` method exists on the session.

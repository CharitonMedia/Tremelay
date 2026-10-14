# ADR 0019: Human passphrase change and checkpoint CLI

Status: Accepted

## Context and security contract

The human CLI can create a vault but cannot yet change its passphrase or invoke
the existing checkpoint-bound backup engine. These are host-custody operations,
not agent capabilities or shared-member permissions. They touch the human/store
and store/audit boundaries, secret extraction, audit tampering, and stale authority
in the threat model. Security invariants 1, 5, 6A, and 10 remain mandatory.

## Decision

### Passphrase change

`vault change-passphrase --path PATH` reads the old passphrase, new passphrase,
and confirmation from a terminal with echo disabled. It never consults the
passphrase environment or accepts passphrase flags, files, or piped input. The
old passphrase is authenticated through ordinary `Unlock` before a new value is
requested. An incorrect old value records the existing locked-unlock denial.
Missing terminal input before authentication makes no vault change. A cancelled
or mismatched replacement after authentication records a fixed change denial.
The command catches SIGINT/SIGTERM while prompting. It enters raw mode
synchronously, uses the existing x/term no-echo line reader (which recognizes
Ctrl-C), and restores the captured terminal state before returning a cancelled
read. A cancelled blocked reader cannot change terminal flags or vault state;
any late returned byte buffer is wiped, and main exits without waiting for input.
SIGKILL, power loss, and a failed OS terminal-restore operation cannot be made
clean cancellations; a restore error fails closed.

The host-only `Session.ChangePassphrase(old, new)` verifies both lengths (the
existing 8–1024 byte bound), rejects an unchanged value, and reauthenticates the
old value against the session wrap. It generates a fresh DEK, re-encrypts every
credential under it, and uses the existing Argon2id production parameters with a
fresh random salt and standard AES-256-GCM with a fresh nonce to wrap the new
DEK. No new recovery authority or cryptographic primitive is introduced. This
does not claim strength or known-compromise checking for the vault passphrase
beyond the existing length check.

The existing encrypted-document transaction writes the new KDF/wrap fields,
resealed document, authenticated audit head, and fixed version-1
`vault_passphrase_change / allowed` row together. The cached header changes only
after commit succeeds. Validation and old-passphrase failures record a secret-free
denial but preserve the original wrap. Transaction failure leaves the original
wrap and authoritative audit unchanged. The existing `audit_seq` compare-and-swap
applies to the wrap as well as the document, so an old session's ordinary write
or second rewrap cannot put the former passphrase back. The existing first-CAS-
miss error and subsequent `ErrStale` behavior are retained.

This operation is available on the trusted host's `Session`, including a shared
vault, and is not exposed on `AgentPrincipal`, `AgentCapability`, MCP, or
`HumanPrincipal`. Grants and membership are unchanged; credential plaintext is
preserved but re-sealed under the new DEK. An old snapshot plus
its original passphrase and wrapped DEK cannot decrypt the current vault.
Changing the passphrase cannot recall a DEK another process already discarded or
stop a compromised host. Copies and snapshots retain their original passphrase
and DEK. This is neither recovery nor a replacement for rotating exposed
credentials or keys.

### Backup and restore CLI

`vault backup --path SOURCE --output ARTIFACT` calls `Backup` directly and emits
only `Checkpoint.MarshalText` on stdout. The operator independently retains that
checkpoint, choosing the one they currently trust for restore. The CLI does not
call `Unlock`, append an audit event, or create an automatic sidecar manifest.
If writing stdout fails after the engine succeeds, it reports that the artifact
was created but checkpoint output failed. It does not claim the artifact vanished.

`vault restore --input ARTIFACT --path NEW_TARGET --checkpoint-file CHECKPOINT`
requires that explicitly supplied checkpoint. A bounded read and canonical parser
reject missing, oversized, or malformed input. There is no discovery of a sibling
manifest or checkpoint inferred from the artifact. Both commands use the existing
passphrase source: a no-echo terminal prompt or `TREMELAY_PASSPHRASE`. They add no
new environment variable or passphrase argument. Existing same-user environment
exposure from ADR 0002 is unchanged; interactive terminal input is preferred.

The engine's source/artifact read-only, no-overwrite, canonical-path and SQLite
sidecar-collision rules are unchanged. Restore returns exit 3 for `ErrPublished`
(the destination remains) and exit 4 for `ErrPublicationUncertain` (rollback
visibility is not known crash-durable). Messages require inspection and prohibit
blind retry. Success followed by failed stdout confirmation also returns exit 3,
explicitly saying the restored destination remains. No restore outcome triggers
an automatic retry, cutover, or additional unlock. These lifecycle commands
subscribe to SIGPIPE so a closed output pipe returns EPIPE to the fixed outcome
handler instead of killing the process before it can report retained state. See ADR 0016 for the publication
and Windows durability limits. Ordinary operational errors return 1; usage returns 2.

An old snapshot and its original checkpoint still match. The CLI cannot tell that
pair is stale. It does not recover lost passphrases, supply a freshness witness,
reset shared ownership, or enforce one active instance across processes/machines.

## Compatibility and alternatives

The vault format and audit hash preimage stay unchanged. The new fixed action is
added to the action allowlist. An older binary lacking that action fails audit
validation after a change, instead of ignoring the administrative event. Backup
artifacts made before the change remain compatible with their original passphrase.

A separate wrap write, a second recovery key, and printing/accepting replacement
passphrases through environment or argv were rejected. Reuse of the existing
transaction and cryptography is the smallest change satisfying atomic custody.

## Verification

`TestChangePassphrase*` covers DEK rotation, fresh salt/nonce, old/new authority,
credential retention, ordinary-write retention of the new wrap, original snapshot
passphrase, invalid/wrong input, transaction rollback, stale sessions, crash
recovery at each commit step, pre-change authority failing on post-change
ciphertext, resident-session reload with ephemeral reload keys, handoff
adversarial cases, and synthetic sentinel absence.
`TestCLIChangePassphrase*` covers prompt order, confirmation,
cancellation, buffer wiping, terminal-only entry and fixed argument errors.
`TestCLIBackup*` and `TestCLIRestore*` exercise CLI checkpoint and engine boundaries.
Existing backup fault tests continue covering publication/rollback failures.
The existing `TestCLIAuditVerifyReadOnly` and `TestVerifyAuditReadOnlyCompatibility`
remain required: this work does not restore a pre-authentication write to verify.

`TestLifecycleProcessCancellation` runs actual Linux PTY child processes for
Ctrl-C, SIGINT, and SIGTERM at all three prompts, checks full terminal-state
restoration, retained old authority and authenticated denial rows.
`TestLifecycleProcessBrokenStdout` closes an actual stdout pipe for all three
lifecycle commands and checks the committed-outcome warning and exit status.
These process/PTY tests are Linux-only; Windows/macOS terminal and signal
behavior has not been directly exercised. Shared state retention is source-
reviewed; the new rewrap fixtures are single-user.

## Amendment 2026-10-14: passphrase change rotates the DEK (V1.md item 3e)

Status stays Accepted pending owner veto.

`vault change-passphrase` now generates a fresh DEK and re-encrypts every
stored credential under it in one SQLite transaction with the new passphrase
wrap and the fixed `vault_passphrase_change / allowed` audit row. Crash or
injected failure before commit leaves the prior wrap, DEK, and ciphertext;
after commit the vault unlocks only with the new passphrase. A long-running daemon session publishes an ephemeral X25519 public key through
the audited commit path when it unlocks; the matching private key lives only
in that process until lock or exit. The reload public key is stored inside the
encrypted credential document (authenticated by the DEK), not in a trusted
plaintext column; a same-uid writer may still overwrite the legacy
`dek_reload_pubkey` column, but `change-passphrase` and reload never read it.
When a reload public key is present in the authenticated document,
`change-passphrase` may leave a one-time `dek_handoff` blob: an inner
AES-256-GCM seal of the new DEK under the **previous** DEK with AAD binding
the vault id and the change commit's audit head and sequence, wrapped in an
outer `nacl/box` anonymous seal to the reload public key
(`inner nonce||inner ciphertext`). The outer box alone does not prove rotation
authority; the inner layer requires the old DEK, so a same-uid writer cannot
forge a handoff with an attacker-chosen DEK using only the public key. The
handoff is not readable from an old backup and passphrase without the daemon's
ephemeral private key. A resident session that still holds the reload key pair
opens the outer box, opens the inner under its current DEK and binding,
adopts the new DEK, and continues the existing verification path; any failure
retires the session. Ordinary writes clear the handoff; if it is cleared before
the daemon reloads, the session fails closed.

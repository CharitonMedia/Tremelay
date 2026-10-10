# ADR 0016: Checkpoint-bound local snapshot backup and restore

Status: Accepted

## Context

M9 calls for recovery as well as shared vaults. M9a is the local approval reference ([ADR 0015](0015-local-shared-vault-authorization.md)). This ADR records only M9b: a local backup and restore of a vault the host can already unlock. It is not recovery of a lost passphrase, a lost owner, a compromised host, or organizational control. It does not complete M9.

The vault is one SQLite file. Credential bytes stay under the Argon2id and AES-GCM envelope from [ADR 0002](0002-single-user-vault-key-hierarchy.md). The audit chain and the locked-denial suffix stay as published in [ADR 0003](0003-custody-audit-hash-chain.md). Shared state stays as published in ADR 0015. No second key wrap, recovery secret, or two-file commit protocol is added.

## Decision

### What the host must do

The trusted host supplies the existing passphrase and a checkpoint it stores outside the backup file. It quiesces the source, keeps a single active instance, and chooses the destination. This process does not enforce those duties across other processes or machines. A successful decrypt is not a freshness proof. Caller text, a filename, and a manifest stored beside the artifact are not a checkpoint.

An old artifact together with the checkpoint issued for that artifact still matches. This reference cannot tell that pair is stale. If the host supplies a newer checkpoint, every older artifact fails the match and restore refuses. There is no stale-snapshot merge, membership reset, authority reissuance, or automatic failover.

### Snapshot

`Backup` copies one existing vault file to a new path with the online backup API of the pinned `modernc.org/sqlite` driver (`sqlite3_backup_init`, `sqlite3_backup_step`, `sqlite3_backup_finish`). That API is the consistency boundary. A byte copy of a live database file is not. The copy is stepped 64 pages at a time. The artifact is created with `O_EXCL` and mode `0600`. A failed backup removes it.

The checkpoint is read from that finished artifact, not from the live source and not from a sidecar. The file is hashed with standard-library SHA-256 while streaming, then opened read-only. Authentication uses the existing envelope, audit-chain, suffix, document, shared-history, membership, request, grant-provenance, health, detection, and key-identity checks. Those checks do not append a denial or an unlock row, so a wrong passphrase does not change the artifact. Backup itself appends no audit event. The tip in the checkpoint is the last audit row in the snapshot, including a valid locked-denial suffix when one is present. A commit on the source after the backup API returns is outside the artifact and outside the checkpoint.

### Checkpoint format

The host-held value is exactly:

```
tremelay-checkpoint-v1
vault <32 lowercase hex>
org <32 lowercase hex, or ->
seq <decimal uint, no leading zero>
tip <64 lowercase hex>
sha256 <64 lowercase hex>
```

`org -` means the snapshot is not shared. `tip` and `seq` are the last audit row, not the authenticated head when a denial suffix follows that head. `sha256` is the artifact file. Missing, extra, reordered, uppercase, or padded fields are rejected. `Backup` does not write this text. `Restore` does not look for it.

### Restore

`Restore` accepts a new destination path and the host's checkpoint. It rejects an empty checkpoint, a symlink component, an existing file, and an existing directory. It does not replace a live vault and it does not follow a destination alias.

The artifact is hashed and opened read-only. The digest, vault id, organization id, tip sequence, and tip hash must match the checkpoint. The same unlock validation runs before any destination name exists. A mismatch, a wrong passphrase, or a corrupt file returns a fixed error, leaves the artifact unchanged, and leaves no destination.

Publication copies the artifact to a private `*.restore-incomplete` file in the destination directory, created with `O_EXCL` and mode `0600`. That copy is hashed and validated again. Only then is it linked onto the destination name, which fails if the name exists. The incomplete name is removed after the link. The destination is mode `0600`. A fault before the link removes the incomplete file and does not create the destination. If removing the incomplete name fails after the link, the destination name is removed and the call returns an error. A crash before the link can leave an incomplete file; that name is not a successful restore and must not be opened as one. A crash after the link and before the incomplete name is removed leaves two names for one complete file. The destination name is the restored vault. A returned error is not a successful restore, even if a later cleanup could not delete a name. No chmod of a directory tree is used.

`Restore` does not append an audit event and does not return a session. Success means the destination name passed validation and was linked. Failure means the call returned an error. Neither result is an audit row. A later `Unlock` of the destination is an ordinary open: it can append the usual unlock event, incorporate a valid denial suffix, and enforce trusted-time expiry. A failed unlock of the destination is that later open, not a claim that restore wrote an audit row.

### What this does not decide

Lost-passphrase recovery, owner recovery, enrollment, SSO, independent custody, a freshness or timestamp service, cross-machine cutover, remote or cloud storage, a new recovery credential, threshold cryptography, automatic rotation, and any agent or member authority to back up or restore are out of scope. Backup and restore are host custody operations. They are not grants.

## Alternatives considered

- **Copy the database file with `io.Copy`.** Rejected. A live SQLite file has no consistency boundary without the backup API or an equivalent official mechanism such as `VACUUM INTO`.
- **Store the checkpoint in the artifact or a sibling manifest.** Rejected. The host must be able to supply a newer checkpoint than any surviving file. A manifest that travels with the artifact cannot do that.
- **Append a backup or restore audit row.** Rejected. A row in the source would move the source tip after the snapshot. A row in the artifact would change the bytes the checkpoint hashes. A failed restore has no durable vault in which a row can be claimed. The historical chain is preserved unchanged.
- **A second wrapping key or a recovery secret.** Rejected. The existing passphrase and DEK wrap are the only unlock material.
- **Treat a matching old checkpoint as stale.** Rejected. The reference has no clock, generation, or witness outside the checkpoint the host presents.

## Security implications

- Extraction: restore does not return a session or a secret. Logs and errors are fixed strings. The passphrase, document plaintext, and caller error text are not written.
- Stale authority: a newer host checkpoint rejects an older snapshot. An older checkpoint still restores that older snapshot, including a grant, membership, or request that the live source has since changed. The host chooses which checkpoint is current.
- Audit: the restored chain is the snapshot's chain. Restore does not invent a success row for a failed check. Ordinary unlock and expiry behavior are unchanged.
- Tampering: a changed artifact fails the digest or the existing authentication checks. The original file is opened read-only.
- Destination: an existing path is not overwritten. A partial staging file is not the destination name.

## Consequences

- M9 remains open for real recovery, enrollment, independent custody, and production shared access.
- Operators do not get a backup CLI in this slice. The demonstration is in-process.
- The host must keep checkpoints outside the artifact. Losing the checkpoint loses the ability to restore that artifact against a later checkpoint, which is the intended refusal.

## Tests

`TestBackupRestoreSyntheticDemo` restores a current shared snapshot, uses the existing attestation broker, keeps plaintext and direct-grant denials and approval provenance, and still enforces expiry and revocation after reopen. `TestBackupRestoreNegative` and `TestCheckpointFormat` cover a stale checkpoint, an old checkpoint that still matches, revocation, membership removal and re-promotion, request consumption, key replacement, containment, foreign and mismatched fields, a missing checkpoint, a wrong passphrase, corruption, destination collision, aliases, and a failed publication. The commands are in [docs/m9b-local-backup.md](../m9b-local-backup.md).

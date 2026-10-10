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

`Backup` copies one existing vault file to a new path with the online backup API of the pinned `modernc.org/sqlite` driver (`sqlite3_backup_init`, `sqlite3_backup_step`, `sqlite3_backup_finish`). That API is the consistency boundary. A byte copy of a live database file is not. The copy is stepped 64 pages at a time. The artifact is created with `O_EXCL` and mode `0600` only when that path and its `-journal`, `-wal`, and `-shm` names are all absent. Those existing names are not changed. A failed backup removes the artifact it created. It removes sidecars only after it has opened that artifact, so a failure before that open does not delete a recovery file it did not create. The artifact file and its parent directory are synced before the checkpoint is returned. A sync failure removes the artifact and returns an error.

The checkpoint is read from that finished artifact, not from the live source and not from a sidecar. If the copied audit table lacks columns added after M1, Backup adds them on the private artifact only, using the same migration Unlock uses, and only then hashes the file. The source is not opened for write. Existing audit hashes are not rewritten. A current schema is not rewritten, so that artifact stays the online-backup bytes. The file is hashed with standard-library SHA-256 while streaming, then opened read-only. Authentication uses the existing envelope, audit-chain, suffix, document, shared-history, membership, request, grant-provenance, health, detection, and key-identity checks. Those checks do not append a denial or an unlock row, so a wrong passphrase does not change the artifact. Backup itself appends no audit event. The tip in the checkpoint is the last audit row in the snapshot, including a valid locked-denial suffix when one is present. A commit on the source after the backup API returns is outside the artifact and outside the checkpoint.

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

`Restore` accepts a new destination path and the host's checkpoint. It rejects an empty checkpoint, a symlink component, an existing file, and an existing directory. It does not replace a live vault and it does not follow a destination alias. Backup and restore both refuse a symlink anywhere in the path, including an ancestor, and do not resolve it. The host passes the canonical path. On macOS the usual temporary directory is under `/var`, a symlink to `/private/var`; that unresolved path is rejected.

The artifact is hashed and opened read-only. The digest, vault id, organization id, tip sequence, and tip hash must match the checkpoint. The same unlock validation runs before any destination name exists. A mismatch, a wrong passphrase, or a corrupt file returns a fixed error, leaves the artifact unchanged, and leaves no destination.

Publication copies the artifact to a private `*.restore-incomplete` file in the destination directory, created with `O_EXCL` and mode `0600`. That copy is hashed and validated again, then chmod'd to `0600`, before it is linked. The destination name and its `-journal`, `-wal`, and `-shm` sidecars are checked again immediately before the link. If any of them exists, the call returns `ErrInvalid` and does not change those files. A fault before the link removes the incomplete file and does not create the destination.

The link is the commit. After it, Restore syncs the parent directory and then removes the incomplete name. If the directory sync fails, Restore removes the destination. When removal and the strict rollback directory sync both succeed, the error is `ErrIO` and this call left no newly restored destination. If removal succeeds but the rollback directory sync fails, the error is `ErrPublicationUncertain`: the name is absent at return, but that absence is not known durable and a crash may restore the linked name. When removal fails, the error is `ErrPublished`: the destination remains and is the restored vault. That error does not mean the destination is absent. If the directory sync succeeds and removing the incomplete name fails, the error is also `ErrPublished` and the destination stays; the incomplete name may remain as a second link to the same file. A crash before the link can leave an incomplete file; that name is not a successful restore and must not be opened as one. A crash after the link can leave the destination, and possibly both names. No chmod of a directory tree is used.

`Restore` does not append an audit event and does not return a session. Its outcomes distinguish ordinary failure, a published destination still present (`ErrPublished`), and uncertain rollback durability (`ErrPublicationUncertain`). A nil result means validation, publication and the platform-supported sync/cleanup operations completed. Ordinary failures do not leave a newly restored destination from this call; pre-existing collision files remain untouched. Fixed logs distinguish `failed`, `published`, and `publication_uncertain`. None of these results is an audit row. After either exceptional publication outcome, the host must inspect and reconcile the destination and its single-active-instance state before retrying or cutting over; absence at one instant is not evidence of durable rollback. A later `Unlock` of the destination is an ordinary open: it can append the usual unlock event, incorporate a valid denial suffix, and enforce trusted-time expiry. A failed unlock of the destination is that later open, not a claim that restore wrote an audit row.

File sync uses a non-creating, non-truncating write-capable handle only for Backup's already-owned artifact; the original source and restore artifact remain read-only. File-copy and sync helpers retain close failures as fixed I/O errors. On Windows, directory Sync may be unsupported: the implementation retains the file sync barrier, but directory-entry crash durability depends on the OS/filesystem. It does not promise a durable directory entry there when the OS cannot confirm it. Rollback uses a strict directory sync on every platform: an unsupported Windows flush therefore yields `ErrPublicationUncertain`, never confirmed rollback. The injected rollback-sync tests exercise the explicit failure result; they do not simulate a power loss.

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
- Destination: an existing path, including a SQLite sidecar, is not overwritten or deleted. A partial staging file is not the destination name. `ErrPublished` means the linked destination remains; it is not a claim that restore left nothing.

## Consequences

- M9 remains open for real recovery, enrollment, independent custody, and production shared access.
- Operators do not get a backup CLI in this slice. The demonstration is in-process.
- The host must keep checkpoints outside the artifact. Losing the checkpoint loses the ability to restore that artifact against a later checkpoint, which is the intended refusal.

## Tests

`TestBackupRestoreSyntheticDemo` restores a current shared snapshot, uses the existing attestation broker, keeps plaintext and direct-grant denials and approval provenance, and still enforces expiry and revocation after reopen. `TestBackupRestoreNegative` and `TestCheckpointFormat` cover a stale checkpoint, an old checkpoint that still matches, revocation, membership removal and re-promotion, request consumption, key replacement, containment, foreign and mismatched fields, a missing checkpoint, a wrong passphrase, corruption, destination collision, aliases, and a failed publication. The publication tests distinguish a retained linked destination from rollback whose directory durability cannot be confirmed. `TestBackupRestorePublication` covers a sidecar collision that is left unchanged, a backup whose directory sync fails closed, a directory sync that rolls back to no destination, and `ErrPublished` when the linked destination remains. `TestBackupMigratesLegacyAuditSchema` backs up an M1 audit table: the source stays unmigrated, the artifact gains the later columns without a hash rewrite, and restore still unlocks. `TestBackupPathRequiresCanonicalAncestor` rejects a symlink ancestor and accepts the canonical path. Ordinary test paths are canonicalized the same way a host must canonicalize them. The commands are in [docs/m9b-local-backup.md](../m9b-local-backup.md).

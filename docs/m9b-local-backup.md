# M9b — checkpoint-bound local snapshot backup and restore

This is a partial slice of M9. The host already has the vault passphrase. `Backup` writes one consistent encrypted SQLite snapshot through the driver's online backup API and returns a checkpoint. The host stores that checkpoint outside the file. `Restore` publishes the snapshot at a new path only when the host passes that same passphrase and a checkpoint that matches the file.

This is not recovery of a lost passphrase, a lost owner, a compromised host, or organizational control. It is not a freshness service, independent custody, or a cross-machine cutover. An old snapshot together with the checkpoint that was issued for it still restores. This reference cannot tell that pair is stale. A newer checkpoint does not match that older file, and restore refuses instead of reviving the older authority. No membership reset, grant reissue, or failover is performed.

The checkpoint binds the vault id, the organization id when the snapshot is shared, the audit tip including a valid locked-denial suffix, and the SHA-256 of the artifact. It is captured from the finished snapshot. If that snapshot's audit table is an M1–M5 schema, Backup adds the missing columns on the private artifact before hashing it. The source file is not modified. Backup and restore do not append an audit event. A later unlock of the restored file is an ordinary open. See [ADR 0016](adr/0016-local-checkpoint-backup.md).

The host path must not contain a symlink. These calls do not resolve aliases. A macOS temporary path under `/var` (a symlink to `/private/var`) is invalid; pass the canonical path, such as the result of resolving that directory.

## Local demonstration

The demonstration uses a temporary database, a disposable Ed25519 key, synthetic identities, and the session clock. It does not call a network or read a live credential.

```bash
go test ./internal/vault/ -run 'TestBackupRestore|TestBackupMigratesLegacyAuditSchema|TestBackupPathRequiresCanonicalAncestor|TestCheckpointFormat' -count=1
```

`TestBackupRestoreSyntheticDemo` is the acceptance path: a current shared snapshot restores, the existing broker still attests, shared plaintext and direct-grant denials remain, approval provenance remains, and expiry and revocation still stop later use after reopen.

`TestBackupRestoreNegative` covers a snapshot that predates request consumption, revocation, membership removal and re-promotion, key replacement, or containment. Each of those artifacts is rejected against the later checkpoint. The same test covers a wrong passphrase, a corrupt file, a missing or mismatched checkpoint, destination collision, a destination alias, and a publication that fails before the destination name exists. `TestCheckpointFormat` checks the checkpoint text.

## What was not run

No live service, production backup, remote store, or cross-machine cutover was exercised. Lost-secret recovery was not implemented. The prohibited historical local validation probes and the old M7 network probe are not part of these tests and were not run.

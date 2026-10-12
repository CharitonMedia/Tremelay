# Human vault lifecycle commands

Tremelay is pre-release security software. Use disposable local test vaults;
do not put production credentials in it yet. These commands are human host-custody
operations. They do not add agent raw-secret access or lost-passphrase recovery.

## Change a passphrase

```sh
tremelay vault change-passphrase --path /canonical/path/vault.db
```

Use a terminal. Enter the old passphrase, then the new value twice; none is echoed.
This command ignores `TREMELAY_PASSPHRASE` and refuses piped input. The replacement
must differ and must contain 8–1024 bytes. This length check is not a guarantee of
strength or a compromised-password check. No passphrase belongs on the command line.

The same data-encryption key is rewrapped with a fresh salt and nonce. The wrap and
audit change commit together. Wrong old input, rejected replacement, mismatched
confirmation or a failed transaction leave the original passphrase in authority.
Denials may append audit rows. A stale session cannot overwrite the new wrap.
Stop other instances first. A change cannot revoke a key already held in another
process or protect against a compromised host. Existing snapshots and copies still
require the passphrase they had when made. Keep that information securely.

After success, `audit verify` can authenticate the current vault with the new
passphrase without writing it. Older binaries lacking the new audit action fail
closed after a change; use the current build for changed vaults.

## Back up and keep the checkpoint independently

Quiesce writers first if the snapshot must represent the newest source state.
Choose a new artifact name and an independently retained checkpoint destination.
The following paths are examples to replace with canonical paths on your machine:

```sh
umask 077
tremelay vault backup --path /canonical/vault.db --output /canonical/backups/snapshot-001.db > /independent/checkpoints/snapshot-001.txt
```

The command emits the checkpoint only on stdout; prompts and diagnostic text use
stderr. Preserve the entire checkpoint exactly. The backup is an encrypted SQLite
snapshot. Its checkpoint binds its digest, vault and organization identity, and
audit tip. There is no automatic sibling manifest and no backup audit event. The
source is read-only, including if authentication fails.

Choose a new checkpoint filename too: shell redirection can overwrite a file before
the command starts. Independently retaining and choosing a current checkpoint is
your responsibility. A checkpoint stored only beside the artifact supplies no
independent freshness. If checkpoint output fails, the artifact may already exist;
the CLI says so. Keep it and make a fresh backup to a different new artifact name
with a working checkpoint destination. Do not blindly rerun against the same name.

## Restore to a new path

```sh
tremelay vault restore --input /canonical/backups/snapshot-001.db --path /canonical/restored/vault.db --checkpoint-file /independent/checkpoints/snapshot-001.txt
tremelay audit verify --path /canonical/restored/vault.db
```

Supply the passphrase from when that snapshot was made, even if the live vault's
passphrase has since changed. Backup and restore accept the existing
`TREMELAY_PASSPHRASE` source or a no-echo terminal prompt. Prefer the prompt; an
environment variable has the same-user exposure described in ADR 0002.

The target and its `-journal`, `-wal`, and `-shm` names must not exist. Files and
sidecars already there are not overwritten or removed. The artifact remains
read-only. Both artifact and destination paths must contain no symlink components;
resolve parent directories yourself first. On macOS, `/var` is normally an alias
of `/private/var`, so use the canonical path.

Exit status:

- 0: the operation and output completed
- 1: ordinary failure; read the fixed diagnostic, including any output-failure warning
- 2: invalid command usage
- 3 on restore: the destination remains; inspect it and reconcile active instances before retry or cutover
- 4 on restore: publication rollback durability is uncertain; the target may reappear after a crash, so inspect and reconcile before any retry or cutover

No command automatically activates the restored vault. Run only one active instance.
A successful restore is not proof of freshness: an old snapshot with its original
old checkpoint still restores. A newer checkpoint rejects an older artifact. This
cannot recover a lost passphrase, lost checkpoint, lost owner, or compromised host.
Windows directory-entry durability remains bounded by OS/filesystem support.
See [ADR 0019](adr/0019-human-vault-lifecycle.md) and
[the backup design](m9b-local-backup.md) for exact limits.

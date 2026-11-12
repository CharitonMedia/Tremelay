# ADR 0029: Archiving old audit rows

Status: Accepted pending owner veto

## Context

Every attempt adds at least one audit row, and nothing ever removed one. A
review of v1.0.3 (finding 11) measured the cost at 200,000 rows: about 114 MiB
of session memory, a 48 MiB file, 2 to 5 seconds per unlock, and about a
second for each daemon reload. Pacing (ADR 0024) bounds how fast one agent
adds rows. It does not bound the total.

The owner asked on 2026-11-11 for a command that exports the log to a file and
carries on from there.

The chain could not simply be shortened. Unlock, reload, verify, backup and
restore all checked that the chain starts at row 1 with `vault_create`, and
four pieces of state are derived from the rows the vault holds: the detection
mirror, the notice index, the suspension index, and the binding between each
credential's stored health and its latest health row.

## Decision

### 1. One chain, cut at the front

`tremelay audit archive --path VAULT --out NEW_FILE [--keep N]` moves the
oldest rows to a file and leaves at least the newest N (1000 by default) in
the vault.

The chain is not restarted. The rows that stay keep their sequence numbers
and hashes, and the first of them still names the hash of the last archived
row. Sequence numbers in alerts and in `ref_seq` stay unambiguous, and the
files from successive archives are consecutive runs of one chain.

No hash, cipher or key derivation is added or changed.

### 2. The cut is sealed in the document

The encrypted document gains one optional member, `audit_base`: the sequence
and hash of the last archived row. It is written in the same transaction that
deletes those rows.

The base is to the front of the chain what the audit head is to its end. On
every unlock, reload, verify, backup and restore, after the document is
authenticated:

- with no base, the first row must be row 1;
- with a base, the first row must be the one after it and must name its hash.

So without the DEK nobody can remove more rows from the front, put archived
rows back, or cut the front of a vault that was never archived. Each of those
fails as an audit verification failure.

The check before authentication is weaker than it was. `verifyChain` used to
refuse any chain that did not start at row 1. It now accepts a chain that
starts later if its rows link to each other, because the base it must be held
to is inside the ciphertext. Every caller that trusts a chain goes on to
authenticate the document, and the base check runs there. What changes is
when a deleted front is noticed. It used to be refused before the passphrase
was looked at, and nothing was written. Now a caller with the wrong passphrase
is told the unlock failed, a caller with the right one is told the audit log
failed verification, and in both cases the usual unlock denial row is
appended first. The alternative was a plaintext copy of the base
in the vault row. That needs a schema migration, and a determined attacker can
rewrite a plaintext column as easily as the rows, so it would catch only
accidents. It was not built.

### 3. The file comes first

The archive is one JSON object per line, each row exactly as stored. The
command creates the file new and owner-only, refuses an existing name and any
symlink in the path, and flushes it.

The file is read back inside the transaction that deletes the rows, after the
delete statement and before the commit. The rows leave only if the file is
exactly those rows at that moment. The place matters. SQLite keeps files of
its own beside a database (`-journal`, `-wal`, `-shm`) and names them after
the file the database path resolves to, which is not always the path a
session opened. It deletes a journal it finds and writes its own; it writes
over a WAL. An archive that ended up under one of those names, by a link or
any other alias, would vanish after its rows had left the vault. Inside the
transaction SQLite has already done that: the stale journal is gone and its
own is in place, to be deleted at commit. A file that still reads back as
the rows is not that journal. The same transaction checks that SQLite is
using the rollback journal at all, because it switches to a WAL when it
finds one beside the vault and writes that at commit, after the read. If
either check fails, nothing is deleted.

In front of that stands a plain rule on the name: the command refuses a file
name that contains `-journal`, `-wal` or `-shm`, in any directory and any
letter case. That also keeps the file from being taken for the sidecar of
some other database later. An earlier version compared the output path with
the vault's own sidecar paths. A vault opened through a symlink got past it,
which is why the check on the vault's side is now made by asking SQLite's
transaction, not by predicting names.

A line is accepted only if it is byte for byte what the command writes for
that row. Go's JSON decoder matches member names without regard to case and
lets a repeated name win, so a looser reader would let one line carry the
hashed value for the check and show a different one to a person reading the
file.

- A refusal (nothing to archive, a bad path, a refused name, an existing
  file) writes an `audit_archive`/`denied` row and no file.
- A commit that fails does not decide the file's fate by its error. The
  command brings its session up to what is stored and accounts for every
  row on file.
  - This command's `audit_archive` row is in the chain and the vault's
    sealed base is at or past this cut: the transaction was durable and a
    later step failed. The file is the archive of its rows, and the command
    reports success, whether or not another archive has cut further since.
    The session adopts a chain only if it still holds the row the session
    last verified, and this command's row would come after that one, so it
    cannot have been archived in between. The base is asked as well as the
    row because two processes on a coarse clock can write the same archive
    row byte for byte. With the base at or past this cut, every row on file
    has left the vault and an archive file holds it. One case is reported
    wrongly: two archives of the same vault started in the same clock tick,
    and the other cut further. The loser reports success for rows the
    winner's file also holds, and its own file ends before the vault's base,
    so it does not verify against the vault; the winner's does. No row is
    lost. Telling the two apart needs a row only one call could have
    written, which is a change to the row format and was not made.
  - Otherwise each row on file must be in one of two places. Rows at or
    before the vault's sealed base left in a cut made with the DEK, so
    another archive's file has them. Every later row must be in the audit
    table, read from the table itself and compared field for field.
  - Every row is accounted for: the file is a spare and is removed. If
    another writer got in first (a commit, or an unlock denial appended
    behind the head), the command cuts at the same row again, up to four
    more times, but only while the chain still starts at the file's first
    row and no new notice row names a row the cut would take. A smaller
    archive by another process moves that start; cutting there would leave
    two files that overlap. A lost race is reported as a stale session.
  - Any row is not accounted for: it was deleted or changed by hand, the
    table cannot be read, or the session could not adopt what is stored. The
    file may be the only true copy. It stays, and the error says so.

A crash or an interrupt between writing the file and the commit leaves the
file with nothing said. The vault still holds every row in it.

`audit verify --path VAULT --archive FILE ...` verifies the vault, verifies
the files as linked runs in the order given, and requires them to be this
vault's rows, to start at row 1 with `vault_create`, and to end at the vault's
base. Passing means the files and the vault together are the whole history.
Files that are the vault's but start later fail with their own message: an
older file is missing, or the front of one was removed. The files need no
passphrase to check as runs. Tying them to a vault does.

### 4. What is audited

A successful archive appends `audit_archive`/`allowed` as the newest row. It
is a version 1 row, like `vault_unlock`. Which rows left is in the document's
base and in the gap the sequence numbers show.

Before that row the command restates the health of each credential whose
latest health row is about to leave, as `health_refresh`/`unchanged` with the
stored generation and findings. Nothing is reassessed and the stored
assessment does not change. The strict rule that a credential's stored health
matches its latest health row in the vault is kept as it was; the restated
row is the row it holds to.

### 5. State derived from the rows

Derived state follows the rows the vault holds. Nothing is carried across the
cut out of band.

- **Detection.** The repeated-denial count for an agent is its denials among
  its last 32 broker rows in the vault. After an archive that is the last 32
  among the kept rows. Only the owner can archive, and an agent can already
  push its own denials out of the window with 32 allowed calls.
- **Notices.** A notice row is verified against its source row, so the cut is
  moved back until no kept notice names an archived source. An alert that was
  decided but not yet delivered, and whose rows are archived, is not retried.
  No shipped build retries one (ADR 0028 delivers at commit). The commit
  path refuses any notice row about a row the vault no longer holds, so an
  alert whose delivery was in flight when its source was archived gets no
  outcome row. Written, that row would leave a chain no unlock accepts.
- **Suspension.** An agent suspended by a containment row that is archived is
  no longer recognised as suspended when its denials are classified. Its
  denials count toward repeated denial again. That raises alerts and hides
  none. Enforcement does not read these rows: it reads the agent and grant
  records in the document. No shipped build suspends an agent (ADR 0028).
- **Views.** `audit list` and `audit get` cover the rows in the vault. An
  archived sequence is not found.

### 6. A running daemon

A resident session adopts another process's commits only when the chain it
reads still contains the row it last verified (ADR 0024). That rule stands.
If an archive removes that row the session cannot tell the cut from a
rollback to an older copy, so it retires itself and the daemon locks and
exits 1. The row a daemon last verified is among the newest, so the default
of 1000 kept rows leaves it in place in ordinary use. Start the daemon again
if it locks.

## Consequences

- Trust boundary: the passphrase holder can now remove audit rows from the
  vault. They could already discard the vault. The removal is recorded, the
  rows go to a file first, and the cut is authenticated. No agent-facing path
  reaches this command, and the daemon does not expose it.
- The archive file is the only copy of its rows. It holds no secret, but it
  holds agent, credential and grant ids and every action taken. Keep it like
  a backup. A changed or shortened file is detected when it is verified
  against the vault; a lost one is not recoverable.
- A vault this command has run on does not open under an older build, even
  if the command refused: the older build does not know the `audit_archive`
  action, the new document member, or a chain that does not start at row 1.
  Upgrade only.
- The vault file does not shrink. SQLite reuses the freed pages.
- `SECURITY_INVARIANTS.md` section 6 holds: the log stays append-oriented and
  tamper-evident, and the archive is an external checkpoint of its front.

## Alternatives considered

- **A fresh chain from row 1 with a pointer to the archive.** Sequence
  numbers would repeat across files, and the link would be a new construct
  instead of the existing hash chain.
- **Carrying derived state across the cut in the document.** More sealed
  state to validate, for facts that either reset harmlessly or can be
  restated as ordinary rows.
- **Relaxing the health binding for credentials whose row was archived.** It
  weakens a check to save writing a few rows.
- **Automatic archiving by the daemon.** The daemon would write files and
  delete audit rows without the owner asking. Left to the owner's own
  schedule.

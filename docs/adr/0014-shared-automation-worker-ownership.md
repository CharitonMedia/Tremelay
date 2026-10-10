# ADR 0014: Shared worker ownership across goal lifecycle changes

Status: Proposed

## Context

An accepted supervisor worker remained active while an ordinary review claim was
already completed. Manual correction and merge proceeded without checking the
supervisor receipt. Its later branch push was published as a second PR because
publication considered only open PRs. Closed-PR filtering also stranded the
supervisor's still-owning receipt, preventing trustworthy terminal reconciliation.

## Decision

Treat both trusted claim families as shared repository ownership before any
initial, ordinary-review or supervisor worker create. Preserve strict canonical
control parsing and fail closed on malformed trusted state or an orphan launch
receipt. Do not release an accepted/ambiguous worker based on age, review/head
changes, labels, PR closure or merge. Historical supervisor completed/escalated
records without a verified terminal receipt require GET-only reconciliation.

Separate launch eligibility from receipt recovery. Enumerate all PR states for
known receipts, while retaining existing author/repository/goal identity bounds.
Closed or held goals permit only service GETs and durable updates to that existing
receipt. Verify agent ID, latest run, run ID/agent association, repository/PR
association and explicit terminal status. Recheck latest run before recording a
terminal receipt, so an earlier finished run cannot hide a later active run.
A missing/unknown response remains owning. Never replay an ambiguous create.
Recovery must not call the assessor, create a worker, request a historical review,
remove a hold, reset a cycle or reset a checkpoint budget.

Fresh source-issue and all-state PR history checks prevent any launch/publication
for a closed issue or a lineage with a merged PR. Recheck immediately before
create/publication. The trusted `main` implement/publish checkout supplies the
new guards for newly deployed workflow definitions. A manual takeover retains
`human-review-required` and removes `goal`; the label alone is intentionally a
supervisor checkpoint. Publication must not restore `goal` to that manual hold.

## Limits and security consequences

This changes development-automation ownership, not Tremelay's credential broker.
No model authority, credentials, activation, secrets, provider fallback, merge
permission, three-cycle allowance or total assessment allowance is expanded.
All-state scans read only metadata/receipts; only eligible current checkpoints
can consume the existing model budget. Recovery remains serialized by the
existing controller, with an optional targeted existing-receipt mode. Automatic
ordinary upgrades are limited to accepted/migrated legacy receipts, which cannot
enter a create/release path. Modern ordinary claims retain their existing per-PR
workflow lock, including release of definitely unattempted prepared claims.

Initial issue workers consult shared review/supervisor ownership, but their own
initial create protocol is not redesigned here. Its ambiguous creates still
require explicit reconciliation. Previously created branches may contain older
workflow YAML: a main-only merge does not retroactively replace that definition.
Retired branches must remain unqueued, and future goals start from patched main.

## Validation

Offline tests exercise the actual ordinary-launch shell with mocked services;
closed source issues, merged prior PRs, manual holds, stale publication snapshots,
repository-wide owners, malformed/orphan receipts, late/closed-PR reconciliation,
old completed/escalated phases, unknown and changed runs, duplicate wake handling,
unchanged polls, cycle accounting, and no model/create/review/label action during
historical recovery. Existing protocol, legacy migration, budget and isolated
Anthropic credential-boundary regressions remain required. No live service call
is part of this validation.

The response checks follow Cursor's current [Get An Agent and Get A Run
reference](https://cursor.com/docs/cloud-agent/api/endpoints#get-a-run): run ID,
agent ID and status are explicit fields; pushed-branch metadata is per-agent.
The retained PR-association check accepts the recorded agent repository PR URL
or its run's matching pushed-branch PR URL, never a guessed branch-to-PR mapping.

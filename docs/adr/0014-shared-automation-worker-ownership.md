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
control parsing and fail closed on unknown-version or malformed trusted state,
or an orphan launch receipt. Only the existing canonical standalone review and
budget markers are exempt non-state controls; checkpoint evidence remains inert.
Do not release an accepted/ambiguous worker based on age, review/head
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
create/publication, including the initial goal-branch push after branch setup.
The trusted `main` implement/publish checkout supplies the
new guards for newly deployed workflow definitions. A manual takeover retains
`human-review-required` and removes `goal`; the label alone is intentionally a
supervisor checkpoint. Publication must not restore `goal` to that manual hold.

## Limits and security consequences

This changes development-automation ownership, not Tremelay's credential broker.
No model authority, credentials, activation, secrets, provider fallback, merge
permission, three-cycle allowance or total assessment allowance is expanded.
All-state scans read only metadata/receipts; only eligible current checkpoints
can consume the existing model budget. Every create path (initial goal, ordinary
review, checkpoint supervisor and opted-in generic remediation), plus ownership
recovery/completion, uses one job-level `tremelay-worker-admission` group with
`cancel-in-progress: false`. The supervisor keeps its different workflow-level
controller group. The fixed `serialized-v1` contract replaces its old coarse
active-workflow gate: queued jobs cannot dispatch while admission is held.

Initial goal creates reserve a deterministic agent ID in a source-issue comment
before POST. Prepared claims can release only before dispatch reservation;
reserved or accepted/unknown creates require GET-only reconciliation forever,
including after job cancellation. Terminal initial receipts prevent relabelling
from repeating the initial attempt. Historical issue receipts migrate through
verified repository and source-branch association without requiring a PR URL.
Generic creates use the same prepared/dispatch distinction: definite pre-create
failures release a still-matching prepared receipt without consuming a round,
and same-head admission can safely retry. Reserved, working and terminal records
retain the original three-round marker. A failed release remains owned until
serialized reconciliation; cancellation after dispatch reservation, 404 and
ambiguous responses never delete ownership or replay create.

The controller recovers initial receipts in every issue state and existing
supervisor/generic/ordinary receipts in all PR states. Retired ordinary recovery also
includes open goal PRs whose source issue closed or whose lineage already merged.
Shared admission allows safe recovery of modern prepared claims. On a live,
eligible ordinary goal, recovery can complete the existing exact-head review
request after fresh descendant/lineage and request-deduplication checks. Cursor
calls remain GET-only; these already-authorized GitHub completion writes prevent
a displaced pending completion job from stranding the goal. Retired/held goals
remain status-only. Unknown legacy
generic forms remain blocked for explicit assessment; the deployment inventory
contained no such records. Missing service access never means terminal.

GitHub may replace an unstarted pending job in a shared group. Durable receipts
preserve safety across that cancellation, while scheduled completion of eligible ordinary claims and the explicit
recovery inputs retain a route to progress. Superseded unstarted goals must be
requeued only after existing ownership is settled. Previously created branches
may contain older workflow YAML: a main-only merge does not retroactively replace
that definition. Retired branches remain unqueued; future goals start from
patched main. No production launch is part of patch validation.

Supervisor association failures emit a bounded diagnostic on the existing GET
recovery path. It contains the expected public repository, canonical numeric PR
and goal-branch identifiers, trusted recorded worker/run UUIDs, a finite
observed-status snapshot, and a strict `workOnCurrentBranch` category (`true`,
`false`, `missing`, or `unrecognized`). Returned foreign or malformed repositories and other
unrecognized strings become fixed categories; response bodies, result text,
prompts, credentials and arbitrary fields are never logged. This snapshot is
not terminal ownership evidence. The diagnostic adds no service request or
credential and cannot itself release ownership.

Status-only supervisor recovery may reconcile an alternate API-returned PR for
a retired goal. This requires the exact stored run ID, an explicit terminal run
status, and matching recorded agent/current-run identities both before and after
the run lookup. One exact agent repository and one complete canonical pushed
branch must identify the alternate PR. Missing agent `prUrl`/`startingRef` is
permitted only with that complete branch evidence; present conflicting values,
multiple branches, foreign repositories and malformed fields fail closed.
Fresh GitHub GETs must independently prove the original PR merged and both PRs
have the approved owner, exact base/head repository, base `main`, identical
canonical goal branch and one unambiguous canonical source-issue marker.
Live-goal association checks remain strict. A successful alternate association
can only retire the existing receipt, never complete a review, change labels,
authorize a worker, or bypass fresh launch/lineage checks.

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
The ordinary PR-association check accepts the recorded agent repository PR URL
or matching pushed-branch PR URL. The retired exception above requires separate
GitHub proof, never a guessed branch-to-PR mapping. `git.branches` is mutable
per-agent state, shared by every run's response. It is association metadata only:
it proves neither a reviewed commit nor that the alternate PR's contents came
from the recorded run. Terminal execution status comes from the exact run.

Additional offline regressions cover two queued initial labels, initial versus
ordinary/supervisor/generic admission, accepted and ambiguous initial creates,
source closure after preparation, current-run changes, historical source-branch
migration, open-PR retirement recovery, all create/recovery job locks, and generic
single-create/no-replay behavior. The read-only deployment inventory is 65
unreconciled receipts, at most 195 Cursor GETs for successful terminal upgrades,
not proof of live or terminal service state.

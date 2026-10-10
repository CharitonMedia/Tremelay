# Build and Review Automation

Tremelay uses Cursor Cloud Agents for implementation and Codex for review. The automation never merges a pull request automatically.

## Required repository Actions secrets

- `CURSOR_API_KEY` — Cursor Cloud Agents API key.
- `GOAL_GITHUB_TOKEN` — fine-grained GitHub token belonging to the human automation identity. It must have sufficient access to this repository to comment on issues/PRs and manage the goal workflow. Codex review requests must not be posted as `github-actions[bot]`.

These secrets are repository configuration and are not stored in the Tremelay source tree.

## Independent checkpoint assessment

The default-branch supervisor can assess stopped checkpoints through Claude
Sonnet 5.5 using short-lived Anthropic WIF credentials. It remains disabled until
separately authorized and retains all three-cycle and exact-head review guards.
See [setup and activation](checkpoint-supervisor.md). This adds no OpenAI API-key
requirement and no automatic provider or model fallback.

## Starting a goal

1. Write a GitHub issue with outcome-oriented acceptance criteria.
2. Apply the `goal` label.
3. The workflow creates/uses `goal/issue-<number>`.
4. Cursor Cloud implements the issue. Cursor receives the always-on repository Ponytail rule at `.cursor/rules/ponytail.mdc`.
5. The workflow opens or updates a single PR and requests Codex review.
6. Legitimate Codex findings are returned to Cursor for remediation.
7. The same PR is re-reviewed after remediation.
8. A clean exact-head Codex review marks the PR `goal-ready`.
9. A human merges. Automation never merges.

## Three-cycle circuit breaker

No unresolved problem may receive more than three automated Cursor↔review remediation cycles.

At the limit:

- automation stops;
- the PR receives `human-review-required`;
- the workflow posts the latest head and stop reason;
- a human must review the approach before additional agent work.

The count must not be reset by rewording the same defect, restarting the workflow, or spawning a fresh agent against the same unresolved PR lineage.

## Recovering an ordinary review-worker launch

Every ordinary goal-review launch now reserves a deterministic Cursor agent ID
bound to repository, PR, reviewed commit and review ID before its sole create
request. Its owner-authored claim records a fixed, validated state envelope.
The stages distinguish definitely unattempted preparation from a potentially
accepted dispatch. A GitHub read/validation failure before the create attempt
releases the claim with verified deletion or a non-owning replacement comment.
An attempted create with a lost response, 5xx, or agent-ID conflict retains the
claim and never causes a repeat POST. Response bodies are not copied into logs.

The normal completion job reconciles that recorded identity. If a launch or
completion job was interrupted, run the `goal` workflow manually on `main`
with `recovery_pr` set to the PR number and `recovery_comment` set to the
existing PR reservation comment ID (also reported in the job log when available).
This recovery is
serialized with launches for the same PR. It only GETs Cursor; it never creates,
restarts, cancels, or replaces a worker and does not remove a stop label.
Normal completion uses that same concurrency group and recovery path. A newer
review or head cannot create a competitor while a recorded ordinary worker is
still prepared, reserved, running, or awaiting its review-completion write.
Both the ordinary launcher and the checkpoint supervisor enforce that ownership;
the supervisor checks again immediately before dispatch. Delayed review/inline
events cannot override a newer approval, dismissal, or clean exact-head review.

- A validated `prepared` claim can be released because no create was attempted.
- A reserved or working claim is reconciled through its stable agent/run IDs.
  A missing/uncertain GET is not proof that no worker exists; the claim stays.
- Nonterminal workers retain ownership without repeated comment writes.
- A finished worker must have advanced the same PR through a descendant commit
  before an idempotent exact-head Codex review is requested.
- Terminal failures or no-op finishes remain recorded and counted; they do not
  launch replacements or silently reset the three-cycle allowance.

Checkpoint comments escape all copied evidence, including HTML control markers
and plain-text cycle phrases. Quoted findings, paths, prior attempts and CI
metadata cannot become owner-authorized launch, resume or supervisor state.
Only the formatter's own final checkpoint marker remains active.

### Upgrading existing control comments

Reader hardening applies to already-stored comments, not only new output. The
original full and oversized checkpoint envelopes are evidence: quoted supervisor,
resume, claim, review-request and budget markers in them grant no authority.
Genuine supervisor records must retain a canonical final state envelope, and
genuine manual resume markers remain supported at their historical boundaries.
An ambiguous stop body that may already have been rewritten into active state
fails closed for explicit reconciliation; it is not silently erased from history.

Pre-upgrade ordinary worker claims also retain ownership across newer heads and
reviews, even without the newer launch-state record. The same GET-only recovery
command can reconcile a canonical old accepted-worker URL after verifying the
agent, run, repository and PR association. It records a separate legacy envelope
under the same comment, preserving the original random agent ID and one consumed
cycle. Only a verified terminal run releases pending ownership. Historical
completion never triggers a new worker, Codex review, stop removal or budget reset.

An old reservation with no recorded worker URL cannot prove that no create was
attempted. It remains blocking and requires the owner to reconcile the original
worker outside this automatic path. A missing lookup, newer review, elapsed time,
or changed head does not justify discarding that reservation or launching again.

## CI

Tremelay runs general Go CI plus dedicated `Test Linux` and `Test Windows` workflows used by exact-head review orchestration. CI also verifies the pinned Ponytail Cursor rule, compiles the Python automation helpers, and runs all automation regression test files. The launch tests execute the actual workflow shell with mocked GitHub/Cursor commands; no live workers are used.

## Shared ownership and manual takeover

Before any initial goal, ordinary review, or supervisor worker create, read the
full repository PR history and both trusted claim families. A normal reservation,
legacy accepted-worker receipt, supervisor assessment reservation, or accepted
supervisor worker may still own work after a newer head/review, label removal,
PR closure, or merge. Malformed trusted state and orphan supervisor launch
receipts fail closed. An old supervisor `completed`/`escalate` phase without a
verified terminal receipt does not release ownership.

The source issue must still be open, and no earlier PR in its canonical branch
or Goal-Issue lineage may already be merged. Publication rechecks this live
history immediately before planning writes; a late worker push cannot recreate
that completed goal. Launch guards also check other goal PRs in the repository,
so a newly queued milestone waits for earlier recorded workers to be reconciled.

`human-review-required` is a checkpoint invitation to the deployed supervisor,
not an exclusive manual takeover. For manual work, retain that label and remove
`goal` from the PR. Publication preserves this hold. Inspect both ordinary and
supervisor ownership before editing/pushing/merging; the labels do not cancel an
accepted worker. Wait for a verified terminal result before competing work.
Restore `goal` only after ownership and the next authorized action are settled.

The scheduled supervisor reads all PR states for existing supervisor receipts
and legacy accepted ordinary receipts. Modern ordinary claims retain their
serialized per-PR `goal` recovery job, so an active prepared claim cannot be
released by another controller. Closed or held PRs only receive GET-only worker
reconciliation and updates to their existing receipt; they cannot trigger assessment, create, review requests or label changes.
Agent identity, its current run, repository/PR association and terminal status
must all match, including a second current-run lookup before recording terminal
ownership. A missing lookup, unknown status or newer run preserves the claim.
No create is replayed. Existing checkpoint/cycle history remains consumed.

For a specific supervisor receipt, run Checkpoint Supervisor on `main` with
`recovery_pr` and `recovery_comment`, leaving preflight and smoke disabled. This
uses the same serialized controller and activation gate and only reconciles that
existing worker. The ordinary `goal` recovery inputs remain supported, including
closed/held PRs. Neither recovery mode authorizes a replacement worker.

Deployment limits: the new implement/publish definitions check out trusted main,
but an already-created goal branch can still carry an old workflow definition.
Do not requeue a retired goal or assume a main-only merge retroactively changes
its old push workflow. Keep old duplicates held until their workers are verified
terminal; create future milestone branches from the patched main. Initial issue
workers now honor shared review/supervisor ownership, but their own first-create
receipt protocol is unchanged. An ambiguous initial issue-worker create still
needs explicit service reconciliation; relabeling/retrying is not proof it failed.

History reads stop after 100 pages of 100 records and fail closed if the history
cannot be completed within that bound. Historical receipt upgrade is incremental: a verified terminal receipt is not
looked up again; one unknown receipt does not prevent independent legacy receipts
on that PR from being checked. An inaccessible/deleted agent, missing run or
unverifiable PR association remains blocking and is reported with its receipt
ID for an explicit owner retirement assessment. No automatic retirement or new
worker is authorized by that report. A terminal upgrade uses three Cursor GETs
and one existing-comment update; running receipts need two GETs per check.

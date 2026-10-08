# Unattended checkpoint supervision

The reviewer model is pinned to GPT-6.1 Sol (`gpt-6.1-sol`) with high reasoning.
Cursor remains the implementer; Codex remains the independent code reviewer.

## Setup

Installation is disabled by default. Merging this workflow does not authorize
paid model calls or worker launches, and a generic pre-existing `true` setting
cannot enable this release. Activation is a separate owner decision after the
spending limit and service setup are agreed.

1. Merge the independently reviewed supervisor PR with all exact-head checks
   passing. The scheduled/event/manual execution gates remain closed.
2. Add a billed OpenAI API key as repository secret `OPENAI_API_KEY` in
   CharitonMedia/Tremelay. Do not paste its value into a PR, issue or chat.
3. Retain `GOAL_GITHUB_TOKEN` for `pattalkslaw-del`, with repository contents/PR
   read and issue/comment/label write permissions. Retain the existing
   `CURSOR_API_KEY`; the trusted supervisor uses it to send its corrective plan
   directly to the worker.
4. Run the default-branch workflow with `preflight_only` selected. This may check
   key presence and the GitHub owner identity while activation remains disabled.
5. Only after explicit owner approval of activation and its spending terms, set
   the repository Actions variable `TREMELAY_SUPERVISOR_ACTIVATION` to
   `reviewed-v1-d9cfdd332b6a490e9999f037f632a750`. This is a public release opt-in
   value, not a secret or authentication credential. Do not enable it merely
   because setup or CI passed. Scheduled/event triggers can make billed calls
   after this value is set; no open browser, workstation or chat is needed.
6. Inspect the first `Checkpoint Supervisor` run and resulting PR assessment.
   Verify that the chosen worker actually starts and gets a new exact-head review.

The default-branch workflow supports `preflight_only` to report missing secret
names without printing values or calling a model. Candidate PR workflows never
receive these secrets. Preflight cannot prove account access or billing.
The live supervisor makes the actual API call only at a stopped checkpoint.

## Operation

After a three-cycle worker stop, the supervisor reads the actual current code
and evidence. Routine corrections receive a recorded plan and one new bounded
segment. Genuine product/security/authority decisions receive a specific
escalation comment. It does not automatically merge.

The event trigger reacts to completed goal/CI runs. A recovery schedule checks
every fifteen minutes for missed checkpoints; GitHub can delay scheduled runs.
Duplicate wakes share one serialized controller and the same trusted checkpoint
claim. Rechecking without a checkpoint does not call the model.
Review-level findings are assessed even when there are no inline comments.
Unsupported binary evidence fails that PR closed while other PRs are still
checked. A definitely unlaunched assessment whose head or review has changed is
durably marked obsolete; its budget remains consumed, and a later wake can
assess the new checkpoint. Reserved or potentially accepted workers are never
discarded or replaced by this stale-assessment recovery.

The existing review launcher also receives the stable review/head claim fixes
from the M5 candidate, so repeated inline/summary events cannot create multiple
workers for one review. Its fixed three-cycle allowance cannot be raised by a
comment, and in-flight launch jobs are no longer cancelled by duplicate events.

The total allowance is three automatic assessments per PR, including failed or
ambiguous reservations. Each resume authorizes at most three worker cycles.
This is a work allowance, not a global billing cap. An owner review is required
to extend it. The model cannot override either limit.

Check the PR's automatic supervisor assessment for the current correction and
head, and the workflow log for dispatch/waiting state. The last assessment must
not be reported as completed implementation; only later commits/CI/reviews prove
that. API failures and ambiguous dispatches preserve their claim and require
reconciliation rather than duplicate launches. The scheduled controller reads
the reserved Cursor identity to recover an accepted launch after a lost response,
waits for completion, verifies an advancing descendant commit, and requests
independent review. The stop label remains during this worker so review-event
launchers cannot race it. A six-hour worker timeout is escalated once while its
ownership stays active. Later wakes continue read-only polling of that same
identity until a terminal result can be reconciled; newer reviews or heads cannot
create a replacement for a worker that is still running or whose state is unknown.

To stop further controller calls, clear the activation variable or disable the
`Checkpoint Supervisor` workflow in GitHub Actions. This also pauses its
reconciliation and does not cancel an already-running Cursor worker; verify that
worker separately before authorizing any replacement.

# Unattended checkpoint supervision

The reviewer model is pinned to GPT-6.1 Sol (`gpt-6.1-sol`) with high reasoning.
Cursor remains the implementer; Codex remains the independent code reviewer.

## Setup

1. Add a billed OpenAI API key as repository secret `OPENAI_API_KEY` in
   CharitonMedia/Tremelay. Do not paste its value into a PR, issue or chat.
2. Retain `GOAL_GITHUB_TOKEN` for `pattalkslaw-del`, with repository contents/PR
   read and issue/comment/label write permissions. Retain the existing
   `CURSOR_API_KEY`; the trusted supervisor uses it to send its corrective plan
   directly to the worker.
3. Merge the independently reviewed supervisor PR. Its default-branch event and
   recovery triggers are then live; no open browser, workstation or chat is needed.
4. Inspect the first `Checkpoint Supervisor` run and resulting PR assessment.
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
launchers cannot race it. A six-hour worker timeout is escalated; it never
creates another worker to replace one whose state is uncertain.

To pause unattended supervision, disable the `Checkpoint Supervisor` workflow
in GitHub Actions. This does not cancel an already-running Cursor worker.

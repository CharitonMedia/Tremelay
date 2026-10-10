# Unattended checkpoint supervision

The assessment model is pinned to Claude Sonnet 5.5 (`claude-sonnet-5-5`), using
adaptive thinking at high effort. Cursor remains the implementer; Codex remains
the independent code reviewer. The supervisor uses Anthropic Workload Identity
Federation (WIF), not an OpenAI API key or a copied personal OAuth session.

## Installation and setup

Installation is disabled by default. This backend has a new release opt-in;
the old OpenAI release value cannot enable it. No account settings, federation
rules, secrets or activation variables are changed by installing this code.

1. Review and merge the adapter with all exact-head checks passing. It runs only
   the deployed `main` workflow; a manual dispatch on another branch is refused.
2. Retain `GOAL_GITHUB_TOKEN` for `pattalkslaw-del` and the existing
   `CURSOR_API_KEY`. These are used by the deterministic controller, never sent
   to Claude. `OPENAI_API_KEY` is neither required nor read; there is no API-key
   or alternate-provider fallback. Existing account credentials are not deleted.
3. Before production use, the owner must authorize the existing Anthropic
   federation rule for the production identity. The successful auth-only test
   covered only `auth-test/anthropic-wif-20261009`; it does not authorize `main`.
   The intended exact production claims are:
   - audience: `https://api.anthropic.com`
   - subject: `repo:CharitonMedia@331478552/Tremelay@1404909620:ref:refs/heads/main`
   - repository_owner: `CharitonMedia`
   - workflow_ref: `CharitonMedia/Tremelay/.github/workflows/checkpoint-supervisor.yml@refs/heads/main`
   Do not add wildcard branches or substitute `job_workflow_ref` for this
   non-reusable workflow. The workflow's `id-token: write` permission is scoped
   to its supervisor job; this permission allows token acquisition, not repository
   writes. Production trust changes require a separate owner action.
4. Open [Checkpoint Supervisor](https://github.com/CharitonMedia/Tremelay/actions/workflows/checkpoint-supervisor.yml),
   choose **Run workflow**, branch **main**, and select **Verify setup and
   Anthropic federation without a model call or restart** (`preflight_only`).
   This verifies existing key presence, GitHub owner identity, and a fresh WIF
   exchange. It does not call Messages, start Cursor, or enable supervision.
   A test-branch-only federation rule is expected to reject this production check.
5. After production preflight and explicit test approval, run the same workflow
   on **main** with only **One small billed Claude connection test; no worker
   launch** (`model_smoke_only`) selected. It sends one fixed synthetic prompt,
   caps output at 256 tokens, validates the model/JSON result, and makes no
   checkpoint, worker, review or budget-marker changes. At published pricing the
   maximum output charge is $0.00256, plus the small fixed input charge; the total
   is expected below one cent, not a guaranteed per-request dollar ceiling. It
   never retries. Do not select preflight and smoke together.
6. After the approved smoke, independent review, and explicit activation
   approval, set repository Actions variable `TREMELAY_SUPERVISOR_ACTIVATION` to
   `claude-wif-v2-5134b392b4a044deae9973b1c8757af2`. This is a public release opt-in
   value, not a credential. It authorizes scheduled/event-triggered assessments;
   do not set it merely because installation or authentication passed.
7. Inspect an actual checkpoint, its worker, and the later exact-head review.
   The tiny smoke establishes model access, not real checkpoint-assessment quality.
   Its `between_tools` thinking mode avoids up-front reasoning; production
   assessments use `adaptive` thinking, which still needs a real checkpoint check.
   Authentication alone is not an inference test.

The owner selected an Anthropic API-credit allowance with overages disabled.
WIF changes authentication, not billing: assessments use that Anthropic workspace's
API credits. Insufficient credit, rate limits, authentication errors, partial
responses and ambiguous network failures stop the assessment without automatic
retry, token refresh, reloading credits, another model, or another billing route.
Cursor worker use still consumes its separate existing Cursor allowance.

## Credential and response boundary

A short-lived isolated Python subprocess receives only GitHub's OIDC request
credentials. It has a clean temporary working directory, no inherited proxy or
provider configuration, no GitHub write token, no Cursor key and no model tools.
It obtains one audience-bound GitHub assertion immediately before one Anthropic
token exchange, then makes at most one Messages request. The assertion and
short-lived Bearer token stay in memory and never enter prompts, files, workflow
outputs, artifacts or logs. Redirects and raw upstream error output are refused.
The controller has a total deadline and kills an unresponsive subprocess group.

Only a completed, exact-model response with locally validated JSON for the exact
reviewed head can resume work. Thinking blocks are discarded, not published.
Unknown output fields, tools, refusals, truncation and missing/invalid usage fail
closed. The existing durable assessment reservation still consumes a checkpoint
on all ambiguous outcomes. No model result is a merge authorization.

See [ADR 0009](adr/0009-claude-wif-checkpoint-assessment.md) for the backend change
and [Anthropic's WIF reference](https://platform.claude.com/docs/en/manage-claude/wif-reference)
for the exchange contract. Preflight prints only allowlisted authentication
metadata; it does not print JWT claims, credential values or provider error bodies.
On failure, it reports only a fixed stage and, for an HTTP rejection, the status
number. A GitHub identity endpoint/acquisition failure occurs before the Anthropic
exchange; an Anthropic token-exchange failure can be compared with the existing
authentication event in Claude Console. A generic failure means no valid safe
diagnostic was available. Do not change federation rules or retry paid assessments
based only on that generic message; checkpoint reservations remain consumed.

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

## Closed goals and manual takeover

The controller now separates receipt recovery from launch eligibility. It reads
all PR states, but only already-recorded workers on closed/goal-removed PRs are
reconciled. Those reads cannot call Claude, create Cursor, request Codex review,
or remove labels. A terminal receipt records the verified current Cursor run;
PR closure, merging, elapsed time and changed heads never prove worker shutdown.
Old accepted receipts with only `completed` or `escalate` are upgraded by service
lookup before they release ownership. Unknown/ambiguous results stay blocking.

Manual dispatch may provide `recovery_pr` plus `recovery_comment` to reconcile
one existing supervisor receipt without any assessment or follow-on work. The
scheduled all-state pass provides the same recovery automatically. No activation,
secret, federation, checkpoint allowance or three-cycle limit changes are needed.

For a manual takeover, retain `human-review-required` and remove `goal`; the stop
label alone intentionally invites this supervisor. Check both supervisor and
ordinary worker receipts and verify terminal status before starting competing
work or merging. See [shared ownership and deployment limits](automation.md#shared-ownership-and-manual-takeover).

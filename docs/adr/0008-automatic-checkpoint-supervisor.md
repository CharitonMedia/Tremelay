# ADR 0008: Automatic review of worker checkpoints

Status: Proposed

## Context

Patrick delegated routine three-cycle stop review to the supervising assistant.
The conversational assistant is not invoked between chat turns. Recording that
delegation alone therefore did not establish unattended supervision. GitHub must
invoke a separate reviewer when the worker loop reaches its checkpoint.

## Decision

Installation and activation are separate. The workflow and controller default
to disabled and require repository variable `TREMELAY_SUPERVISOR_ACTIVATION` to
match this release's public opt-in value, documented in the setup guide. The
fresh version-specific value is not a credential; it avoids accidental activation
from an unknown existing generic boolean setting. No variable is set by this PR.
Activation requires a separate explicit owner decision after service setup and
spending terms are agreed. Ordinary manual dispatch, schedule and workflow-run
events all use the same gate. A manually selected preflight bypasses activation
only to verify key presence and owner identity without a model or Cursor call;
it never changes activation or prints secret/variable values.

`Checkpoint Supervisor` runs trusted code from `main` after completed goal/CI
workflows and on a recovery schedule every fifteen minutes. GitHub scheduling is
best effort, not a fifteen-minute service guarantee. The controller scans open,
non-draft, same-repository goal PRs authored by `pattalkslaw-del`, targeting main,
with an exact Goal-Issue line and `human-review-required`. It does not run PR code.

Use the Responses API model `gpt-6.1-sol`, high reasoning, no tools, structured
output, no stored response, and an 8192-token output limit. Give it the original
goal, exact-head Codex review-body and inline findings, CI state, previous attempts, changed
source files, security documents and ADRs. Reject evidence above 1,000,000 UTF-8
bytes rather than silently omitting source. Repository contents and discussion
are untrusted evidence, never authority to change the controller's rules.
Review-body-only findings qualify for assessment; an empty review, the fixed
Codex wrapper alone, or its canonical clean-review result does not. The complete
original review body is retained in the evidence. Binary or malformed source
content fails that PR closed without stopping the scan of other eligible PRs.

The model returns only `resume` (with a specific corrective approach/tests) or
`escalate` (with a concrete decision requiring Patrick). It cannot merge, issue
tool calls, choose API endpoints, change budgets, set repository secrets, or run
commands. A deterministic controller validates the exact head and newest Codex
review again, durably records the assessment, then directly launches one deterministic Cursor worker with the actual
assessment and correction in its payload. The stop label remains until completion
to block existing review-event launchers. Read-only scheduled reconciliation
recovers the same worker, verifies an advancing descendant commit and requests
independent review. Review requests carry a trusted marker for idempotent recovery.
A model assessment is not an independent clean code review or permission to
merge. Existing exact-head merge gates remain unchanged.

Three unsuccessful worker cycles still require an independent assessment. The
separate total allowance is three automatic model assessments per PR, including
failed/ambiguous reservations: at most three automatically resumed segments.
Only actual checkpoint cases call the model. Routine polling and event handling
make no model call. A budget-exhaustion comment requires Patrick to decide
whether more work is justified. This bounds unattended API/worker use without
asking him to approve every defect. It is not a dollar limit on Cursor usage.
The allowance is deliberately fixed in the trusted workflow; increases require
an explicit owner decision and a reviewed configuration change.

Reserve an assessment in a comment posted by the approved owner token before
calling OpenAI. State markers from other identities do not authorize or consume
supervisor work. Retain reservations after ambiguity; never automatically repeat
an uncertain billed request or worker dispatch. Global workflow concurrency is
serialized and non-cancelling. A stale head/review or active goal job blocks
resumption. A failed durable assessment write cannot remove the stop label.
A completed resume assessment is persisted as `dispatch_ready` before idle
checks; scheduled recovery may retry those checks without another model call.
If its head or newest independent review changes before any dispatch reservation,
the controller durably marks that definitely unlaunched assessment `obsolete`.
Its original assessment and consumed budget remain recorded; a later wake may
assess the new checkpoint within the remaining allowance. A failed obsolescence
write leaves the prior claim active. States with a worker identity or any dispatch
reservation are never retired this way and never permit a replacement create.
The controller reserves dispatch and a stable agent identity only after the idle
gate succeeds. After reservation, it checks the live head/review/stop without
waiting for its own comment-generated goal runs, which cannot launch while the
stop label is held. Reserved creates remain GET-only during recovery, even if
never accepted. Ambiguous creates are reconciled through that identity, never replayed.
A separate launch reservation after the resume marker consumes one worker cycle
even if the create response is lost. Unresolved transport failures remain visible
in Actions; recovery reads can run again without another billed create.
Elapsed time alone never releases worker ownership. A nonterminal worker older
than six hours receives one durable timeout escalation while remaining active.
Newer heads/reviews cannot replace it; later wakes reconcile the same identity
until an actual terminal result is verified.

The supervisor itself cannot silently enable or change secrets. The secret
presence preflight executes no PR code and prints no values. Live operation
requires `OPENAI_API_KEY` and owner-identity `GOAL_GITHUB_TOKEN` with issue/comment,
label and PR-read permissions, and the existing `CURSOR_API_KEY`. No
pull-request-controlled workflow receives these secrets. Preflight runs only
from the deployed default-branch workflow.

## Security and operational consequences

- This is development automation, not a new Tremelay vault or agent secret API.
- Public PR text/code cannot cause arbitrary privileged tool calls from a model.
- A supervisor-produced correction is still subject to the worker's security
  rules, independent Codex review and tests. Never weaken tests to get approval.
- Default-branch execution isolates privileges from candidate code, but the
  model still sees repository material; only the authorized public repository
  is supported by this initial implementation.
- Missing keys, a declined/incomplete model response, incomplete evidence,
  stale state, invalid output or ambiguous network outcomes fail closed.
- Dispatch failure may require reconciliation. This is a real authority/transport
  problem, not an ordinary product defect that demands repetitive permission.
- Fixes to the existing worker workflow must be deployed on main to govern main
  workflow runs. Do not confuse a candidate fix with a deployed fix.
- No automatic merging or new milestone creation is introduced here.

## Validation

Controller tests cover trusted identity/repository eligibility, newest exact-head
review, forged markers, malformed decisions, stale heads, concurrent workers,
input/output bounds, redirect refusal, durable reservation ordering, failed
assessment writes, ambiguous dispatch, escalation and the total allowance.
Regressions also cover review-body-only findings, per-PR binary-evidence failure,
head/review changes before dispatch, failed retirement writes, retained budget,
and refusal to retire a potentially accepted worker.
Activation regressions cover each trigger, reject empty/generic/stale release
values, prevent all service calls while disabled, and verify read-only preflight
without disclosing setup values.
An actual key/model-access check and a real checkpoint resume remain required
before declaring unattended operation verified. Secret presence alone does not
prove model access, API billing or token permissions.

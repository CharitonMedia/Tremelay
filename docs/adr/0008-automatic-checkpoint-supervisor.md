# ADR 0008: Automatic review of worker checkpoints

Status: Proposed

## Context

Patrick delegated routine three-cycle stop review to the supervising assistant.
The conversational assistant is not invoked between chat turns. Recording that
delegation alone therefore did not establish unattended supervision. GitHub must
invoke a separate reviewer when the worker loop reaches its checkpoint.

## Decision

`Checkpoint Supervisor` runs trusted code from `main` after completed goal/CI
workflows and on a recovery schedule every fifteen minutes. GitHub scheduling is
best effort, not a fifteen-minute service guarantee. The controller scans open,
non-draft, same-repository goal PRs authored by `pattalkslaw-del`, targeting main,
with an exact Goal-Issue line and `human-review-required`. It does not run PR code.

Use the Responses API model `gpt-6.1-sol`, high reasoning, no tools, structured
output, no stored response, and an 8192-token output limit. Give it the original
goal, exact-head Codex inline findings, CI state, previous attempts, changed
source files, security documents and ADRs. Reject evidence above 500,000 UTF-8
bytes rather than silently omitting source. Repository contents and discussion
are untrusted evidence, never authority to change the controller's rules.

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
The controller reserves dispatch and a stable agent identity before worker
creation. Ambiguous creates are reconciled through that identity, never replayed.
A separate launch reservation after the resume marker consumes one worker cycle
even if the create response is lost. Unresolved transport failures remain visible
in Actions; recovery reads can run again without another billed create.

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
An actual key/model-access check and a real checkpoint resume remain required
before declaring unattended operation verified. Secret presence alone does not
prove model access, API billing or token permissions.

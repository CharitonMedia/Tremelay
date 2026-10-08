# Build and Review Automation

Tremelay uses Cursor Cloud Agents for implementation and Codex for review. The automation never merges a pull request automatically.

## Required repository Actions secrets

- `CURSOR_API_KEY` — Cursor Cloud Agents API key.
- `GOAL_GITHUB_TOKEN` — fine-grained GitHub token belonging to the human automation identity. It must have sufficient access to this repository to comment on issues/PRs and manage the goal workflow. Codex review requests must not be posted as `github-actions[bot]`.

These secrets are repository configuration and are not stored in the Tremelay source tree.

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
- another segment waits for a documented supervisor assessment on the pull request.

That assessment resumes one bounded segment. It is not an automatic reset. The implementation worker must not post it, remove `human-review-required`, or otherwise authorize its own further cycles. Supervision is not a background process between those assessments. Escalate when the stop needs a product decision, new authority, or a security judgment the recorded review does not settle.

The count must not be reset by rewording the same defect, restarting the workflow, or spawning a fresh agent against the same unresolved PR lineage. A trusted `<!-- tremelay-human-resume -->` comment is the only segment boundary.

## One worker per review

A Codex review arrives as a review event, one or more inline comments, and a summary comment. Those events share one launch claim: `review id` plus the full reviewed head. The trusted automation identity posts that claim before it creates a cloud agent. The claim comment includes the stable marker and the cycle-count phrase, so the circuit breaker counts the reservation itself. Updating that comment with the agent URL has to succeed before the job continues. If that update fails, the job stops and the original comment still counts; it does not drop the cycle or allow a second worker. Cancellation after the worker is accepted, or while the create call has not settled, keeps the claim. A definitive client rejection (HTTP 4xx) deletes the claim so a later event can launch. An HTTP 5xx or any other non-definitive status keeps the claim and therefore keeps the cycle count. A different head is a different claim.

`pull_request_review`, `pull_request_review_comment`, and `issue_comment` run the workflow file and the checked-out scripts from the default branch. This dedupe is inactive until that change is on `main`. Merging the pull request is what deploys it. The circuit breaker, trusted identity, exact-head review, no-op stop, and the ban on automatic merge stay in place.

## CI

Tremelay runs general Go CI plus dedicated `Test Linux` and `Test Windows` workflows used by exact-head review orchestration. CI also verifies the pinned Ponytail Cursor rule, compiles the Python automation helpers, and runs `goal_agent_request.py self-check`.

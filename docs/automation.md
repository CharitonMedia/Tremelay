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
- a human must review the approach before additional agent work.

The count must not be reset by rewording the same defect, restarting the workflow, or spawning a fresh agent against the same unresolved PR lineage.

## CI

Tremelay runs general Go CI plus dedicated `Test Linux` and `Test Windows` workflows used by exact-head review orchestration. CI also verifies the pinned Ponytail Cursor rule and compiles the Python automation helpers.

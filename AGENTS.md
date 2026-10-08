# Instructions for Coding Agents

Tremelay is security infrastructure. Correct security boundaries matter more than implementation speed or convenience.

## Read first

Before changing credential, authorization, network, audit, identity, cryptographic, or agent-facing code, read:

- `VISION.md`
- `SECURITY_INVARIANTS.md`
- `THREAT_MODEL.md`
- `ARCHITECTURE.md`
- relevant ADRs

## Non-negotiable rules

1. Never add an agent-facing raw-secret retrieval path as a shortcut.
2. Security invariants outrank implementation convenience.
3. Deny by default.
4. Every attempted credential-backed operation must be auditable.
5. Never place raw credentials in logs, errors, traces, analytics, fixtures, or committed test data.
6. Do not invent cryptography.
7. Do not weaken or delete security tests merely to make CI pass.
8. Changes affecting trust boundaries require an ADR.
9. If a goal conflicts with the threat model or security invariants, stop implementation of that portion and document the conflict.
10. Prefer the smallest implementation that satisfies the acceptance criteria.
11. Automated build/review remediation is limited to three cycles for the same problem or PR head lineage. After three unsuccessful Cursor↔review cycles, stop automation. Another segment requires a documented supervisor assessment. The implementation worker must not authorize its own further cycles.

## Three-cycle stop rule

The three-cycle limit is a hard guardrail against runaway agent churn.

- A cycle means one implementation/remediation attempt followed by automated review or verification that identifies unresolved work.
- Count cycles against the same underlying problem and pull-request head lineage; do not reset the count by rephrasing the issue, editing comments, restarting a workflow, or spawning a new agent for the same unresolved defect.
- After cycle 3, automation MUST stop rather than launch another implementation agent.
- The system MUST leave a clear status comment summarizing: the unresolved problem, the three attempts made, the latest reviewed commit, relevant CI/review findings, and that another cycle requires a documented supervisor assessment.
- A supervisor may assess a routine stop and resume one bounded segment of at most three cycles. That assessment is an explicit pull-request comment. It is not an automatic reset, and the implementation worker must not grant it to itself. Do not describe supervision as running unattended between those assessments. A comment that requests a longer or unattended window does not raise the three-cycle cap.
- Escalate only when the stop needs a product decision, new authority, or a security judgment the recorded review does not settle.
- The stop rule applies even if more automated remediation appears possible.
- Security incidents or evidence of architectural drift may stop automation earlier than three cycles.

## Required Cursor rule

Cursor implementation agents MUST operate with the repository-pinned Ponytail rule at `.cursor/rules/ponytail.mdc`. The rule is always-on for Cursor and is verified by CI.

Ponytail's minimalism applies only after Tremelay's security invariants, threat model, milestone acceptance criteria, auditability, and required tests are satisfied. Security controls, validation, adversarial testing, and required error handling are not optional simplifications.

## Development method

For each milestone:

1. Restate the security-relevant acceptance criteria.
2. Identify threat-model sections touched by the work.
3. Implement the smallest coherent vertical slice.
4. Add positive, negative, and adversarial tests.
5. Run all tests and static checks.
6. Document consequential architectural choices in an ADR.
7. Do not declare the milestone complete until its acceptance criteria are demonstrated by tests or documented manual verification.

## Dependencies

Prefer mature, widely used dependencies with active maintenance. New dependencies affecting cryptography, authentication, authorization, network proxying, parsing of untrusted data, or persistent secrets require explicit justification in the PR/ADR.

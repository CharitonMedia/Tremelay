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

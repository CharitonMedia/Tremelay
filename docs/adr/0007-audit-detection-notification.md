# ADR 0007: Audit views, detection, and notification

Status: Accepted

## Context

M1–M4 already append a secret-free hash-chained row for every credential, grant, and broker attempt ([ADR 0003](0003-custody-audit-hash-chain.md), [ADR 0004](0004-agent-capability-grants.md), [ADR 0006](0006-http-request-policy.md)). M5 has to make that history reviewable, distinguish suspicious results from ordinary denials, and notify the vault owner without a new secret path. It does not add credential-health checks, rotation, or an external chat/email service.

The version-1 and version-2 preimages stay as published. Classification of those rows is a function of the action and result already inside the hash, plus a count of broker denials in the chain. Notification and containment are new decisions, so their class and the sequence they point at have to be authenticated.

## Decision

Risk class and severity are fixed codes. The mapping is:

- `allowed`, `completed`, `upstream_error` — `routine` / `info`
- ordinary denials (`denied`, `denied_agent`, `denied_credential`, `denied_operation`, `denied_scope`, `denied_expired`, `denied_missing`, `denied_destination`, `denied_malformed`, and a second `grant_revoke`) — `expected_denial` / `low`
- `denied_origin` — `origin_mismatch` / `high`
- `denied_method`, `denied_path`, `denied_action` — `policy_violation` / `high`
- `denied_ssrf` — `ssrf` / `critical`
- `denied_redirect` — `redirect_escape` / `critical`
- `denied_abuse` — `rate` / `high`
- `denied_destructive` — `destructive` / `high`
- `denied_revoked` on `broker_http` or `capability_authorize` — `replay` / `high`
- `denied_secret` — `secret_probe` / `high`
- three or more broker denials for the same agent inside the lookback, when the row would otherwise be `expected_denial` — `repeated_denial` / `high`
- `notify` and `contain` — `notice` / `info`, which does not raise another alert
- a result outside this set — `audit_tamper` / `critical`

`denied_destination` stays an ordinary denial. ADR 0006 already treats an unconfirmed lookup as different from SSRF. `denied_secret` is produced only when the operation is the closed token `get_secret`. That token is not copied into the row. Any other unknown operation stays `denied` with empty identity fields.

Detection state is the audit chain plus a mirror stored in the encrypted document. The mirror counts broker denials per agent over the last 32 broker rows for that agent, and it keeps at most 256 agents. It stores agent ids and counts, never secrets, URLs, or caller strings. On unlock and on `audit verify`, the mirror must match a fresh count of the chain. A missing, negative, oversized, or suppressed count fails closed. The mirror is written in the same transaction as the audit row that changes it. An attacker cannot clear the count and keep a successful verify, and cannot drop the underlying rows without breaking the chain.

`Session.AuditHistory` and `Session.AuditBySeq` are the human views. They require an unlocked session, re-check the chain and the mirror, and return fixed fields plus the derived class. Filters are credential id, agent id, action, class, inclusive time bounds, and an exclusive sequence cursor. The page size defaults to 50 and caps at 100. The views do not append a row and do not return credential plaintext. `AgentPrincipal` does not grow a view, a notifier, or a containment method. `audit verify` still does not append.

High and critical rows can notify. The payload is severity, class, timestamp, agent id, credential id, grant id, action, result, audit sequence, and audit hash. It has no URL, header, body, or secret. `MemoryNotifier` is the in-process sink. A nil notifier means delivery is not configured: the security row is still durable, and no failure row is invented.

Delivery failure appends `notify` / `failed` and does not copy the sink's error text into the audit row or the process log. Each source sequence is attempted at most twice. A second `DeliverPending` call does not send again after that. One call sends at most eight alerts. `notify` / `delivered` is written only after the sink returns nil. The security row is committed before either outcome, so a sink failure cannot remove it.

Containment is chosen by `ResponsePolicy` before the event, not by the agent. The policy and the notifier are process-local, same as the M4 abuse hook: they are not written into the vault, and a new process starts at notify-only with no sink. The zero value notifies only and does not mutate grants or agents. `ContainFlag` appends `contain` / `flagged` and does not notify. `ContainSuspendGrant` revokes the grant id on that event and no other grant; a missing or already-revoked grant appends `flagged` or `unchanged` and does not pick a substitute. `ContainSuspendAgent` sets that one agent to `suspended`. A suspended agent fails later authorize and broker decisions as `denied_agent`, which is an ordinary denial, so the suspension does not notify again. `DestructiveDeny` refuses `DELETE` after the grant matches and before DNS or the credential copy, with result `denied_destructive`. The zero value still allows a granted `DELETE`.

Notification and containment rows use audit version 3. The preimage is the version-2 preimage plus a length-prefixed class and the referenced sequence as a uint64. Version-1 and version-2 rows must keep class empty and the reference zero; a value there fails verification. The referenced sequence must be an earlier row. The SQLite audit table stores `v`, `class`, and `ref_seq`. A version other than 1, 2, or 3 fails verification. The authenticated audit head is unchanged: external checkpointing still compares that head, and rewriting it onto a shorter chain still fails decryption.

## Alternatives considered

- **Store the class on every existing row by extending the version-2 preimage.** Rejected. That would invalidate the published version-2 hash and the M1 vector.
- **Put the class in `result` or `operation`.** Rejected. Those fields already have closed meanings. A second code stuffed into them would be ambiguous and could copy caller text.
- **Keep detection only in a plaintext counter.** Rejected. A counter outside the encrypted document can be cleared without breaking the hash chain. The chain remains the source of the count, and the mirror is authenticated with the credential state.
- **Notify from `audit verify` when the chain fails.** Rejected. ADR 0003 says verify does not append. A broken chain is not a place to write a new trusted row. The operator-visible result is `ErrAudit`.
- **A required email or chat transport.** Rejected for this milestone. The notifier interface is the boundary. A hosted sink can be added later without changing the payload.

## Security implications

- Agent principals still cannot retrieve a secret, list the audit chain, set the notifier, or change containment.
- Ordinary denials stay distinct from SSRF, redirect escape, policy mismatch, replay of a revoked capability, secret-probe attempts, repeated broker denials, rate vetoes, and destructive-method denials.
- A high-risk row remains in the chain when notification fails. The failure row cannot raise another alert.
- Containment changes one named grant or one named agent, in the same transaction as its audit row.
- Audit views, notification payloads, containment rows, and delivery errors do not gain a plaintext path for the credential or for caller-controlled resource strings.
- Version-1 and version-2 verification is unchanged. A version-3 class or reference that does not match the hash fails verification.

## Consequences

- Operators inspect history with `audit list` and `audit get` after the passphrase check. `audit verify` still prints the chain tip.
- A process that wants alerts sets a `Notifier`. The default policy does not revoke grants or suspend agents.
- M6 can add health events under a later audit version without redefining version 3.
- The detection ceiling is 256 agents and 32 broker rows of lookback per agent.

## Tests

- The classification table covers the codes above, including the repeated-denial threshold and a counter that does not match the chain.
- Version-3 linkage detects content changes, deletion, reordering, insertion, a forged hash, a forged previous link, an unknown version, a version-2 notice, and a changed class or reference.
- Rewriting the authenticated head onto an earlier sequence fails verify. A stored version of 9 and a deleted middle row fail the chain read.
- A notifier receives the high-risk class and the audit sequence. `AuditBySeq` returns that row only when the hash matches.
- A failing sink leaves the security row in place, records `notify` / `failed`, and stops after two attempts. The sink error is absent from the audit row, the view, and the log.
- Suspending a grant revokes that grant only. Suspending an agent leaves every other agent active. Flag does not notify. The default policy does not revoke a grant.
- A sentinel secret, a sink error that is not a stored secret, and the `get_secret` token are absent from audit rows, notification JSON, containment rows, and the audit view.

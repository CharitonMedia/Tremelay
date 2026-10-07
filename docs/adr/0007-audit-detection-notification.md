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
- three or more broker denials for the same agent inside the lookback, when the row would otherwise be `expected_denial` — `repeated_denial` / `high`. A `denied_agent` row whose agent already has an earlier `contain` / `agent_suspended` row stays `expected_denial` / `low` for every later call, including after that triggering row leaves the lookback. The row is still audited and still increments the detection mirror. `denied_agent` from an agent with no such row, including an active agent that has no matching grant, still promotes. A grant suspension (`contain` / `suspended`) does not suppress that promotion. High-risk rows that precede the suspension keep their class
- `notify`, `contain`, and `respond` — `notice` / `info`, which does not raise another alert
- a result outside this set — `audit_tamper` / `critical`

`denied_destination` stays an ordinary denial. ADR 0006 already treats an unconfirmed lookup as different from SSRF. `denied_secret` is produced only when the operation is the closed token `get_secret`. That token is not copied into the row. Any other unknown operation stays `denied` with empty identity fields.

Detection state is the audit chain plus a mirror stored in the encrypted document. The mirror counts broker denials per agent over the last 32 broker rows for that agent, and it keeps at most 256 agents. Past that ceiling it drops the agents whose latest broker row is oldest. It stores agent ids and counts, never secrets, URLs, or caller strings. Every seal writes the `detection` member, including when the count is empty. On unlock and on `audit verify`, a document that contains that member must match the retained count of the chain. A negative, oversized, or suppressed count fails closed: omitting a retained agent, adding an evicted one, or listing more than 256 agents fails verification. A document sealed before M5 has no `detection` member. After that ciphertext authenticates, the mirror is taken from the chain so the vault can open; the next commit writes the member. That absence is not a suppressed count, and a later document cannot drop the member and still verify. Repeated-denial classification still reads the full chain, so an evicted subject stays visible in the audit view. The mirror is written in the same transaction as the audit row that changes it. An attacker cannot clear a retained count and keep a successful verify, and cannot drop the underlying rows without breaking the chain.

`Session.AuditHistory` and `Session.AuditBySeq` are the human views. They require an unlocked session, re-check the chain and the mirror, and return fixed fields plus the derived class. Filters are credential id, agent id, action, class, inclusive time bounds, and an exclusive sequence cursor. The page size defaults to 50 and caps at 100. The views do not append a row and do not return credential plaintext. `AgentPrincipal` does not grow a view, a notifier, or a containment method. `audit verify` still does not append.

High and critical rows can notify. The payload is severity, class, timestamp, agent id, credential id, grant id, action, result, audit sequence, and audit hash. It has no URL, header, body, or secret. `MemoryNotifier` is the in-process sink. A nil notifier means delivery is not configured: the security row is still durable, and no failure row is invented.

The notification choice is an authenticated `respond` row committed with the security event. Its result is the fixed code `notify` or `flag`. `DeliverPending` reads that row and does not read the session's current policy, including after a policy change or a reopen. A `flag` decision stays flag-only. A `notify` decision keeps the two-attempt cap. A high-risk row sealed before `respond` existed has no decision row. That absence is not filled in from the current policy. If such a row already has a `notify` row, delivery was chosen and the same cap applies. Otherwise it is not delivered.

Before the sink is called, the vault appends `notify` / `attempted`. That row is the attempt. If it cannot be written, the sink is not called. Delivery failure then appends `notify` / `failed` and does not copy the sink's error text into the audit row or the process log. Each source sequence has at most two `attempted` rows. A later `DeliverPending` call does not send again after that. One call sends at most eight alerts. `notify` / `delivered` is written only after the sink returns nil. The security row is committed before either outcome, so a sink failure cannot remove it. A crash after the sink returns and before the outcome row still counts the attempt, so retries cannot exceed two.

Containment is chosen by `ResponsePolicy` before the event, not by the agent. The policy and the notifier are process-local, same as the M4 abuse hook: they are not written into the vault, and a new process starts at notify-only with no sink. The zero value notifies only and does not mutate grants or agents. `ContainFlag` appends `contain` / `flagged` and records `respond` / `flag`. `ContainSuspendGrant` revokes the grant id on that event and no other grant; a missing or already-revoked grant appends `flagged` or `unchanged` and does not pick a substitute. `ContainSuspendAgent` sets that one agent to `suspended` and appends `contain` / `agent_suspended`. Grant suspension still appends `contain` / `suspended`. Suspend policies record `respond` / `notify`. The security event, the `respond` row, the containment row, and the grant or agent mutation commit in the existing SQLite and encrypted-document transaction. A storage failure rolls that whole transaction back, so a suspension trigger is not durable while its target stays active, and the broker does not treat the attempt as complete. Notification transport stays outside the transaction: the sink is called only after the attempt row commits.

A suspended agent fails later authorize and broker decisions as `denied_agent`, which stays `expected_denial` / `low`, so the suspension does not notify again. That holds for as many follow-up broker calls as the agent sends. The mirror count is unchanged by this rule. The broker checks that suspension before it classifies the destination, so a later special-use, malformed, or wrong-origin target stays `denied_agent` instead of another critical or high event. Authorize checks the same suspension before secret-probe classification, so `get_secret` from a suspended agent is `denied_agent` and the token is not stored. `DestructiveDeny` refuses `DELETE` after the grant matches and before DNS or the credential copy, with result `denied_destructive`. The zero value still allows a granted `DELETE`.

Notification, containment, and response rows use audit version 3. The preimage is the version-2 preimage plus a length-prefixed class and the referenced sequence as a uint64. Version-1 and version-2 rows must keep class empty and the reference zero; a value there fails verification. The referenced sequence must be an earlier row. `respond` is a version-3 action. Its result is only `notify` or `flag`. The authenticated audit head remains the chain tip, which may be the response or containment row from that same transaction. The SQLite audit table stores `v`, `class`, and `ref_seq`. A vault created before those columns exist gets them on open, along with `agent_id`, `grant_id`, and `operation` when those are absent. Existing rows are backfilled with an empty class and a zero reference. `v` is 2 for capability actions and 1 otherwise. The hash preimage is not rewritten. A version other than 1, 2, or 3 fails verification. The authenticated audit head is unchanged: external checkpointing still compares that head, and rewriting it onto a shorter chain still fails decryption.

## Alternatives considered

- **Store the class on every existing row by extending the version-2 preimage.** Rejected. That would invalidate the published version-2 hash and the M1 vector.
- **Put the class in `result` or `operation`.** Rejected. Those fields already have closed meanings. A second code stuffed into them would be ambiguous and could copy caller text.
- **Keep detection only in a plaintext counter.** Rejected. A counter outside the encrypted document can be cleared without breaking the hash chain. The chain remains the source of the count, and the mirror is authenticated with the credential state.
- **Notify from `audit verify` when the chain fails.** Rejected. ADR 0003 says verify does not append. A broken chain is not a place to write a new trusted row. The operator-visible result is `ErrAudit`.
- **Apply containment in a second transaction after the security event.** Rejected. A failed second write leaves the triggering row durable and the grant or agent active. The event, the response decision, and the suspension are one transaction. The sink stays outside it so a delivery failure cannot roll the event back.
- **Let `DeliverPending` read the current response policy.** Rejected. A later change to notify would send an alert a flag decision had suppressed, and a later change to flag would drop retries that were already chosen.
- **A required email or chat transport.** Rejected for this milestone. The notifier interface is the boundary. A hosted sink can be added later without changing the payload.

## Security implications

- Agent principals still cannot retrieve a secret, list the audit chain, set the notifier, or change containment.
- Ordinary denials stay distinct from SSRF, redirect escape, policy mismatch, replay of a revoked capability, secret-probe attempts, repeated broker denials, rate vetoes, and destructive-method denials.
- A high-risk row remains in the chain when notification fails. The failure row cannot raise another alert.
- Containment changes one named grant or one named agent, in the same transaction as the triggering security event and the `respond` row. A failed transaction leaves neither the trigger nor the suspension durable.
- `DeliverPending` follows the recorded `respond` decision. Changing the process policy does not notify a flag-only event or suppress retries for a notify event.
- A suspended agent's later `get_secret` authorize call is an ordinary `denied_agent`, not another secret-probe alert.
- A suspended agent's later broker `denied_agent` rows stay `expected_denial` / `low` and do not notify, including after the lookback no longer contains the triggering event. The mirror still counts those denials. An active agent's repeated `denied_agent` rows still become `repeated_denial`. The triggering high-risk row keeps its class.
- Audit views, notification payloads, containment rows, and delivery errors do not gain a plaintext path for the credential or for caller-controlled resource strings.
- Version-1 and version-2 verification is unchanged. A version-3 class or reference that does not match the hash fails verification.
- Opening an older vault adds the audit columns and does not rewrite version-1 or version-2 hashes. A pre-M5 document with no `detection` member takes its mirror from the chain after authentication. A document that already contains the member cannot drop a retained count.

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
- A failing sink leaves the security row in place, records `notify` / `attempted` before the sink runs and `notify` / `failed` after it returns, and stops after two attempts. If the attempt row cannot be written, the sink is not called. If the outcome row cannot be written, a later delivery still stops at two attempts. The sink error is absent from the audit row, the view, and the log.
- Suspending a grant revokes that grant only. Suspending an agent leaves every other agent active. Flag does not notify. The default policy does not revoke a grant.
- A failed event transaction leaves no suspension-trigger row and leaves the target active. A later write failure, after the event and the suspension have committed, still shows the target suspended on reopen. Policy changes in both directions, including across reopen, keep a recorded flag decision silent and still retry a recorded notify decision within the two-attempt cap.
- Three `get_secret` authorize calls after agent suspension stay `denied_agent` and do not add alerts. A chain with no `respond` row is not delivered from the current policy; an existing `notify` row on that chain still counts as a chosen delivery.
- After `ContainSuspendAgent`, more follow-up `BrokerHTTP` calls than the lookback, plus `get_secret` authorize calls, stay audited `denied_agent` / `expected_denial` and add no response or alert. Reopen and `DeliverPending` do not notify them. The mirror still counts those broker denials. An active agent's repeated `denied_agent` still becomes `repeated_denial` and notifies.
- A sentinel secret, a sink error that is not a stored secret, and the `get_secret` token are absent from audit rows, notification JSON, containment rows, and the audit view.
- An M1 audit table and an M4 audit table open, verify, and accept a later denial after the columns are backfilled. The stored hash of the original row is unchanged.
- An authenticated pre-M5 document whose chain contains a broker denial opens and verifies. The next commit writes the mirror. Re-sealing that document with an empty `detection` member still fails.
- The 257th distinct broker-denial subject is audited. The mirror keeps 256 subjects and drops the least recently active one. A mirror that drops a retained subject still fails.

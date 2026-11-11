# ADR 0028: Owner alerts from the daemon

Status: Accepted pending owner veto

## Context

ADR 0007 gave the vault a notifier, a response policy, an abuse guard and a
containment step. No command installed any of them. A review of v1.0.3
(finding 4) found that high-risk events were written to the audit chain and
nobody was told. The same review found three faults in the dormant parts:
containment blamed an agent for a redirect on the granted origin and for a
resolver's answer (finding 13), a suspended agent could not be reinstated
(finding 14), and alerts had no bound (finding 15).

The owner decided on 2026-11-11: alerts go to a command the owner names,
there is no breach lookup, and nothing is suspended automatically.

## Decision

### 1. `tremelay daemon --alert-command /absolute/path`

When the flag is set the daemon installs a notifier. Each high-risk event the
daemon commits (severity `high` or `critical` in ADR 0007's table) is handed
to the owner's command.

- The command is executed directly, with no shell and no arguments. The path
  must be absolute and name an executable regular file, checked before the
  passphrase is asked for.
- It receives one JSON object per line on stdin. Each is the secret-free
  `Notification` of ADR 0007: severity, class, time, agent, credential and
  grant ids, action, result, and the sequence and hash of the audit row. It
  holds no URL, header, body, token or secret.
- Its environment is the daemon's without `TREMELAY_PASSPHRASE`.
- Its stdout, stderr and exit text are never echoed. A failed or timed-out
  run prints one fixed line on the daemon's stderr.

This is a trust-boundary change: the daemon now starts a process. The process
runs as the owner, is named by the owner on the daemon's own command line,
and is given only data the audit chain already holds. The daemon still makes
no network call for alerting; the command may.

### 2. Alerts are batched and bounded (finding 15)

The vault calls the notifier from inside an agent's request. The notifier
only queues. A separate goroutine runs the command, at most once every 30
seconds, with everything queued since the last run, and a run is ended after
30 seconds. The queue holds 100 alerts. An alert that finds it full is
refused, the vault audits that as `notify` / `failed`, and the next run ends
with a `{"dropped":N}` line. When the daemon locks, what is queued gets one
last run of at most 5 seconds.

A flood of probes therefore costs the owner two runs a minute, not one
process and one message per probe.

Limits, stated plainly:

- `notify` / `delivered` in the audit chain means the alert entered the
  daemon's queue. Whether the command then succeeded is on the daemon's
  stderr only.
- Each alert still costs up to three audit rows beside its source row (the
  decision, the attempt, the outcome), as ADR 0007 designed.
- Only events the daemon commits are alerted. A row another process wrote,
  such as a human CLI command, is not. Rows that were high-risk before the
  flag was first used are not replayed.
- `tremelay mcp` without `--daemon` has no alert command.

### 3. An alert names an agent only for what the agent did (finding 13)

This changes two results that ADR 0006 fixed.

- **Resolver answers.** A granted name that resolves to a non-public address,
  a mixed answer set, or a dial that would leave the pinned address is now
  `denied_destination`, the result ADR 0006 already uses for a lookup that
  cannot be confirmed. The agent asked for exactly what its grant names; the
  answer came from the resolver. `denied_ssrf` (`ssrf` / `critical`) is kept
  for a target the agent itself wrote: a literal address, or a name in a
  special-use form.
- **Redirects that stay on the origin.** A 3xx whose `Location` resolves to
  the scheme and host the request was sent to is still not followed, and now
  ends as `upstream_error`. GitHub answers a renamed repository with a 301 to
  the same host. A 3xx with no `Location`, including 304, is `upstream_error`
  too. `denied_redirect` (`redirect_escape` / `critical`) is kept for a 3xx
  that names another scheme, host or port.

No redirect is followed in any case, and the credential is offered to no
second hop. What changed is which refusals page the owner.

The agent-visible error follows the result: `denied_destination` and the
generic upstream failure, where it used to read `denied_ssrf` and
`denied_redirect`.

Accepted residual: an owner who grants a credential to a name an agent
controls no longer gets an `ssrf` alert when that name is pointed at a
private address. The request is still refused and audited. An agent that
controls the granted name already receives the credential on every allowed
call.

### 4. Not built

- **Automatic containment.** No command sets a response policy, so the
  library's suspend-grant and suspend-agent steps stay unreachable.
- **Reinstating a suspended agent (finding 14).** With no containment, no
  shipped build can suspend an agent, so there is nothing to reinstate.
  Suspension is derived from the audit chain (ADR 0007), so reinstatement is
  a change to that derivation and must be built together with any command
  that turns containment on.
- **Breach lookup.** No checker is installed. `credential policy
  --compromise-opt-in true` says so.
- **The abuse guard.** Logins and frames are paced before they are audited
  (ADR 0024, amendment of 2026-11-11). No veto hook is installed.

## Consequences

- An owner who sets the flag is told about secret probes, origin mismatches,
  agent-written SSRF targets, cross-origin redirects, method and path
  violations, use of a revoked grant, repeated denials, and audit failures.
- Chains written by this version use `denied_destination` and
  `upstream_error` where earlier versions wrote `denied_ssrf` and
  `denied_redirect` for the two cases above. Both results already existed, so
  earlier versions verify these chains.

## Tests

`TestDaemonAlertCommandReceivesHighRiskEvents`,
`TestAlertSinkBatchesAndReportsDrops`,
`TestAlertCommandMustBeAnAbsoluteExecutable`,
`TestAlertEnvDropsThePassphrase`,
`TestUpstreamAndResolverFaultsDoNotAlert`, and the updated expectations in
`TestBrokerDNSPinAndProxy`, `TestBrokerRedirectsDoNotInherit`,
`TestBrokerHTTP` and `TestMCPNetworkBrokerDestinationDenials`.

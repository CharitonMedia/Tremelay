# ADR 0010: Credential health and lifecycle

Status: Accepted

## Context

M1 stores lifecycle timestamps on each credential but does not evaluate them. `Put` only creates a credential. Password strength, reuse, compromise lookup, refresh, and rotation reminders are not implemented. M5 already notifies from an audit row without putting a secret in the alert ([ADR 0007](0007-audit-detection-notification.md)).

Health has to be checked when a secret is added or replaced, and again when a human asks. It must not become an agent-facing probe, a second secret index, or a reason to rotate or revoke on its own.

## Decision

Health lives in the encrypted credential document, next to the secret it describes. A missing `health` member means the credential has not been assessed. Unlock does not invent a healthy result.

Each stored assessment records the credential generation, the assessment time, a sorted set of fixed finding codes, a compromise status, a strength status, and any explicitly unsupported checks. The generation increments only when the secret bytes change. An identical replacement keeps the generation and `UpdatedAt`, so a known match for those bytes survives a later checker failure. A different value drops prior-value evidence. The first assessment of an older credential assigns generation 1 to the bytes already stored. That assignment is not a rotation: unchanged bytes keep their `UpdatedAt`.

Findings that can be true at the same time are `weak`, `reused`, `compromised`, `expired`, `review_due`, `rotation_due`, and `rotation_overdue`. Empty findings are not a health verdict. `evidence` is `unassessed`, `partial`, or `complete`. Complete means the applicable checks finished. It does not mean the credential is safe.

Compromise status is one of `match`, `clear`, `not_checked`, `unavailable`, or, at read time only, `stale`. A `clear` result means that checker returned no match for that prefix at that time. A `match` is kept for the same generation when a later lookup fails, times out, or returns a malformed body, and when the assessment is older than the freshness window. A failed lookup does not become `clear`. `stale` is how a fresh read presents an old `clear`. It is not stored, and it does not replace a `match`.

The session clock is the only time base for expiry, review, rotation, and freshness. Agent calls have no time argument and no health methods.

### Password strength

The heuristic is a fixed list of common passwords, ASCII case-folding at check time, keyboard walks, sequential runs, contiguous repeated-byte runs, and repeated blocks. Sequential and repeated-byte runs use the pattern-run threshold, including a run that has a different prefix or suffix. Length below the configured minimum is weak. Character-class counts are not treated as strength. The stored bytes are not lowercased, normalized, or truncated.

The scan reads at most 8192 bytes. A longer secret is stored whole and reported `unassessed` with unknown code `strength_bounded`. The list is not a breach corpus and not a general dictionary. Non-ASCII passwords are not matched against that list.

Configurable thresholds are minimum length (default 12, allowed 8–128), pattern-run length (default 6, allowed 3–64), freshness (default 24h), and reminder lead (default 7 days; zero means no early reminder).

### Reuse

Identical password bytes on two different password credentials produce `reused` on each. The comparison excludes the credential itself. Adding or replacing a password rewrites the finding on every password whose reuse bit changes. The comparison is in memory at assessment time. No password index, hash, or fingerprint is sealed or logged.

ponytail: the compare is pairwise. Upgrade path: a session-only map wiped on lock and never written into the document.

### Compromise lookup

No lookup runs unless a human sets `compromise_opt_in` and the process has a `CompromiseChecker`. Both start off. The checker is process-local, like the M5 notifier. It is not part of the vault. A restart has no checker until one is installed again. Opt-in alone does not dial anything. This binary does not contain a provider client.

The checker receives `Algorithm: sha256` and a 5-hex-character prefix of SHA-256 over the exact secret bytes. It does not receive the password, the rest of the hash, the credential id, or the vault id. It returns lowercase hex suffixes. The vault compares those suffixes locally. More than 1024 suffixes, a wrong length, uppercase, or a non-hex suffix makes the whole response `unavailable`. Checker errors are dropped. The prefix is not written to the audit row or the process log.

A checker that calls back into the vault and commits changes the audit sequence. The in-flight result is discarded with `ErrConflict`, whose text is fixed, and the outer attempt is recorded as a fixed denial against the current vault state. The planned secret, health, and policy are not committed. A delayed match cannot land on a replacement.

An external checker is not implemented here. One added later must speak this prefix protocol, use HTTPS, refuse redirects, bound the request and the response, and keep the prefix out of logs. The destination and the exact transmitted fields are the algorithm name and the 5-hex prefix. The residual limit is that the checker learns that 20-bit prefix and nothing else about the vault.

### Lifecycle

Explicit `ExpiresAt`, `ReviewDueAt`, and `RotationDueAt` win over intervals. `RotationEvery` and `ReviewEvery` apply only while the matching explicit timestamp is unset. Zero disables that interval. Rotation intervals are measured from `UpdatedAt`. Review intervals are measured from `CreatedAt`. A replacement that changes the secret bytes updates `UpdatedAt` and therefore moves an interval-based rotation due time. An identical replacement, including the first generation assigned to unchanged pre-assessment bytes, does not. Neither kind of replacement moves an explicit timestamp or a review interval. Expiry has no early reminder. Review uses the reminder lead as the start of `review_due`. Rotation uses the lead for `rotation_due` and becomes `rotation_overdue` at the due instant. The due instant itself is overdue, not merely due.

There is no type or service field on replace. Grants keep their credential id, class, and resource. Health does not revoke, rotate, or widen a grant. Credential state stays `active`.

### Refresh

`RefreshHealth` is the only repeat. It is human-called, uses the session clock, and runs only on an unlocked session. A locked vault or a stopped process keeps the last sealed assessment and does not evaluate. The default freshness is 24 hours. A human who wants assessments inside that window unlocks and refreshes. Nothing in this milestone starts a daemon or leaves the vault unlocked.

A refresh that does not change findings appends one `health_refresh` / `unchanged` row for a single credential, or one vault-level unchanged row when a full sweep changes nothing. It does not append another notification.

### Audit and notification

`credential_put`, `credential_get`, and `credential_list` stay version 1. Health operations use audit version 4. The version-4 preimage is the version-1 preimage plus a length-prefixed canonical reason list and the credential generation as a uint64. Version-1, version-2, and version-3 preimages are unchanged. Older databases gain `reasons` and `cred_gen`, defaulting empty and zero. Existing hashes are not rewritten. Version-3 notice rows leave both columns empty. Verification and human reads reject a notice row that carries either column, because those values are outside the version-3 preimage.

The latest `health_assess` or `health_refresh` row for a credential must match the stored generation and findings. A legacy credential has neither. A mismatch fails unlock and verify.

The credential change, the health rows for every credential whose findings changed, the policy row when policy changes, and any `respond` / `notify` decision commit in one SQLite transaction. A fault leaves the previous secret, health, policy, and audit chain.

Actionable health rows record `respond` / `notify` with class `health`. That class is delivered with M5's reservation, two-attempt cap, and batch of eight. Containment policy is not applied. A nil notifier leaves the decision row and does not invent `notify` / `failed`. A sink failure does not roll back the health row. The notification carries the audit sequence and hash, plus the fixed reason list. It has no secret, prefix, or checker text.

A finding that was already present for the same generation does not notify again. A new generation notifies when the new assessment has any finding. Removing a finding is audited and not notified.

Human reads are `health_get` and `health_list` at audit version 1. `AgentPrincipal` does not gain those methods, a checker, a clock, or a policy setter.

## Alternatives considered

- **Store a password hash index in the document.** Rejected. That is a reusable fingerprint at rest.
- **Call a hosted breach API by default.** Rejected. Lookup is opt-in, provider-independent, and local in this milestone.
- **Fold health into the version-3 notice preimage.** Rejected. ADR 0007 leaves version 3 for notification rows and says a later version can carry health.
- **Treat health as high risk inside `withResponse`.** Rejected. That would suspend grants under the containment policy. Health is advisory.
- **Run a background refresh against an unlocked vault.** Rejected. The human unlocks, refreshes, and locks.

## Security implications

- Agents still cannot read a secret, read health, set the checker, or choose the evaluation time.
- A confirmed compromise survives checker failure and age until the secret generation changes.
- Checker errors and caller-supplied ids are not audit fields.
- The only data a checker can observe is a 20-bit hash prefix.
- Version-1, version-2, and version-3 verification is unchanged.
- Opening a vault sealed before M6 does not fabricate an assessment.

## Consequences

- Operators inspect health with `credential health` and reevaluate with `credential refresh` after unlock.
- `credential replace` changes the secret and can change lifecycle policy. It does not change type.
- `credential policy` stores thresholds and the compromise opt-in. Installing a checker is in-process only.
- A full sweep that changes nothing still appends one audit row, so the attempt is durable. It does not append one row per unchanged credential and it does not notify again.

## Tests

- Common, patterned, and class-mixed passwords; Unicode and malformed bytes round-trip without normalization; over-long secrets stay intact and unassessed. A repeated-byte run at the pattern-run threshold is weak with a prefix, suffix, or different neighbors. A shorter run is not.
- Reuse is reported on the other credential, cleared when the match goes away, and excluded for the same id.
- Replace keeps id, type, creation time, and grant scope. A faulted replace leaves the secret, peer findings, and audit chain unchanged.
- A checker sees only the prefix. Opt-in and a checker are both required. Malformed bodies and errors do not become a clear result or erase a match. An identical replacement keeps that match; a changed value does not. A reentrant call discards the delayed result and records a fixed denial for the outer refresh, replace, ingest, lifecycle, and policy attempt.
- Due and overdue boundaries, explicit dates over intervals, disabled policy, and replacement resetting an interval use the session clock. An identical replacement of an unassessed credential keeps `UpdatedAt`, so an overdue interval stays overdue; a byte change moves `UpdatedAt`.
- A legacy document without health opens as unassessed. Invalid health and a document that disagrees with the health row fail closed. An older audit table migrates without changing version-1 hashes. A version-3 respond, notify, or contain row with forged reasons or cred_gen fails verify, unlock, and read.
- Repeated refresh does not repeat the alert. Delivery failure keeps the health row, retries twice, and recovers after reopen. A nil sink does not invent a failure. Containment does not suspend an agent for a weak password.
- A sentinel secret and a checker error that contains it are absent from audit rows, notifications, and logs.

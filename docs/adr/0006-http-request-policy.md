# ADR 0006: HTTP request policy and network hardening

Status: Accepted

## Context

M3 ([ADR 0005](0005-http-credential-broker.md)) lets an agent with an active `http_request` grant call one canonical HTTPS target. The broker inserts the credential. The agent receives a status code and not the secret, the header, or the upstream body. ADR 0005 refuses redirects, pins the first public address, and treats every destination failure as `denied_destination`. It leaves generalized host, method, path, and redirect policy to M4.

M4 does not add notification delivery, anomaly detection, credential rotation, GitHub integration, SSH signing, shared vaults, or an MCP/SDK transport. It hardens the same broker. The agent request and response shapes stay as ADR 0005 defined them. The version-2 audit preimage stays as ADR 0004 defined it.

## Decision

An `http_request` grant resource remains the exact text `METHOD https://host[:port]/path[?query]`. That text is the policy. The broker parses it into origin (host and port), method, path, query, and action class. There is no wildcard, glob, or prefix language. A path grant for `/v1` does not authorize `/v1/ping`, and a query is part of the resource. Path and query comparison is exact and case-sensitive. Host comparison is the canonical lowercase DNS name; the broker does not rewrite case, dots, or percent-encoding into a second name.

Action class is derived from the method, not stored as a separate grant field:

- `read` — `GET`, `HEAD`
- `write` — `POST`, `PUT`, `PATCH`, `DELETE`

A request is allowed only when an active grant matches every field and the M2 lifecycle checks pass. Anything else is denied before DNS and before the secret is copied. When several grants are in scope, the broker chooses the deterministic closest one: score origin, then path, then action, then method, and break ties with the lowest grant id. The denial class is the first mismatch of that grant:

- `denied_origin` — scheme, host, or port differs, including a public IP literal and an alternate name for the same address
- `denied_path` — path or query differs
- `denied_action` — read versus write
- `denied_method` — method differs inside the same action class

A grant whose resource is not a canonical HTTP policy stays an ordinary M2 scope denial (`denied_scope`). Expired, revoked, and missing grants keep the M2 result codes. Those are ordinary denials. The classes below are the security-relevant ones.

Destination classification is a prefix list of IANA special-purpose ranges plus the Go standard-library unicast checks, not a pile of one-off host exceptions. IPv4-mapped addresses are unmapped and judged as IPv4. IPv6 is limited to `2000::/3` minus the special-purpose ranges inside it, including documentation, 6to4, benchmarking, TEREDO, and AS112. The M3 `192.88.99.0/24` refusal stays in that list. Names in `localhost`, `.local`, `.internal`, `.localdomain`, `.arpa`, `.onion`, `.test`, and `.invalid` are special-use destinations. Obfuscated IP spellings (decimal, octal, hex, and short dotted forms) are the same class. The result is `denied_ssrf`.

Ambiguous authority that the broker refuses to canonicalize — userinfo, backslash, fragment, percent-encoding, non-lowercase host, trailing dot, explicit port 443 — is `denied_malformed`. Garbage input that is not an HTTP target (empty target, unknown method, `*`, control bytes) stays `denied` with empty identity fields, so the caller string is not an audit field. Both fail closed.

DNS answers are accepted only when every address is public. A mixed public and non-public set is `denied_ssrf`. A lookup error or an empty answer is `denied_destination`: the origin could not be confirmed, and that is not by itself an SSRF attempt. The broker resolves once. It copies the first accepted address and dials that copy. The dial ignores the address the HTTP stack requested, does not resolve again, and does not consult `HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY`. The credential is copied only after that pin exists, and only onto a request that dials the pin.

Redirects stay refused. M4 does not re-issue a hop. Same-origin, cross-origin, scheme, port, relative, protocol-relative, special-use, and chained redirects all stop after the first response. A redirect never inherits the credential. The audit result is `denied_redirect`. The first hop, when it was authorized, already has its pre-send `allowed` row; the follow-up does not.

`Session.SetAbuseGuard` is the control-plane hook for later rate, repeated-denial, and destructive-action limits. It runs after policy and destination checks and before the secret is copied or the connection is opened. The argument is an `AbuseDecision`: agent id, grant id, credential id, action class, and decision class. It has no URL, header, body, or secret. A non-nil error vetoes an otherwise allowed call as `denied_abuse`. The same hook observes denials and cannot turn a denial into an allow. The guard is process-local. An agent principal cannot set it. This milestone does not count rates or send notifications.

Broker audit rows stay on hash version 2. New result codes are the policy decision class. They are fixed literals. Allowed and denied attempts both produce a row. `allowed` is committed before the credential is sent. A denial other than the post-send redirect refusal has no `allowed` row, which is how a reviewer sees that the credential was not transmitted. `completed` and `upstream_error` follow `allowed`. Rows still omit the resource string, the target URL, authorization headers, and upstream bodies.

`denied_destination` remains a legal historical result and the result for a lookup that cannot be confirmed. New SSRF, origin, and redirect failures use the finer codes.

## Alternatives considered

- **Follow redirects that re-authorize each hop.** Rejected for M4. A second request is a second destination. Refusing every hop is the smaller rule and matches the M3 threat the tests already lock.
- **Prefix or glob paths.** Rejected. ADR 0004 refused wildcards. Exact path and query are enough for this milestone and have no ambiguous match set.
- **A new audit field for the decision class.** Rejected. The result code is already in the version-2 preimage. A new field would change the hash without storing more trustworthy data.
- **Connect to the public members of a mixed DNS answer.** Rejected. A name that answers with any non-public address is an untrustworthy destination. The credential is not sent to the public subset either.
- **Normalize IDNA, case, or default ports before matching.** Rejected. Normalization is a second origin. Non-canonical forms fail closed.

## Security implications

- The broker still has no agent-facing secret retrieval. The response is still only a status code.
- A grant for one origin, method, path, and action does not authorize a neighbor. Mismatches fail before DNS and before the secret is copied.
- A public IP literal, an alternate hostname, the wrong scheme, or a policy-significant port cannot borrow a grant for a name.
- Special-use and non-public destinations, including answers discovered only at DNS time, do not receive the credential. `192.88.99.0/24` stays refused.
- The dialed address is the address that passed that check. Proxy environment variables are not an alternate egress path.
- No redirect receives the credential. The first hop's authorization is not inherited.
- The abuse hook cannot widen a denial. It can only stop a call that policy already allowed, and it never sees the secret.
- Audit, logs, and errors gain new fixed result codes and do not gain a new plaintext path for the secret or the caller URL.

## Consequences

- M5 can classify and notify from these result codes, and can install a guard, without changing the broker trust boundary.
- Callers that need encoded paths or a non-HTTPS origin are still refused.
- Existing `denied_destination` rows remain verifiable. New chains also use the finer codes.
- The in-process `AgentPrincipal` remains the agent transport.

## Tests

- Policy mismatches for host, same-IP alternate name, scheme, port, path, query, read/write action, and method are denied before DNS and before a credential-bearing dial.
- Special-use names, obfuscated addresses, IPv4 and IPv6 special-purpose ranges, and the `192.88.99.0/24` boundaries are denied as SSRF. A mixed DNS answer and a name that resolves only to a non-public address are denied before the dial.
- The dial uses the first validated address after that address's bytes are copied. A later change to the resolver's slice, a second lookup, and `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` do not move the connection.
- Same-origin, cross-origin, scheme, port, relative, special-use, and chained redirects produce one upstream request and `denied_redirect`.
- Expired, revoked, and missing grants still fail closed before the network. A non-HTTP resource string remains `denied_scope`.
- The abuse hook sees a secret-free decision, vetoes a write before the dial, and cannot turn an SSRF denial into an allow.
- Allowed, completed, denial, and upstream-error rows stay secret-free and verifiable. The agent-visible result remains a status code.

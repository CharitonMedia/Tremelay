# ADR 0005: Generic HTTP credential broker

Status: Accepted

## Context

M3 requires an agent with an active M2 `http_request` grant to call one HTTP service with a stored credential and never receive that credential. [ADR 0001](0001-initial-product-boundary.md) makes a scoped capability the agent abstraction. [ADR 0004](0004-agent-capability-grants.md) defines agent identity, exact resource match, the session clock, and audit version 2. It does not perform the authorized request.

The broker must stay a closed path. An `http_request` grant is necessary and is not general network authority. Response bytes are part of the trust boundary. Redirects, SSRF, and alternate destinations must not carry the credential to an unintended origin. Generalized host, method, path, and redirect policy remains M4.

## Decision

`AgentPrincipal.BrokerHTTP` is the only agent-facing broker operation. The human session does not export it. The request names a credential id, an HTTP method, and an absolute target. It has no header, body, or secret field. The response is a status code. It has no body, headers, or outbound request dump. Upstream body bytes stay inside the broker.

The M2 resource string for a brokered call is the exact text `METHOD https://host/path`. The method allowlist is `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, and `DELETE`. The broker does not rewrite the target. A target that is not already in that canonical form is refused. Canonical form means:

- scheme `https`, lowercase host, no userinfo, no fragment, no percent-encoding, no backslash, and no `*`;
- a DNS name of at least two labels, not an IP literal and not a decimal, octal, or hex IP spelling;
- no `localhost`, `.localhost`, `.local`, `.internal`, `.localdomain`, `.arpa`, or `.onion` name;
- an absolute path with no `.` or `..` segments;
- port omitted when it is 443, otherwise an explicit non-zero port.

Authorization uses the M2 `judge` decision and the session clock. The operation is always `http_request`. A missing, expired, revoked, or non-matching grant fails before DNS and before any use of the secret. After an allow, the broker resolves the host once. Every returned address must be a public unicast address. IPv4 loopback, private, link-local, multicast, unspecified, documentation, benchmarking, and carrier-grade NAT addresses are refused, as is the 6a44 relay address `192.88.99.2`. IPv6 is limited to `2000::/3`, excluding special-purpose ranges that are not ordinary public destinations: `2001::/23` (benchmarking, TEREDO, and the other IETF assignments), `2001:db8::/32`, `2002::/16`, `3fff::/20`, and `2620:4f:8000::/48`. That also refuses addresses outside `2000::/3`, including deprecated site-local `fec0::/10`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, and discard-only `100::/64`. The production client dials only the first accepted address and does not consult `HTTP_PROXY`. Redirects are refused, including same-origin redirects and chains.

The stored secret is copied only after those checks. It is placed in one `Authorization: Bearer` header. The caller cannot supply that header. Secrets that contain a space or a non-printable byte are not sent. The header value is not returned, logged, or audited.

The agent receives the upstream status code when that status is outside the 3xx range and within 200–599. The upstream body is read only to finish the call, then wiped. It is not inspected for encodings and it is not returned. A transport error, a redirect, an unusable status, or an audit failure returns a fixed error and a zero status. Upstream error text and upstream body bytes are not copied into the agent-visible result.

Broker attempts use audit action `broker_http` and hash version 2. The version-1 preimage and the version-2 field list are unchanged. The resource string and the target URL are not audit fields. Result codes distinguish the attempt:

- `allowed` — authorization and destination checks passed, and this event is durable before the credential is sent;
- `completed` — the upstream call finished and the status code was returned;
- `denied`, `denied_agent`, `denied_credential`, `denied_operation`, `denied_scope`, `denied_expired`, `denied_revoked`, `denied_missing` — the M2 decision refused the call;
- `denied_destination` — the target, the resolved addresses, or a redirect was refused;
- `upstream_error` — the call was authorized but the broker did not return a status.

A crash can still lose the completion event after `allowed`. It cannot lose the fact that a credential use was authorized, and it cannot return a status whose completion event failed to commit.

M2 grants are not single-use. Repeating a broker call inside an active grant is allowed. Agent bearer tokens, OAuth refresh, SSH signing, and a CLI broker command are not part of this milestone.

## Alternatives considered

- **Follow redirects that stay on the same host.** Rejected. A same-origin redirect still forwards `Authorization`, and M3 does not yet have a path policy that can judge the second request.
- **Normalize targets before comparing them to the grant.** Rejected. Rewriting ports, case, or encodings is a second destination. Exact canonical text keeps the M2 matcher unchanged.
- **Put the target URL in the audit result.** Rejected. The target is caller-controlled and is a plaintext secret path, which ADR 0004 already refuses for resource strings.
- **A separate `capability_authorize` row plus a broker row.** Rejected. One `broker_http` decision row is the broker attempt. The pre-send `allowed` row is the credential-use record required before the secret touches the network.
- **Return the upstream body after decoding reflected secrets.** Rejected. Percent-encoding, JSON escapes, base64, hex, and further compositions are not a closed set. M3 does not return upstream body bytes at all.

## Security implications

- `AgentPrincipal` still has no credential retrieval method. `BrokerHTTP` does not return the secret, the Authorization header, or the outbound request.
- A grant for one canonical target does not authorize a different host, method, or path. Those mismatches fail before DNS and before the secret is copied.
- A grant whose target is an IP literal, a loopback name, or a private address does not cause the credential to be sent. Resolution to a non-public address fails the same way.
- The production dialer pins the connection to the address that passed that check. Environment proxies are not used.
- Redirect responses are discarded. The broker does not issue the next request, so the credential is not forwarded.
- The agent-facing result is a status code. An upstream body that contains the secret, in any encoding, does not cross the boundary. The agent sees that status or a fixed error string.
- Audit rows, process logs, and the vault file do not gain a new plaintext path for the secret. Tests use a high-entropy sentinel and check those surfaces.

## Consequences

- M4 can replace the closed target grammar, the always-refuse redirect rule, and the single-lookup pin without changing the agent request shape.
- Callers that need percent-encoded paths or a non-bearer scheme wait for that policy. M3 will not send those requests.
- The audit chain gains `broker_http` rows under the existing version-2 preimage. No SQLite migration is required.
- The in-process `AgentPrincipal` remains the agent transport.

## Tests

- A human stores a sentinel credential, creates an agent, issues an expiring `http_request` grant, and binds an `AgentPrincipal`. The broker calls a stub upstream that requires the injected bearer value. The agent-visible response is the status code. That response, errors, logs, audit columns, environment, and the vault file do not contain the sentinel or the upstream body.
- The same call is refused before any upstream request for the wrong credential, method, host, path, principal, expiry, revocation, missing grant, and malformed input.
- Loopback, link-local, private, `192.88.99.2`, non-public IPv6, and obfuscated destinations are refused, including when a grant names that destination. A name that resolves only after authorization to a loopback, mixed private, site-local, NAT64, or `192.88.99.2` address is refused before the upstream hook.
- Redirects, including 301, 302, 303, 307, and 308, produce one upstream request and no second hop.
- An upstream body, including one that contains the secret in raw, JSON-escaped, percent-encoded, hex, or base64 form, is not part of the agent response. A transport error that embeds the secret is not copied into the error. An unsafe secret byte is not sent.
- Allowed, completed, capability-denial, destination-denial, and upstream-error audit rows are present, secret-free, and accepted by audit verification.

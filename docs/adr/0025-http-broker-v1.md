# ADR 0025: Prefix-scoped HTTP broker with redacted response bodies

Status: Accepted pending owner veto

Supersedes the response projection of [ADR 0005](0005-http-credential-broker.md),
the one-URL-per-grant rule of [ADR 0006](0006-http-request-policy.md) for this
operation, and all of [ADR 0011](0011-github-issue-state.md).

## Context

[V1.md](../../V1.md) item 4 asks for an HTTP broker an agent can actually use.
The shipped broker could not do that. ADR 0005 returns a status code and nothing
else, ADR 0006 matches one exact `METHOD https://host/path` string per grant, and
the only way to read a real response was ADR 0011's hand-written GitHub
issue-state decoder: one grant per issue, four validated fields, and a parser
that only works for one endpoint of one vendor. Every further useful API would
have needed another operation, another decoder and another ADR.

The threats in view are the ones [THREAT_MODEL.md](../../THREAT_MODEL.md) lists
for the broker: secret extraction through response reflection, scope escalation
to another host or path, credential forwarding through redirects or SSRF,
request smuggling through caller-supplied headers, and error-path leakage.

## Decision

### 1. Trust-boundary change

Two boundaries move, and only for the new operation.

**Agents now receive response bytes.** [Invariant 12](../../SECURITY_INVARIANTS.md)
says an allowed upstream call does not authorize returning the whole response.
ADR 0011 already crossed that line for four fields it could validate. This ADR
crosses it for the body itself, so the vault can no longer vouch for the
*meaning* of what the agent reads. What it still enforces is the *shape*: the
status code, a closed allowlist of response headers, a fixed body cap with an
explicit `truncated` flag, and removal of every spelling of the credential from
both. An upstream that reflects the credential cannot hand it back.

**Grants are prefixes, not single URLs.** One grant covers an origin, an
explicit method set and a path prefix instead of one exact URL. That is strictly
more authority per grant. It is the authority the acceptance line requires
("lists and reads GitHub issues"), and the prefix is a bounded, auditable
statement of it. The segment-boundary rule below keeps a prefix from reaching a
sibling resource.

### 2. A new operation, not a widened one

`http_broker` is a new grant operation. `http_request` is unchanged.

An existing exact `http_request` grant keeps working exactly as before, on the
status-only `BrokerHTTP` path, with no migration. It does not gain a body, a
header projection, or a prefix. Nothing rewrites stored grants. This is ADR
0011's reasoning applied again: stored grants list their operations explicitly,
so an old grant cannot satisfy a judge for an operation that did not exist when
it was issued.

The alternative — teaching `http_request` about prefixes and bodies — would have
silently upgraded every grant already in a vault. Rejected.

### 3. Grant shape

A `http_broker` grant carries:

- **Resource**: the single canonical text `https://host[:port]/prefix`. The
  origin and the prefix are one string so there is one spelling per grant and
  one thing to read in a review. Canonicalisation is ADR 0006's, unchanged and
  reused: `https` only, lowercase DNS host with at least two labels, no
  trailing dot, no IP literal or obfuscated-IP form, no special-use or
  loopback name, no explicit `:443`, no userinfo, no query, no fragment, no
  percent-encoding, no backslash, no `//`, no `.` or `..` segment, no control
  byte, and no trailing slash except for the root prefix `/`.
- **Methods**: an explicit, sorted, de-duplicated subset of GET, HEAD, POST,
  PUT, PATCH, DELETE. Empty is refused; there is no "any method".
- **Injection style**: exactly one of
  - `bearer` — `Authorization: Bearer <secret>`,
  - `header` — the grant's named header carries the secret,
  - `basic` — the grant's stored user and the secret as RFC 7617 credentials,
  - `query` — the grant's named parameter carries the URL-encoded secret.

  A `header` grant may not name any header an agent is refused, so the two
  rules can never disagree about who owns that header. A `basic` user may not
  contain `:`. These fields name the slot; they never hold the secret.

Those three fields are required for `http_broker` and refused on every other
operation, at issuance and again on unlock. A stored document that loses them,
or that puts them on another operation, fails closed.

Path prefix matching is on segment boundaries: `/repos/o/r` covers `/repos/o/r`
and `/repos/o/r/issues`, and does not cover `/repos/o/rx`.

### 4. Request shape

`AgentPrincipal.BrokerRequest` and the `invoke_capability` MCP tool take a
method, a path under the prefix, a query, non-auth headers, and a body capped at
32 KiB. There is no credential field, no authorization field, no redirect field
and no destination field beyond the granted origin.

Refused, before DNS and before any secret is copied: `Authorization`,
`Proxy-Authorization`, `Cookie`, `Host`, `Content-Length`,
`Transfer-Encoding`, the hop-by-hop names (`Connection`, `Keep-Alive`,
`Proxy-Connection`, `TE`, `Trailer`, `Trailers`, `Upgrade`), the grant's own
named injection header, and — for query injection — any query parameter with the
grant's parameter name. Header names and query parameter names are compared
case-insensitively, because HTTP treats them that way. Header values are
restricted to printable ASCII and tab, so a value cannot carry CR or LF.

A body is refused on GET, HEAD and DELETE, and the body the broker does send is
framed with one fixed `Content-Length` and no chunking.

The grant is resolved after authorization and before destination resolution,
because only the grant knows which slot the credential will occupy. A request
that would write that slot is `denied_malformed`; it is never silently
overwritten.

### 5. Response shape

The agent receives the status code, an allowlist of response headers, and the
capped body with a `truncated` flag.

The header allowlist is `Content-Type`, `Content-Length`, `ETag`,
`Last-Modified`, `Link`, `Retry-After`, and the `X-RateLimit-*` family. It is
closed by construction: `Set-Cookie`, `WWW-Authenticate`, `Authorization` and
every transport header are absent because they are not on the list, not because
they were subtracted from one.

Every spelling of the credential is removed from both the body and the returned
headers: raw, URL-encoded, base64, hex and JSON-string-escaped, plus the basic
`user:pass` pair in those same spellings. Each occurrence becomes `[redacted]`.

Redaction is streaming-safe by construction: the capped buffer is assembled
first, then rewritten in one left-to-right pass, so a credential split across
upstream read boundaries is still one match and inserted marker bytes are never
rescanned. Truncation can cut a credential in half, so a truncated buffer also
loses its longest trailing proper prefix of any spelling. After projection the
broker re-checks containment and withholds the whole response as
`upstream_error` if any spelling survived; a leak fails the call, not the check.

### 6. Defences kept unchanged

Every ADR 0005 and 0006 network control still runs on this path, because it is
the same `brokerExchange`: target classification before DNS, special-use and
private-address refusal, one DNS lookup with a first-public-address pin, a
transport that ignores `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` and dials only the
pinned address, total refusal of redirects including chains, the destructive-
method policy, and the abuse-guard hook. A 3xx is refused before its headers or
body are read, so `Location` never reaches the agent and the credential is never
offered to the next hop.

Audit discipline is unchanged: rows stay on `broker_http` with hash version 2,
`allowed` is committed before the secret is placed on the request, and
`completed` or `upstream_error` follows. Rows never carry the URL, headers, body
or secret. The operation field is `http_broker`. Denials reuse the existing
codes, now including `denied_origin`, `denied_path` and `denied_method` chosen
by the closest matching grant.

### 7. GitHub issue-state is removed

`github_issue_state`, its grant operation, its resource builder, its decoder and
its tests are deleted. An ordinary `http_broker` grant for
`https://api.github.com` with prefix `/repos/OWNER/REPO` and `bearer` injection
covers the same use with more capability and less code.

Migration is deliberate and not automatic: `github_issue_state` is no longer in
the operation allowlist, so a vault that still holds such a grant fails closed on
unlock. The owner revokes it with the pre-upgrade binary first. This matches the
precedent set when M9a's shared-vault grants were retired, and it is the
fail-closed choice: the alternative, silently rewriting a stored grant into a
prefix grant during unlock, would mint authority the owner never approved.

### 8. Wire surfaces

The agent-capability TLV protocol (ADR 0017) stays at version 1. The
`github_issue_state` field ids 16–19 are retired and not reallocated, so a stale
encoder cannot be misread as a broker response. New ids 21–28 carry the request
shape, the response projection, and the disclosed grant scope. The MCP
`invoke_capability` tool (ADRs 0018, 0020, 0021) gains `method`, `path`,
`query`, `headers` and `body_base64` arguments, mutually exclusive with the
attestation `payload`. The catalogue discloses each broker grant's method set
and injection slot name so an agent knows what it may send; it never discloses a
credential value.

The response body is a JSON string when the redacted bytes are valid UTF-8
without NUL, and `body_base64` otherwise. Exactly one of the two is present.

### 9. CLI

`tremelay grant create` gains `--method` (repeatable), `--inject` and
`--inject-name`. No other command changes. There is no agent-facing CLI.

## Consequences

- An agent with one grant can now read response bodies from a whole path
  subtree. That is the point of the milestone, and it is a real increase in
  blast radius per grant compared to one exact URL. The origin, method set and
  prefix are the stated bound; the owner chooses how wide the prefix is.
- The vault no longer validates response *content* for this operation. An agent
  can be fed anything the upstream says, including prompt-injection text. The
  broker guarantees the credential is not in it, not that it is trustworthy.
- Redaction is a closed list of literal spellings, not an encoding-aware scan.
  An upstream that re-encodes the credential some other way (gzip, a custom
  cipher) would defeat it; the containment re-check cannot see that either.
  Marked `ponytail:` in `credentialForms` with the upgrade path.
- Percent-encoding is refused everywhere in the path and query, inherited from
  ADR 0006. An API that requires a percent-encoded path or query value cannot be
  reached yet. That is a known, deliberate gap.
- Body caps are fixed at 32 KiB each way, chosen so one request and one response
  both fit inside the existing capability and MCP frame limits. A larger
  response is truncated, never streamed.
- Vaults holding a `github_issue_state` grant need one revoke with the old
  binary before upgrading.

## Alternatives rejected

- **Widen `http_request`.** Silently upgrades existing grants.
- **Keep a typed decoder per API.** ADR 0011 already showed the cost: one ADR,
  one parser and one operation per endpoint.
- **Return the body unredacted and rely on the agent.** The agent is the
  adversary in [THREAT_MODEL.md](../../THREAT_MODEL.md) section 4.
- **Wildcard or regex path scopes.** Not auditable at a glance; a prefix with a
  segment-boundary rule is.
- **Auto-migrate `github_issue_state` grants on unlock.** Mints unapproved
  authority during a key operation.

## Acceptance

Synthetic only. No live API is called by the test suite.

- `TestBrokerUpstreamEchoIsRedacted` — for each of the four injection styles, a
  TLS upstream reflects the injected header, the query string and the basic
  pair back in the body and in an allowlisted header. The agent output, the
  audit rows, the error text, the host log, the vault file and the process
  environment contain no spelling of the credential.
- `TestBrokerRedactsSecretSplitAcrossReads` — the credential straddles two
  upstream chunks and is still redacted exactly once.
- `TestBrokerTruncatesOversizedBody` — an oversized body is truncated, flagged,
  and does not end in a partial credential.
- `TestBrokerDeniesMalformedPathsBeforeDNS` — traversal, encoded and literal
  slashes and backslashes, percent-encoded dots, double slashes, fragments,
  userinfo, control bytes and whitespace are refused with no DNS lookup and no
  connection.
- `TestBrokerRefusesHeaderSmuggling` — every refused header name, CR/LF in a
  name or value, and the grant's own injection slot under any case spelling.
- `TestBrokerRefusesRedirect` — a 3xx is refused, its `Location` and body are
  not projected, and the credential is not forwarded.
- `TestBrokerGrantMatching` — positive and negative origin, prefix and method
  matching, including the `/repos/o/rx` sibling case.
- `TestBrokerGrantShapeValidation`, `TestBrokerRequestShapeLimits`,
  `TestBrokerRedactForms`, `TestBrokerPathUnderPrefix`.
- `TestMCPNetworkBroker*` — the whole MCP path: catalogue scope, handle
  retargeting, foreign handles, lifecycle, credential replacement, destination
  denials and fail-closed audit, now parameterised over `http_broker`.
- `TestMCPSyntheticCredentialFixture` and the named-client smoke script — a real
  stdio MCP client reads a brokered body from a TLS upstream that echoes the
  credential, and gets `[redacted]` in every field.

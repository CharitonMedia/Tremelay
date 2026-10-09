# ADR 0011: Scoped GitHub issue-state read

Status: Accepted

## Context

M7 asks for one real GitHub capability that does not reveal the credential. [ADR 0005](0005-http-credential-broker.md) already brokers an authorized HTTPS call and returns only a status code. The upstream body stays inside the broker because response bytes are part of the trust boundary. [Invariant 12](../../SECURITY_INVARIANTS.md) says an allowed upstream call does not authorize returning the whole response.

GitHub's "Get an issue" endpoint is `GET /repos/{owner}/{repo}/issues/{issue_number}` on `https://api.github.com`. The same endpoint returns pull requests. A useful progress check needs the issue number, whether it is open or closed, whether it is locked, and how many comments it has. It does not need the title, body, user, or any other field.

This changes the ADR 0005 boundary for one operation: four validated fields may cross to the agent. The raw body still may not. The threats in view are secret extraction through response reflection, scope escalation to another repository or issue, and credential forwarding through redirects, alternate hosts, or SSRF.

## Decision

`github_issue_state` is a separate grant operation from `http_request`. `AgentPrincipal.GitHubIssueState` is the only caller. The human session does not export it. The request names a credential id, an owner, a repository, and an issue number. It has no header, body, URL, or secret field.

The grant resource is the exact text `GET https://api.github.com/repos/{owner}/{repo}/issues/{number}`. `GitHubIssueResource` builds that text. Authorization uses the existing judge, session clock, revocation state, and network policy. One grant matches one owner, repository, and issue. It does not match another issue, repository, endpoint, method, or origin.

An existing `http_request` grant does not gain this response. Stored grants list their operations explicitly, and this operation is new, so an old grant cannot satisfy the judge. `BrokerHTTP` stays status-only. It does not grow a body, a selector, or a decoder. A `github_issue_state` grant does not authorize `BrokerHTTP`.

### Canonical identity

Owner, repository, and issue number are accepted only in canonical form, before DNS and before the secret is copied:

- Owner is 1–39 ASCII letters, digits, or hyphens, and does not start or end with a hyphen.
- Repository is 1–100 ASCII letters, digits, `.`, `-`, or `_`. It does not start or end with `.`, and it does not end in `.git` in any ASCII case.
- Issue number is a decimal integer from 1 through 999999999 with no sign and no leading zero.

Percent-encoding, slash, backslash, query, fragment, whitespace, controls, and non-ASCII are rejected. The host is always `api.github.com` and the method is always `GET`. The broker does not accept a caller-supplied URL.

### Upstream call

The broker sends one `GET` and does not retry, follow links, paginate, or try another authentication scheme. The timeout is the existing 10 second broker timeout. The response body is capped at 256 KiB. A deeper document than 16 nested arrays or objects is rejected before it is decoded.

The caller cannot set headers. The broker sets:

- `Authorization: Bearer` with the stored secret, only after the `allowed` audit row commits
- `Accept: application/vnd.github+json`
- `X-GitHub-Api-Version: 2026-03-10`
- `User-Agent: tremelay`

`2026-03-10` is the pinned GitHub REST version. `2022-11-28` remains supported by GitHub until 2028-03-10 and is not what this broker sends. Redirects, including a 301 for a transferred issue, stay refused. The credential is not sent to the next location. A private DNS answer is still `denied_ssrf`. Proxy environment variables are still ignored.

### Response projection

Only HTTP 200 is a success. The body must be one JSON object. These members are required, must occur once, and are checked inside the broker:

- `url` equals `https://api.github.com/repos/{owner}/{repo}/issues/{number}`
- `repository_url` equals `https://api.github.com/repos/{owner}/{repo}`
- `number` is that same canonical integer
- `state` is `open` or `closed`
- `locked` is JSON `true` or `false`
- `comments` is a canonical integer from 0 through 1000000

Comparison is exact and case-sensitive, so a different spelling is a mismatch even though GitHub treats names as case-insensitive. Escaped slashes in those strings are rejected. `url` and `repository_url` are not returned.

A `pull_request` member, including `null`, means the object is a pull request. The read fails. Every other member is optional. `title`, `body`, `user`, `labels`, `html_url`, `state_reason`, and any further member are discarded whether they are present or absent. Duplicate top-level names fail. Missing, typed-wrong, or out-of-range required members fail.

The agent receives `number`, `state`, `locked`, and `comments`. On every failure the struct is the zero value. Upstream errors, rate limits, oversized bodies, and malformed JSON return `ErrBrokerUpstream`. That text is fixed. Response bodies, transport errors, and retry URLs are not copied into it.

### Audit

Rows stay on `broker_http` and hash version 2. The version-1 through version-4 preimages are unchanged. The operation field is `github_issue_state` for this call and `http_request` for `BrokerHTTP`. `allowed` is committed before the secret is placed on the request. `completed` is committed only after the summary validates, and the summary is not returned if that write fails. Parse failures and non-200 responses are `upstream_error`. Malformed owner, repository, or issue text is `denied` with empty identity fields. Redirects, SSRF, expiry, revocation, and scope mismatches keep their existing result codes. Notification and containment are unchanged.

## Alternatives considered

- **Return the issue JSON from `BrokerHTTP`.** Rejected. ADR 0005 keeps that response as a status code. A body passthrough is a general disclosure path.
- **Let an existing `http_request` grant receive the four fields.** Rejected. That would give every current GitHub URL grant a new response it was not issued for.
- **A caller-supplied field list or JSON path.** Rejected. That is an agent-controlled decoder.
- **Follow a 301 to a transferred issue.** Rejected. The next URL is a different resource, and the credential would be forwarded.
- **A new audit version for the summary.** Rejected. The summary is not an audit field. The existing operation field distinguishes the call without changing the preimage.

## Security implications

- The agent still has no credential retrieval method. The new method returns four typed fields and not the secret, the header, or the body.
- A grant for one issue does not authorize another issue, repository, method, endpoint, or origin. Those mismatches fail before DNS and before the secret is copied.
- An `http_request` grant for the same URL still receives only a status code. A `github_issue_state` grant does not authorize `BrokerHTTP`.
- Redirects, private addresses, and proxy variables cannot carry the credential. A transferred issue is a refused redirect, not a second read.
- Unknown JSON, error bodies, and reflected secrets stay inside the broker. Tests use a unique sentinel and check the result, errors, logs, audit rows, and the vault file.
- The `allowed` row is durable before transmission. A failed `completed` row withholds the summary.

## Consequences

- Humans issue the new operation with the exact resource from `GitHubIssueResource`. The CLI allowlist lists it. There is no new agent command and no live GitHub client.
- Callers that need issue text, comment pages, or another GitHub endpoint need a later operation. This one will not grow a selector.
- Comment counts above 1000000 and bodies above 256 KiB fail closed.
- Live calls to `api.github.com` were not run. Acceptance is the synthetic upstream in `TestGitHubIssueState`.

## Tests

- `TestGitHubIssueState` stores a synthetic sentinel, creates an agent, issues an expiring grant for one issue, and checks that the stub upstream received the bearer token. The agent receives the four-field summary. The sentinel is absent from that summary, errors, logs, audit rows, the environment, and the vault file, including raw, JSON-escaped, percent-encoded, hex, and base64 reflections in ignored fields, error bodies, and headers.
- The same test refuses the wrong agent, credential, repository, issue, method, and origin, and refuses a missing, expired, revoked, or suspended grant, before any credential-bearing request.
- An `http_request` grant for the same URL does not authorize the summary. `BrokerHTTP` still returns only a status code when the body is an issue document. A `github_issue_state` grant does not authorize `BrokerHTTP`.
- Redirects, private DNS, oversized and malformed JSON, duplicate fields, pull-request objects, identity mismatches, and invalid state, lock, and comment values fail with a fixed error. The summary is withheld when the completion audit write fails.
- `TestCanonicalGitHubIssue` and `TestParseGitHubIssueState` cover the canonical input rules and the response checks. `TestBrokerHTTP` and `TestNoGetSecretMethod` still hold the status-only boundary and the agent method set.

# Reading GitHub issues through the HTTP broker

The `github_issue_state` special case is gone. GitHub is now an ordinary
`http_broker` grant. See [ADR 0025](adr/0025-http-broker-v1.md); the removed
design is recorded in [ADR 0011](adr/0011-github-issue-state.md).

## Grant one repository

```bash
tremelay grant create --path vault.db --agent AGENT_ID --credential CREDENTIAL_ID \
  --operation http_broker \
  --resource 'https://api.github.com/repos/OWNER/REPO' \
  --method GET \
  --inject bearer \
  --expires 2030-01-01T00:00:00Z
```

That grant lets the agent read anything under `/repos/OWNER/REPO` with `GET`:
the repository, its issues, one issue, that issue's comments. It does not reach
another repository, another owner, another host, or any other method. Add
`--method POST` if the agent should also comment or open issues.

The resource is one canonical string: `https://` plus a lowercase host plus the
path prefix, with no trailing slash, no query, and no percent-encoding. Prefix
matching is on segment boundaries, so `/repos/o/r` covers `/repos/o/r/issues`
and does not cover `/repos/o/rx`.

## What the agent sends and receives

Through MCP, the agent calls `invoke_capability` with the handle it discovered
plus the request:

```json
{"handle": "...", "method": "GET", "path": "/repos/OWNER/REPO/issues", "query": "state=open&per_page=5"}
```

It receives the status code, the allowlisted response headers
(`Content-Type`, `Content-Length`, `ETag`, `Last-Modified`, `Link`,
`Retry-After`, `X-RateLimit-*`), and the body up to 32 KiB with a `truncated`
flag. `Link` and `X-RateLimit-*` are what make paging and rate-limit backoff
work.

The agent cannot send `Authorization`, `Cookie`, `Host`, `Content-Length`,
`Transfer-Encoding`, a hop-by-hop header, or the grant's own injection slot. The
token is injected inside the broker. Every spelling of it is removed from the
body and the returned headers before the agent sees them, so an endpoint that
echoes the token back cannot disclose it.

## Local demonstration

No test in this repository dials `api.github.com`.

```bash
go test ./internal/vault/ -run 'TestBroker|TestMCPNetworkBroker' -count=1
```

`TestBrokerUpstreamEchoIsRedacted` is the demonstration: a synthetic TLS
upstream reflects the injected credential back in the body and in an
allowlisted header, and the agent receives `[redacted]` in both.
`TestMCPNetworkBrokerProtectedUse` runs the same thing over MCP against an
`api.github.com`-shaped prefix grant.

## What was not run

Live verification against `api.github.com` was not performed. This repository
does not create credentials, start OAuth, install a GitHub App, or send a real
token. A human who already controls a token and a repository can exercise the
same grant from their own process.

# M7 — scoped GitHub issue-state read

This is the implemented reference capability for M7. It reads one GitHub issue's state through the broker. It is not a GitHub client, and it does not list, page, or write issues.

The agent calls `GitHubIssueState` with a credential id, owner, repository, and issue number. The grant resource is:

```text
GET https://api.github.com/repos/{owner}/{repo}/issues/{number}
```

`GitHubIssueResource` builds that exact string. The operation is `github_issue_state`. An `http_request` grant does not authorize this response, and this grant does not authorize `BrokerHTTP`. The result is `number`, `state` (`open` or `closed`), `locked`, and `comments`. The credential, the raw body, and every other GitHub field stay inside the broker.

The pinned request is one `GET` to `https://api.github.com` with `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2026-03-10`, and `User-Agent: tremelay`. The caller cannot replace those headers. The body limit is 256 KiB and the timeout is 10 seconds. Redirects, including a transferred issue, are refused. See [ADR 0011](adr/0011-github-issue-state.md).

## Local demonstration

Acceptance uses a synthetic credential and a local stub. No test in this repository dials `api.github.com`.

```bash
go test ./internal/vault/ -run 'TestGitHubIssueState|TestCanonicalGitHubIssue|TestParseGitHubIssueState' -count=1
```

`TestGitHubIssueState` is the demonstration: a human session stores a sentinel, creates an agent, issues an expiring grant for one issue, and the agent receives the typed summary. The stub checks that the bearer token was the stored sentinel. The agent result does not contain it.

A human grant for the same shape, still without a live call, is:

```text
tremelay grant create --path vault.db --agent AGENT_ID --credential CREDENTIAL_ID \
  --operation github_issue_state \
  --resource 'GET https://api.github.com/repos/OWNER/REPO/issues/NUMBER' \
  --expires 2030-01-01T00:00:00Z
```

Owner, repository, and issue number must already be in the canonical form documented in ADR 0011. The resource spelling is case-sensitive and must match the `url` GitHub would return.

## What was not run

Live verification against `api.github.com` was not performed. This repository does not create credentials, start OAuth, install a GitHub App, or send a real token. A human who already controls a credential and a repository can exercise the same call from their own process. That run is outside acceptance.

## Acceptance mapping

| Acceptance | Test |
| --- | --- |
| Synthetic credential, expiring grant, typed summary, stub checks the bearer token | `TestGitHubIssueState` |
| Wrong agent, credential, repository, issue, method, origin | `TestGitHubIssueState` |
| Missing, expired, revoked, and suspended authority | `TestGitHubIssueState` |
| Malformed owner, repository, issue number, encoding, traversal, query, and header injection | `TestCanonicalGitHubIssue`, `TestGitHubIssueState` |
| Existing `http_request` grant does not receive the summary | `TestGitHubIssueState` |
| `BrokerHTTP` stays status-only | `TestGitHubIssueState`, `TestBrokerHTTP`, `TestNoGetSecretMethod` |
| `github_issue_state` does not authorize `BrokerHTTP` | `TestGitHubIssueState` |
| Pull-request responses, identity mismatches, duplicate and invalid fields | `TestParseGitHubIssueState`, `TestGitHubIssueState` |
| Redirects, private DNS, oversized and malformed JSON, upstream and rate-limit errors | `TestGitHubIssueState` |
| Sentinel absent in raw, JSON-escaped, percent-encoded, hex, and base64 forms | `TestGitHubIssueState` |
| `allowed` before transmission; summary withheld if completion audit fails | `TestGitHubIssueState` |
| Denials before authorization do not send the credential | `TestGitHubIssueState` |

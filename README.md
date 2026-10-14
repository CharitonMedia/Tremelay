# Tremelay

**A local credential broker, so your AI agents can use your credentials without ever seeing them.**

You already give agents real authority: read these issues, push this branch, call
that API. Today that means pasting a token into a config file, an environment
variable, or an MCP server, and hoping nothing logs it, echoes it, or wanders off
to the wrong host with it.

Tremelay splits **possession** of a secret from **authority** to use it. You keep
credentials in a local encrypted vault. Each agent gets its own identity and its own
narrow, expiring, revocable grants — "GET anything under
`https://api.github.com/repos/you/yourrepo` with this token", "authenticate to
`git.example.com` as `git` with this SSH key". The agent asks Tremelay to perform
the operation; Tremelay performs it with the credential and returns only the result
the grant allows. The agent never receives the secret, there is no `getSecret` tool
to call, and every attempt — allowed or denied — lands in a hash-chained audit log.

> The broker possesses secrets. Agents possess capabilities.

Agents connect over MCP (`list_capabilities`, `describe_capability`,
`invoke_capability`), or over an ssh-agent socket for SSH signing. Everything is
local: one SQLite vault file, one user-only socket or named pipe, no server, no account, no telemetry.

## Demo

A real session against a throwaway vault. The secret is the literal string
`dummy-demo-secret`. Every command except `vault create` also writes one
`vault_unlock id=… result=allowed` line to stderr; those are trimmed here,
nothing else is.

```
$ tremelay vault create --path demo.db
vault_create id=d8df6f8230cf55a9a8b1b7c7df424f1a result=allowed
vault created

$ CRED=$(tremelay credential put --path demo.db --label "demo api key" --type api_key --secret-file ./secret)
credential_put id=649cee93880ae731b17ea858a439d7fe type=api_key result=allowed reasons=
health_assess id=649cee93880ae731b17ea858a439d7fe type=api_key result=allowed reasons=
649cee93880ae731b17ea858a439d7fe

$ AGENT=$(tremelay agent create --path demo.db --label claude-code)
agent_create agent=3a0f2de100565eb2e4be158fdb9a8201 grant= result=allowed
3a0f2de100565eb2e4be158fdb9a8201

$ GRANT=$(tremelay grant create --path demo.db --agent $AGENT --credential $CRED \
    --operation http_broker --resource https://api.github.com/repos/CharitonMedia/Tremelay \
    --method GET --inject bearer --expires 2030-01-01T00:00:00Z)
grant_create agent=3a0f2de100565eb2e4be158fdb9a8201 grant=a0f8b04d64d8ece4a56130feb2607ce9 result=allowed
a0f8b04d64d8ece4a56130feb2607ce9

$ tremelay capability list --path demo.db --agent $AGENT
capability_list agent=3a0f2de100565eb2e4be158fdb9a8201 grant= result=allowed
{"grant_id":"a0f8b04d64d8ece4a56130feb2607ce9","agent_id":"3a0f2de100565eb2e4be158fdb9a8201","credential_id":"649cee93880ae731b17ea858a439d7fe","operations":["http_broker"],"resource":"https://api.github.com/repos/CharitonMedia/Tremelay","created_at":"2026-10-14T04:20:00.618845291Z","expires_at":"2030-01-01T00:00:00Z","status":"active"}

$ tremelay capability authorize --path demo.db --agent $AGENT --credential $CRED \
    --operation http_broker --resource https://api.github.com/repos/CharitonMedia/Tremelay
capability_authorize agent=3a0f2de100565eb2e4be158fdb9a8201 grant=a0f8b04d64d8ece4a56130feb2607ce9 result=allowed
allowed a0f8b04d64d8ece4a56130feb2607ce9

$ tremelay capability authorize --path demo.db --agent $AGENT --credential $CRED \
    --operation http_broker --resource https://api.github.com/repos/someone/else
capability_authorize agent=3a0f2de100565eb2e4be158fdb9a8201 grant=a0f8b04d64d8ece4a56130feb2607ce9 result=denied_scope
denied_scope

$ tremelay grant revoke --path demo.db --id $GRANT
grant_revoke agent=3a0f2de100565eb2e4be158fdb9a8201 grant=a0f8b04d64d8ece4a56130feb2607ce9 result=allowed
a0f8b04d64d8ece4a56130feb2607ce9

$ tremelay capability authorize --path demo.db --agent $AGENT --credential $CRED \
    --operation http_broker --resource https://api.github.com/repos/CharitonMedia/Tremelay
capability_authorize agent=3a0f2de100565eb2e4be158fdb9a8201 grant=a0f8b04d64d8ece4a56130feb2607ce9 result=denied_revoked
denied_revoked

$ tremelay audit list --path demo.db --agent $AGENT --action capability_authorize
{"seq":12,"time":"2026-10-14T04:20:00.755379639Z","action":"capability_authorize","credential_id":"649cee93880ae731b17ea858a439d7fe","credential_type":"api_key","result":"allowed","agent_id":"3a0f2de100565eb2e4be158fdb9a8201","grant_id":"a0f8b04d64d8ece4a56130feb2607ce9","operation":"http_broker","class":"routine","severity":"info","hash":"bcf38c87bf3038dafc6f1b0c52be3cb6b213cd202096d481370373e3abf847ab"}
{"seq":14,"time":"2026-10-14T04:20:00.821094153Z","action":"capability_authorize","credential_id":"649cee93880ae731b17ea858a439d7fe","credential_type":"api_key","result":"denied_scope","agent_id":"3a0f2de100565eb2e4be158fdb9a8201","grant_id":"a0f8b04d64d8ece4a56130feb2607ce9","operation":"http_broker","class":"expected_denial","severity":"low","hash":"2d2432203b7bbacf562c4f0433090f0647037d746e6d689492c44f25e3b2d2b1"}
{"seq":18,"time":"2026-10-14T04:20:00.951247858Z","action":"capability_authorize","credential_id":"649cee93880ae731b17ea858a439d7fe","credential_type":"api_key","result":"denied_revoked","agent_id":"3a0f2de100565eb2e4be158fdb9a8201","grant_id":"a0f8b04d64d8ece4a56130feb2607ce9","operation":"http_broker","class":"replay","severity":"high","hash":"f8b19ee681e76b1b6fc813116232e732e57644d47ebd3afbefab0a8e23ce2cf1"}

$ tremelay audit verify --path demo.db
84d0bf149dc187c9517fd9a0afce2571fb4fad648cac25ebb5298e5cf68e27a4
```

Both denials exited non-zero, and no row carries a secret. The passphrase came
from `TREMELAY_PASSPHRASE`; interactively you get a no-echo prompt instead.

## Install

Tremelay is pre-release security software and no stable release is published yet,
so building from source is the only install path. It needs the pinned Go toolchain
(1.26.9, see [go.mod](go.mod)).

```
go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest
```

From a clone, `make build` or `go build ./cmd/tremelay` does the same thing.
Releases will carry per-platform archives, a CycloneDX SBOM and a `SHA256SUMS`
file — a checksum detects a corrupt download, not a substituted release. Signed
releases are not in v1. `make release-dry` builds those artifacts locally; see
[ADR 0027](docs/adr/0027-release-artifacts.md).

## Quickstarts

Copy-paste setup from install to first successful call, one page per client:
[docs/quickstarts/](docs/quickstarts/) (Claude Code, Codex, Hermes, generic MCP).

The shape is the same everywhere. `tremelay daemon --vault PATH` asks for your
passphrase once in your terminal and then serves agents on a user-only local
socket; `tremelay agent create --token-file FILE` gives each agent its own bearer
token file, and `tremelay agent token issue|rotate|revoke` manage it later without
recreating the agent; `tremelay mcp --daemon --token-file FILE` is the stdio command the
client launches. `tremelay lock`, the idle timeout, or losing the process
zeroises the key. See [the headless daemon guide](docs/headless-daemon.md), or
[local stdio MCP](docs/local-stdio-mcp.md) for the per-launch pinentry path
instead. For SSH, [`tremelay ssh-agent`](docs/ssh-agent.md) publishes an
`SSH_AUTH_SOCK` that signs with a key that never leaves the daemon.

## What it does not do

Read this before you trust it with anything.

- **One human.** Single user, single vault. No multi-user, no orgs, no shared
  vaults, no team policy.
- **One machine.** A user-only Unix socket or Windows named pipe, and stdio;
  there is no network or remote MCP transport. `tremelay ssh-agent` is Linux and
  macOS only and fails closed on Windows.
- **The agent still reads broker responses.** An `http_broker` grant returns the
  status code, an allowlisted set of response headers, and up to 32 KiB of the
  body with every spelling of the credential redacted. The agent never sees the
  credential, but it does see the data that credential unlocks — and anything in
  that body can be prompt injection. Tremelay guarantees the secret is not in the
  response, not that the response is trustworthy.
- **An unlocked daemon trusts your uid.** While it is unlocked, any code running
  as you can use your agents' granted capabilities. It still cannot read a
  credential, change a grant, or learn your passphrase, and everything it does is
  audited — but that is the boundary.
- **No OAuth refresh brokering, no database session brokering, no browser form
  fill, no TOTP, no provider-assisted rotation.** These are in
  [VISION.md](VISION.md) and on the roadmap, not in v1.
- **No third-party audit.** No independent security review and no signed releases
  yet. The audit chain is tamper-evident to *you*; nobody else checkpoints it.
- **`credential get` prints the raw secret.** That is the human control plane, by
  design — it is not reachable from any agent interface.
- **Pre-release.** Do not put production credentials in it yet.

## Security

- [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) — the rules that outrank
  convenience.
- [THREAT_MODEL.md](THREAT_MODEL.md) — who the adversary is, including the agent.
- [SECURITY.md](SECURITY.md) — reporting a vulnerability.

## Docs

[ARCHITECTURE.md](ARCHITECTURE.md) · [VISION.md](VISION.md) ·
[ADRs](docs/adr/) · [vault lifecycle](docs/vault-lifecycle.md) ·
[HTTP broker](docs/adr/0025-http-broker-v1.md) · [SSH signing](docs/ssh-agent.md) ·
[measured client integrations](docs/named-client-mcp-tests.md) ·
[what is in v1](V1.md) · [milestone history](MILESTONES.md)

`tremelay --help` prints the full command list.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). Apache License 2.0; see [LICENSE](LICENSE).

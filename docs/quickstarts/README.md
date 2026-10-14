# Agent quickstarts

One page per client, each copy-paste from install to a first successful call:
your agent reads GitHub issues with a token it never sees.

- [Claude Code](claude-code.md) — `claude mcp add`
- [Codex](codex.md) — `codex mcp add` or `~/.codex/config.toml`
- [Hermes](hermes.md) — `mcp_servers:` in `~/.hermes/config.yaml`
- [Grok CLI and any stdio MCP client](generic-mcp.md) — the generic command/args shape

Pick one. They differ only in step 4, where the client is told how to launch
`tremelay mcp --daemon --token-file FILE`.

## What you end up with

A vault at `$HOME/.tremelay/vault.db` holding one GitHub token, one agent per
client with its own 0600 token file, and one `http_broker` grant per agent
allowing `GET` under `https://api.github.com/repos/OWNER/REPO`. A `tremelay
daemon` process you unlocked once holds the vault in memory and serves those
agents over a user-only socket. The agent gets the status code, an allowlisted
set of response headers and a capped, credential-redacted body. It never gets
the token, and every attempt is in the audit chain.

## Before you start

- Linux and macOS only. On other platforms `daemon`, `lock` and `mcp --daemon`
  fail closed; use the pinentry path in [local stdio MCP](../local-stdio-mcp.md).
- Each control-plane command prompts for your passphrase. Losing the daemon
  process, rebooting, or running `tremelay lock` locks the vault again.
- Give each client its own agent and token file. The token file is a bearer
  secret: anything that can read it can use that agent's grants while the
  daemon is unlocked.

## When something fails

Agents get one generic denial, by design. Your audit has the reason:

```sh
tremelay audit list --path "$HOME/.tremelay/vault.db" --action broker_http
tremelay audit list --path "$HOME/.tremelay/vault.db" --action daemon_auth
```

| Symptom | Usual cause |
| --- | --- |
| `no unlocked daemon is reachable` | the daemon is not running, or it locked |
| `daemon refused the agent token` | wrong token file, or the agent was revoked |
| the daemon exited by itself | a `credential`/`agent`/`grant` command ran against the same vault, or the idle timeout expired |
| `request denied` on every call, `upstream_error` in the audit | the stored secret has a trailing newline — restore it with `printf '%s'` |
| `denied_origin`, `denied_path`, `denied_method` | the request left the grant's origin, path prefix or method set |

## Background

[Headless daemon](../headless-daemon.md) ·
[HTTP broker](../m7-github-issue.md) ·
[ADR 0024](../adr/0024-headless-unlock-daemon.md) ·
[ADR 0025](../adr/0025-http-broker-v1.md)

# Agent quickstarts

One page per client, each copy-paste from install to a first successful call:
your agent calls an HTTPS API with a credential it never sees.

- [Claude Code](claude-code.md) — `claude mcp add`
- [Codex](codex.md) — `codex mcp add`, or the `[mcp_servers.…]` block in `config.toml`
- [Hermes](hermes.md) — `mcp_servers:` in `config.yaml`
- [Any stdio MCP client](generic-mcp.md) — the `mcpServers` command/args shape

Pick one. They differ only in step 4, where the client is told how to launch
`tremelay mcp --daemon --token-file FILE`.

## What you end up with

A vault holding one credential, one agent per client with its own 0600 token
file, and one `http_broker` grant per agent. A `tremelay daemon` process you
unlocked once holds the vault in memory and serves those agents over a
user-only socket or named pipe. The agent gets the status code, an allowlisted
set of response headers and a capped, credential-redacted body. It never gets
the credential, and every attempt is in the audit chain.

The quickstarts use `https://httpbin.org/anything` with a throwaway secret
because httpbin echoes the request back, so you can see the injected
`Authorization` header come home as `Bearer [redacted]`. A real grant has the
same shape with a real origin and prefix.

## Before you start

- Linux, macOS and Windows. Only `tremelay ssh-agent` is Unix-only; the MCP
  path on this page is not.
- Every control-plane command asks for your vault passphrase with a no-echo
  prompt. The daemon asks once and then serves.
- Give each client its own agent and its own token file. A token file is a
  bearer secret: anything that can read it can use that agent's grants while
  the daemon is unlocked.
- Nothing here ever asks you to recreate an agent or edit the client's MCP
  config again. `agent token issue|rotate|revoke` replaces a token at the path
  the client already points at.

## When something fails

Agents get one generic denial, by design. Your audit has the reason:

```sh
tremelay audit list --path /home/you/.tremelay/vault.db --action broker_http
tremelay audit list --path /home/you/.tremelay/vault.db --action daemon_auth
```

| Symptom | Usual cause |
| --- | --- |
| `no unlocked daemon is reachable` | the daemon is not running, it locked, or the client launched `tremelay` without `XDG_RUNTIME_DIR` (see the [Codex page](codex.md#4-register-the-server-with-codex)) |
| `daemon refused the agent token` | wrong token file, or the token was rotated or revoked |
| `request denied` on every call, `upstream_error` in the audit | the stored secret has a trailing newline; rewrite it with `printf '%s'` and `tremelay credential replace` |
| `denied_origin`, `denied_path`, `denied_method` | the request left the grant's origin, path prefix or method set |
| `denied_revoked` | the grant was revoked; create a new one, no restart needed |

## Background

[Headless daemon](../headless-daemon.md) ·
[HTTP broker](../m7-github-issue.md) ·
[SSH signing](../ssh-agent.md) ·
[ADR 0024](../adr/0024-headless-unlock-daemon.md) ·
[ADR 0025](../adr/0025-http-broker-v1.md)

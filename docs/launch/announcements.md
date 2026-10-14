# Announcement drafts for Patrick to post himself

Drafts for `V1.md` item 9. Nothing here has been posted.

Core links to include in each post:

- Repository: https://github.com/CharitonMedia/Tremelay
- Landing page: https://charitonmedia.github.io/Tremelay/

## Hacker News

### Show HN title (73 chars)

```
Show HN: Tremelay, local credential broker so agents never see your keys
```

### First comment

```
I built Tremelay because I wanted coding agents to use real credentials without
ever receiving the raw secret.

How it works:

- Credentials stay in a local encrypted SQLite vault.
- Each agent gets its own identity and grant set.
- For HTTP, a grant includes origin, method set, path prefix, injection style,
  and expiry.
- Agent-facing MCP surface is only list_capabilities, describe_capability, and
  invoke_capability. There is no secret-retrieval tool.
- Allowed or denied attempts are written to a hash-chained audit log.

For unattended use, `tremelay daemon` unlocks once and serves over a user-only
local socket (named pipe on Windows). `tremelay mcp --daemon --token-file ...`
is the stdio command clients run.

Accepted limits from V1:
- H1: HTTP response content is not screened for prompt injection. The broker
  keeps credentials out of the response. It does not make response instructions
  trustworthy.
- H2: If a vault still has a legacy `github_issue_state` grant, that vault will
  not unlock until the grant is revoked with the pre-v1 binary.

Status and scope:
- Single-user only (no multi-user/shared vault model in v1).
- Pre-1.0, no independent security audit.
- Local-only transport for MCP in v1 (stdio plus local daemon endpoint).

Install:
go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest

Repo: https://github.com/CharitonMedia/Tremelay
Landing page: https://charitonmedia.github.io/Tremelay/
```

## r/ClaudeAI post

### Title

```
Claude Code + Tremelay: local credential broker, scoped grants, no raw secrets
```

### Body

```
I made Tremelay to let Claude Code call APIs with my credentials without seeing
the raw key.

The pattern is:
1) store credentials in a local encrypted SQLite vault,
2) create a Claude-specific agent token file,
3) create scoped grants (origin + methods + path prefix + injection style +
   expiry),
4) run `tremelay daemon`,
5) register `tremelay mcp --daemon --token-file ...` as the local MCP server.

Claude then uses list_capabilities / describe_capability / invoke_capability.
There is no agent-facing raw-secret retrieval tool. Every allowed and denied
attempt is auditable.

Accepted limits (from V1):
- H1: response content is not screened for prompt injection.
- H2: vaults with legacy `github_issue_state` grants must revoke that grant
  using the pre-v1 binary before unlocking.

Important status:
- Single-user only in v1.
- Pre-1.0, no independent security audit.
- Local-only MCP transport in v1.

Repo: https://github.com/CharitonMedia/Tremelay
Landing page: https://charitonmedia.github.io/Tremelay/
```

## r/LocalLLaMA post

### Title

```
Tremelay: local credential broker for MCP agents and local SSH signing
```

### Body

```
Tremelay is a local credential broker for agent workflows.

It separates secret possession from secret use:
- credentials stay in an encrypted local SQLite vault,
- agents get scoped capabilities, not raw credentials,
- MCP side exposes list_capabilities, describe_capability, invoke_capability.

HTTP broker grants are scoped by origin, methods, path prefix, injection style,
and expiry. Responses are projected with allowlisted headers and a capped body,
with credential strings redacted.

There is also `tremelay ssh-agent` for local SSH signing with pinned host-key
grants (Linux/macOS path; MCP path is Linux/macOS/Windows).

Accepted limits from V1:
- H1: HTTP response content is not screened for prompt injection.
- H2: a vault that still contains a legacy `github_issue_state` grant will not
  unlock until that grant is revoked with the pre-v1 binary.

Scope and maturity:
- single-user only,
- local-only MCP transport in v1,
- pre-1.0 and no independent security audit.

Repo: https://github.com/CharitonMedia/Tremelay
Landing page: https://charitonmedia.github.io/Tremelay/
```

## MCP server directory listing

### Short description

```
Local credential broker for AI agents: scoped capability calls over MCP without exposing raw credentials. Single-user, pre-1.0.
```

### Long description

```
Tremelay keeps credentials in a local encrypted SQLite vault and lets agents use
them through scoped capabilities rather than raw-secret access.

Agent-facing MCP tools:
- list_capabilities
- describe_capability
- invoke_capability

No agent-facing secret retrieval path exists in the MCP surface.

HTTP grants are scoped by origin, methods, path prefix, injection style, and
expiry. Allowed/denied attempts are written to a hash-chained audit log.

Accepted limits from V1:
- H1: HTTP response content is not screened for prompt injection.
- H2: vaults with legacy `github_issue_state` grants do not unlock until those
  grants are revoked with the pre-v1 binary.

Current scope and status:
- single-user model in v1,
- local-only MCP transport in v1,
- pre-1.0, no independent security audit.

Repository: https://github.com/CharitonMedia/Tremelay
Landing page: https://charitonmedia.github.io/Tremelay/
```

### Install line

```
go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest
```

### Tags

```
mcp
credential-broker
secrets-management
api-keys
ssh-agent
vault
audit-log
deny-by-default
least-privilege
local-only
go
```

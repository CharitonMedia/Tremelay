# Quickstart: Claude Code

Claude Code reads one GitHub repository through a token it never sees. Linux
and macOS only. Replace `OWNER/REPO`, and `/home/you` with your own `$HOME`
wherever a config file needs a literal path.

## 1. Install

```sh
go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest
command -v tremelay   # note this absolute path; config files cannot expand $HOME
```

Release archives, checksums and SBOMs: [download and verify](../../README.md#install).

## 2. Vault, credential, agent, grant

Each command prompts for your vault passphrase and prints an audit line to
stderr; IDs go to stdout.

```sh
mkdir -p "$HOME/.tremelay" && chmod 700 "$HOME/.tremelay"
tremelay vault create --path "$HOME/.tremelay/vault.db"
```

`printf '%s'` writes the token with **no trailing newline**. The broker refuses
a secret holding any byte outside printable ASCII, so a stored newline makes
every call fail.

```sh
umask 077
read -rs TOKEN                                      # paste the token; not echoed
printf '%s' "$TOKEN" > "$HOME/.tremelay/github.secret"
unset TOKEN
tremelay credential put --path "$HOME/.tremelay/vault.db" \
  --label github --type api_key --secret-file "$HOME/.tremelay/github.secret"
rm -f "$HOME/.tremelay/github.secret"               # the vault holds it now
```

That printed `CREDENTIAL_ID`. The agent gets its own token file, and the command
prints `AGENT_ID` and that path, never the token itself.

```sh
tremelay agent create --path "$HOME/.tremelay/vault.db" --label claude-code \
  --token-file "$HOME/.tremelay/claude-code.token"

tremelay grant create --path "$HOME/.tremelay/vault.db" \
  --agent AGENT_ID --credential CREDENTIAL_ID \
  --operation http_broker \
  --resource 'https://api.github.com/repos/OWNER/REPO' \
  --method GET --inject bearer \
  --expires 2027-01-01T00:00:00Z
```

The printed `GRANT_ID` allows `GET` anywhere under `/repos/OWNER/REPO` and
nothing else — no other repo, host or method. See
[the broker guide](../m7-github-issue.md).

## 3. Unlock once, in its own terminal

```sh
tremelay daemon --vault "$HOME/.tremelay/vault.db" --idle-timeout 8h
```

It prompts for the passphrase, prints its endpoint path, and serves until you
lock it. Keep it in its own terminal, `tmux` window or user service: the key
lives nowhere else.

**Lock, change, unlock.** A `credential`, `agent` or `grant` command run against
the same vault makes the running daemon's session stale, and it exits with
`daemon can no longer serve this vault and has locked; inspect the vault audit,
then restart it`.

## 4. Register the MCP server

```sh
claude mcp add --transport stdio --scope user tremelay -- \
  /absolute/path/to/tremelay mcp --daemon --token-file "$HOME/.tremelay/claude-code.token"
```

`claude mcp list` should show it connected. This command never prompts, so the
default startup timeout is fine.

## 5. First call

With the daemon unlocked, ask Claude Code:

> Use the tremelay MCP server. Call `list_capabilities`, then
> `invoke_capability` on the active `http_broker` handle with `method: GET`,
> `path: /repos/OWNER/REPO/issues`, `query: state=open&per_page=5`. Show me the
> status code and the issue titles.

`list_capabilities` returns one entry per grant:

```json
{"handle": "<44-char base64>", "operation": "http_broker",
 "resource": "https://api.github.com/repos/OWNER/REPO", "methods": "GET",
 "injection": "bearer", "status": "active", "expiry": "2027-01-01T00:00:00Z"}
```

`invoke_capability` returns the projected response:

```json
{"status_code": 200,
 "headers": {"Content-Type": "application/json; charset=utf-8",
             "Link": "<...>; rel=\"next\"", "X-RateLimit-Remaining": "4998"},
 "body": "[{\"number\":41,\"state\":\"open\",\"title\":\"...\"}]",
 "truncated": false}
```

Headers are limited to `Content-Type`, `Content-Length`, `ETag`,
`Last-Modified`, `Link`, `Retry-After` and `X-RateLimit-*`; the body is capped
at 32 KiB; every spelling of the token becomes `[redacted]`, even when the
upstream echoes it back. A wrong or newline-terminated token returns only
`{"code":"denied","message":"request denied"}`, and the reason is in
`tremelay audit list --path "$HOME/.tremelay/vault.db" --action broker_http`.

## 6. Lock and revoke

```sh
tremelay lock                                        # zeroises and stops the daemon
tremelay grant revoke --path "$HOME/.tremelay/vault.db" --id GRANT_ID
```

Either one makes the next agent call fail closed. While the daemon is unlocked,
anything running as you can use this agent's grants — see
[the headless daemon guide](../headless-daemon.md) and
[ADR 0024](../adr/0024-headless-unlock-daemon.md).

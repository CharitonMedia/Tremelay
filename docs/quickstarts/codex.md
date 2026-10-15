# Quickstart: Codex

Codex calls an HTTPS API through a credential it never sees. Run it once with
the throwaway secret below, then swap in a real one.

Replace `/home/you` with your own `$HOME` wherever a config needs a literal
path. Windows differences are at the bottom.

## 1. Install

```sh
go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest   # Go toolchain per go.mod
"$(go env GOPATH)"/bin/tremelay --help
```

Note that absolute path. TOML expands nothing, so the config needs it literally.

## 2. Vault, credential, agent, grant

Each command asks for your vault passphrase and prints one audit line to
stderr; ids go to stdout.

```sh
mkdir -p "$HOME/.tremelay" && chmod 700 "$HOME/.tremelay"
tremelay vault create --path "$HOME/.tremelay/vault.db"
```

`printf '%s'` writes the secret with **no trailing newline**. The broker
refuses a secret holding any byte outside printable ASCII, so a stored newline
turns every call into `request denied` with `upstream_error` in the audit.

```sh
umask 077
printf '%s' 'dummy-quickstart-secret' > "$HOME/.tremelay/demo.secret"
CRED=$(tremelay credential put --path "$HOME/.tremelay/vault.db" \
  --label demo --type api_key --secret-file "$HOME/.tremelay/demo.secret")
rm -f "$HOME/.tremelay/demo.secret"   # the vault holds it now
```

For a real token, `read -rs TOKEN` first and `printf '%s' "$TOKEN"` into the
file instead of the literal above.

```sh
tremelay agent create --path "$HOME/.tremelay/vault.db" --label codex \
  --token-file "$HOME/.tremelay/codex.token"
```

That prints the agent id and then the token path, on two lines — note the id.
The token itself is never printed, and the file is created 0600.

An `http_broker` resource must be `https` with a public DNS hostname (at least
two labels, lowercase). IP literals, loopback, and private or special-use names
such as `localhost` or `*.internal` are refused.

```sh
tremelay grant create --path "$HOME/.tremelay/vault.db" \
  --agent AGENT_ID --credential "$CRED" \
  --operation http_broker \
  --resource 'https://httpbin.org/anything' \
  --method GET --inject bearer \
  --expires 2027-01-01T00:00:00Z
```

httpbin echoes the request back, which is how you see the redaction work. A
real grant has the same shape — only the resource changes:

```sh
  --resource 'https://api.github.com/repos/OWNER/REPO'
```

Either way the grant allows `GET` under that one prefix and nothing else: no
other repo, host or method. See [ADR 0025](../adr/0025-http-broker-v1.md).

## 3. Unlock once, in its own terminal

```sh
tremelay daemon --vault "$HOME/.tremelay/vault.db" --idle-timeout 8h
```

At a terminal it prompts for the passphrase. Non-empty `TREMELAY_PASSPHRASE`
works without a prompt but is not recommended ([passphrase from the
environment](../headless-daemon.md#passphrase-from-the-environment)). It prints
its endpoint path and serves until you lock it. Keep it in its own terminal or
`tmux`/`screen` window ([keeping the daemon
running](../headless-daemon.md#keeping-the-daemon-running)): the key lives
nowhere else. Control-plane commands keep working while it runs; it re-reads the
vault in place with the key it already holds.

## 4. Register the server with Codex

```sh
codex mcp add tremelay --env XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" -- \
  /home/you/go/bin/tremelay mcp --daemon --token-file /home/you/.tremelay/codex.token
```

That writes the `command`, `args` and `env` keys into `~/.codex/config.toml`.
The same block by hand, with optional timeouts:

```toml
[mcp_servers.tremelay]
command = "/home/you/go/bin/tremelay"
args = ["mcp", "--daemon", "--token-file", "/home/you/.tremelay/codex.token"]
startup_timeout_sec = 10
tool_timeout_sec = 30

[mcp_servers.tremelay.env]
XDG_RUNTIME_DIR = "/run/user/1000"
```

**On Linux the `env` entry is required.** Codex launches MCP servers with a
scrubbed environment — `HOME`, `LANG`, `LOGNAME`, `PATH`, `PWD`, `SHELL`,
`TERM`, `TMPDIR`, `USER` — and `XDG_RUNTIME_DIR` is not in it. Without it
`tremelay` looks for the daemon in the wrong place and exits with `no unlocked
daemon is reachable`. On macOS `XDG_RUNTIME_DIR` is normally unset, both sides
fall back to `$TMPDIR/tremelay-<uid>`, and `TMPDIR` does survive the scrub; if
a call still reports no reachable daemon there, add `TMPDIR` the same way.
`codex mcp list` shows the entry. The timeouts can be short because this
command never prompts and runs no KDF.

## 5. First call

With the daemon unlocked, ask Codex:

> Use the tremelay MCP server. Call `list_capabilities`, then
> `invoke_capability` on the active `http_broker` handle with `method: GET`
> and `path: /anything/hello`. Show me the status code and the `Authorization`
> header in the response body.

Interactive Codex asks you to approve each tool call. Non-interactive
`codex exec` cannot ask, so it refuses with `MCP tool call requires approval`;
approve this server's tools for that run:

```sh
codex exec -c 'mcp_servers.tremelay.default_tools_approval_mode="approve"' "<the prompt above>" </dev/null
```

`list_capabilities` returns one entry per grant:

```json
{"handle": "<44-char base64>", "operation": "http_broker",
 "resource": "https://httpbin.org/anything", "methods": "GET",
 "injection": "bearer", "status": "active", "expiry": "2027-01-01T00:00:00Z"}
```

`invoke_capability` returns the projected response. httpbin reflects the
header the broker injected, and it comes back redacted (body abridged):

```json
{"status_code": 200,
 "headers": {"Content-Type": "application/json", "Content-Length": "428"},
 "body": "{\n  \"headers\": {\n    \"Authorization\": \"Bearer [redacted]\", \n    \"Host\": \"httpbin.org\"\n  }, \n  \"method\": \"GET\", \n  \"url\": \"https://httpbin.org/anything/hello\"\n}",
 "truncated": false}
```

Response headers are limited to `Content-Type`, `Content-Length`, `ETag`,
`Last-Modified`, `Link`, `Retry-After` and `X-RateLimit-{Limit,Remaining,Reset,Used,Resource}`; the body is capped
at 32 KiB; the secret's common encodings become `[redacted]`. A denial is only
`{"code":"denied","message":"request denied"}` — the reason is in your audit.

## 6. Day two

All three work against the running daemon. Nothing restarts, nothing
re-prompts, and `config.toml` never changes again.

```sh
# Widen or narrow authority. The next agent call sees it.
tremelay grant create --path "$HOME/.tremelay/vault.db" --agent AGENT_ID --credential "$CRED" \
  --operation http_broker --resource 'https://api.github.com/repos/OWNER/REPO' \
  --method GET --inject bearer --expires 2027-01-01T00:00:00Z
tremelay grant revoke --path "$HOME/.tremelay/vault.db" --id GRANT_ID

# Replace the token at the path the config already points at. The old token is
# refused on its next call, even on a connection Codex already holds.
tremelay agent token rotate --path "$HOME/.tremelay/vault.db" --agent AGENT_ID \
  --token-file "$HOME/.tremelay/codex.token"

# Stop everything. The next agent call fails closed.
tremelay lock
```

`agent token revoke` cuts access while keeping the agent and its grants;
`agent token issue` gives it back later (delete the stale file first and reuse
the same path). You never have to recreate an agent. See
[the headless daemon guide](../headless-daemon.md).

## Windows

Same commands in PowerShell, with Windows paths and no `umask`:

```powershell
go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest
& "$(go env GOPATH)\bin\tremelay.exe" --help

New-Item -ItemType Directory -Force "$env:USERPROFILE\.tremelay" | Out-Null
[IO.File]::WriteAllText("$env:USERPROFILE\.tremelay\demo.secret", 'dummy-quickstart-secret')
```

`WriteAllText` writes no trailing newline, which is the point of `printf '%s'`
above. The daemon serves on the named pipe `\\.\pipe\tremelay-<your SID>`
instead of a socket, so there is no `XDG_RUNTIME_DIR` and no `env` block to
add; `daemon`, `lock` and `mcp --daemon` are otherwise identical. TOML
single-quoted strings take Windows paths without escaping:

```toml
[mcp_servers.tremelay]
command = 'C:\Users\you\go\bin\tremelay.exe'
args = ['mcp', '--daemon', '--token-file', 'C:\Users\you\.tremelay\codex.token']
```

`tremelay ssh-agent` is Unix-only and fails closed on Windows; nothing on this
page depends on it.

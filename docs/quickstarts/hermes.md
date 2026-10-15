# Quickstart: Hermes

Hermes calls an HTTPS API through a credential it never sees. Run it once with
the throwaway secret below, then swap in a real one.

Replace `/home/you` with your own `$HOME` wherever a config needs a literal
path. Windows differences are at the bottom.

## 1. Install

```sh
go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest   # Go toolchain per go.mod
"$(go env GOPATH)"/bin/tremelay --help
```

Note that absolute path. YAML expands nothing, so the config needs it literally.

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
tremelay agent create --path "$HOME/.tremelay/vault.db" --label hermes \
  --token-file "$HOME/.tremelay/hermes.token"
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

With a terminal it prompts for the passphrase; a user service needs
`TREMELAY_PASSPHRASE` instead ([headless daemon](../headless-daemon.md#run-the-daemon-as-a-user-service)).
It prints its endpoint path and serves until you lock it. Keep it in its own
terminal, `tmux` window or user service: the key
lives nowhere else. Control-plane commands keep working while it runs — it
re-reads the vault in place with the key it already holds.

## 4. Register the server with Hermes

Add this under `mcp_servers:` in `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  tremelay:
    command: /home/you/go/bin/tremelay
    args: [mcp, --daemon, --token-file, /home/you/.tremelay/hermes.token]
    protocol: legacy
    connect_timeout: 10
    supports_parallel_tool_calls: false
```

`protocol: legacy` selects the initialize-based lifecycle this server speaks.
Leave parallel tool calls off: exact grants are the control, and the endpoint
admits one call at a time. `connect_timeout` can be short because this command
never prompts and runs no KDF.

Check it before you restart Hermes:

```sh
hermes mcp test tremelay
```

It should report connected and three tools discovered — `list_capabilities`,
`describe_capability`, `invoke_capability`.

## 5. First call

With the daemon unlocked, ask Hermes:

> Use the tremelay MCP server. Call `list_capabilities`, then
> `invoke_capability` on the active `http_broker` handle with `method: GET`
> and `path: /anything/hello`. Show me the status code and the `Authorization`
> header in the response body.

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
re-prompts, and `config.yaml` never changes again.

```sh
# Widen or narrow authority. The next agent call sees it.
tremelay grant create --path "$HOME/.tremelay/vault.db" --agent AGENT_ID --credential "$CRED" \
  --operation http_broker --resource 'https://api.github.com/repos/OWNER/REPO' \
  --method GET --inject bearer --expires 2027-01-01T00:00:00Z
tremelay grant revoke --path "$HOME/.tremelay/vault.db" --id GRANT_ID

# Replace the token at the path the config already points at. The old token is
# refused on its next call, even on a connection Hermes already holds.
tremelay agent token rotate --path "$HOME/.tremelay/vault.db" --agent AGENT_ID \
  --token-file "$HOME/.tremelay/hermes.token"

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
instead of a socket; `daemon`, `lock` and `mcp --daemon` are otherwise
identical. In YAML, single-quote Windows paths so the backslashes stay
literal:

```yaml
    command: 'C:\Users\you\go\bin\tremelay.exe'
    args: [mcp, --daemon, --token-file, 'C:\Users\you\.tremelay\hermes.token']
```

`tremelay ssh-agent` is Unix-only and fails closed on Windows; nothing on this
page depends on it.

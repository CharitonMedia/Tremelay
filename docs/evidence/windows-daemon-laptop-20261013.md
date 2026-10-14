# Windows daemon acceptance on Patrick's laptop, 2026-10-13 and 2026-10-14

Commit under test: 9305cf2 (branch `v1-windows-daemon`), cross-built `GOOS=windows GOARCH=amd64`
on render-1. Machine: LAPTOP-T09K3E6A, Windows, AMD64, user `patri`, reached over `ssh laptop`
(an elevated OpenSSH session). Script: [windows-daemon-laptop-accept.ps1](windows-daemon-laptop-accept.ps1).
Throwaway vault in `%TEMP%`, random passphrase held only in process env, dummy `api_key` credential
`dummy-demo-secret`, one agent with a token file, one `http_broker` grant
(`GET https://httpbin.org/anything`, bearer). Everything was deleted after the run.

1. `tremelay agent create --token-file` wrote a file whose DACL has exactly one entry:
   `LAPTOP-T09K3E6A\patri FullControl Allow` (no SYSTEM, no Administrators).
2. `tremelay daemon --vault v.db --idle-timeout 10m` unlocked once and served
   `\\.\pipe\tremelay-S-1-5-21-…-1001-accept3b` (`TREMELAY_DAEMON_INSTANCE=accept3b`).
3. With `TREMELAY_PASSPHRASE` cleared, a raw MCP stdio client launched
   `tremelay mcp --daemon --token-file cc.token`: `initialize` OK, `list_capabilities` returned the
   grant, `invoke_capability` `GET /anything/windows-check` returned 200 with httpbin's echo
   `"Authorization": "Bearer [redacted]"`.
4. A random 32-byte hex token in an owner-only file: `daemon refused the agent token`, exit 1;
   audit `daemon_auth result=denied`, no agent attribution.
5. `tremelay lock` → `locked`, daemon process exited; the next `mcp --daemon` with the valid token:
   `no unlocked daemon is reachable`, exit 1.
6. `audit list --action daemon_auth`: allowed rows name the agent, one denied row; `audit verify`
   passed. `dummy-demo-secret` appeared in no output file and not in the vault.

On 2026-10-13 the Claude Code step could not run (`claude -p` on the laptop failed with
`OAuth session expired`). Desk's MCP bridge runs as `NT AUTHORITY\SYSTEM` and cannot stand in.

## Re-run with Claude Code, 2026-10-14

Commit under test: d70c0c7 (v1 head), cross-built `GOOS=windows GOARCH=amd64` on render-1; same
script, same laptop, Claude Code 2.1.296 logged in by Patrick. Every step above repeated with the
same results (owner-only token DACL `LAPTOP-T09K3E6A\patri FullControl Allow`; pipe
`\\.\pipe\tremelay-S-1-5-21-…-1001-accept3b`; raw MCP client 200 with `Bearer [redacted]`; random
token refused, exit 1, audit `daemon_auth result=denied`; `lock` exited the daemon and the next
connection got `no unlocked daemon is reachable`, exit 1; `audit verify` passed;
`dummy-demo-secret` in no output file and not in the vault; temp dir removed). New:

7. Claude Code, started as `claude -p --strict-mcp-config --mcp-config mcp.json` with only the
   three tremelay MCP tools allowed and `TREMELAY_PASSPHRASE` cleared from its environment, whose
   server command is `tremelay mcp --daemon --token-file cc.token`, replied:

   ```
   HTTP status: 200
   URL httpbin echoed: `https://httpbin.org/anything/windows-check`
   Authorization header httpbin echoed: `Bearer [redacted]`
   ```
   `claude exit=0`. Its call shows up as the first `daemon_auth result=allowed` row (seq 10).

Observed: a named pipe has no half-close, so `mcp --daemon` ends the session when its stdin
closes. A client that writes requests and closes stdin before reading loses the replies; MCP
clients keep stdin open for the session, so this only affects ad-hoc piping. Also, an elevated
shell creates files owned by `BUILTIN\Administrators`; a hand-made token file is refused for that
reason, while files written by `tremelay agent create` set the owner explicitly.

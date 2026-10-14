# Daemon reload (3d) and agent token custody (3c) on render-1 (Linux), 2026-10-14

Commits under test: 44d9866 and, re-run with identical results after review fixes, 8d21ee3 (branch `v1-daemon-reload-tokens`, on v1 4db8ea5). Throwaway
tmpfs vault, generated passphrase in a 0600 file, private `XDG_RUNTIME_DIR`, dummy `api_key`
credential, `http_broker` grants on `https://httpbin.org/anything/{one,two,three}` (GET, bearer).
Claude Code ran as `claude -p --strict-mcp-config --mcp-config mcp.json` with server command
`tremelay mcp --daemon --token-file cc.token`; that `mcp.json` was written once and never edited.
The daemon was started once and never restarted; `TREMELAY_PASSPHRASE` was unset in its parent
shell after unlock and set only for individual human CLI commands. Everything was deleted after.

1. Agent created with `agent create` and no `--token-file` (no token file exists). With the daemon
   running, `agent token rotate --token-file cc.token` wrote `-rw-------` cc.token; Claude Code
   then called grant one: 200, httpbin echoed `Authorization: Bearer [redacted]`.
   (`agent token issue` on that agent refused with `agent already holds a token; rotate it instead`:
   `agent create` always seals a digest. A truly pre-ADR-0024 agent with no digest is covered by
   `TestAgentTokenCustody` in internal/vault.)
2. `grant create` for `/anything/two` while running: Claude Code's next session listed and called
   both grants, 200 each.
3. `grant revoke` of grant one: the next session listed it `revoked` and called only grant two.
4. `agent token rotate` to the same path: file content changed; Claude Code with the unchanged
   `mcp.json` called grant two, 200.
5. The pre-rotation token: `daemon refused the agent token`, exit 1.
6. `agent token revoke`: the current token is refused (exit 1). `agent token issue` to the same path:
   Claude Code called grant two again, 200 — same agent id, same grants.
7. Daemon still alive after steps 1–6, no passphrase re-entry.
8. A further `grant create`, then the newest audit row's hash overwritten in the SQLite file while
   unlocked: the next agent connection was refused (exit 1) and the daemon exited with
   `daemon can no longer serve this vault and has locked; inspect the vault audit, then restart it`.
9. `dummy-live-secret` appeared in no output, log or vault file.

Note: after the tamper, the refused client is told `daemon refused the agent token` (the daemon
fails closed before reporting why); the daemon's own stderr carries the lock diagnostic.

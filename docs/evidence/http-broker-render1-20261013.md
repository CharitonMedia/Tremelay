# HTTP broker acceptance on render-1 (Linux), 2026-10-13

Commits under test: 0d3f731 + e48d9fc (branch `v1-http-broker`, rebased on v1 3bc4de2), served
through the ADR 0024 daemon to Claude Code (`claude -p`, strict MCP config,
`tremelay mcp --daemon --token-file ...`). Throwaway tmpfs vault with a generated passphrase,
deleted after the run. Two `http_broker` grants for one agent, both `GET` with bearer injection:

- `https://api.github.com/repos/CharitonMedia/Tremelay`, credential = the operator's real GitHub
  token (read-only use; written to the vault from `gh auth token`, never printed).
- `https://httpbin.org/bearer`, credential = a random canary string. httpbin echoes the bearer
  token in its JSON body.

Results through MCP `invoke_capability`:

1. `GET /repos/CharitonMedia/Tremelay/issues?state=all&per_page=3` → 200, body with issues #49,
   #48, #47, `X-RateLimit-Remaining` returned.
2. `GET /repos/CharitonMedia/Tremelay` → 200, `full_name` and `visibility` returned.
3. `GET /repos/CharitonMedia/Other` → generic `denied`; audit `denied_path`, no `allowed` row
   (credential never sent).
4. `GET https://httpbin.org/bearer` → 200, body `{"authenticated": true, "token": "[redacted]"}`.
5. A scan of the full Claude Code stream-json transcripts, the daemon log, `tremelay audit list`
   output and the raw vault file found no occurrence of either credential (raw, base64,
   URL-encoded, or a 12-character prefix/suffix of the GitHub token).

Setup note: the first GitHub attempt stored the token with a trailing newline; the broker
refused it before sending (`upstream_error`, no `allowed` row). After `credential replace`
with the exact token, the calls above succeeded.

# Quickstarts executed on render-1 (Linux), 2026-10-14

Docs under test: docs/quickstarts/ at branch `v1-quickstarts` (binary built from that tree, which is
v1 17eee51 plus docs only). Each page ran in its own tmpfs `HOME` and private `XDG_RUNTIME_DIR`, with
only the client's own auth made available; real client configs were not edited. The secret was the
pages' dummy value; it appeared in no captured output. Everything was deleted afterwards.

Deviations, the same on every page:
- Install: `go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest` was NOT run, because until
  `v1.0.0` is tagged `@latest` resolves to the pre-release `v0.9.0-dryrun.1`, which predates the broker
  and daemon. The v1 binary was placed at `$HOME/go/bin/tremelay` instead and the page's
  `"$(go env GOPATH)"/bin/tremelay --help` check ran verbatim. Re-run the install line after the tag.
- Passphrase from `TREMELAY_PASSPHRASE` (a 0600 file) instead of the interactive prompt; the daemon ran
  in the background instead of "its own terminal", and the variable was unset before any client ran.
- Placeholders (`AGENT_ID`, `/home/you`, `GRANT_ID`, `OWNER/REPO`) substituted; the "ask Claude Code"
  steps ran as `claude -p` with the page's prompt text.

## Claude Code (claude-code.md)
1. Sanity `--help`: OK. 2. vault create, credential put (`printf '%s'`), agent create (token file
`-rw-------`), http_broker grant on `https://httpbin.org/anything`: all `result=allowed`.
3. `tremelay daemon --vault … --idle-timeout 8h`: endpoint printed.
4. `claude mcp add --transport stdio --scope local tremelay -- …/tremelay mcp --daemon --token-file …`;
`claude mcp list`: `tremelay … ✔ Connected`.
5. First call: status **200**, `Authorization: Bearer [redacted]`.
6. Day two, daemon still running: a second grant (api.github.com/repos/CharitonMedia/Tremelay) created
and revoked; `agent token rotate` to the same path; next Claude Code call with the unchanged config:
200, `Bearer [redacted]`. `tremelay lock` → `locked`; the next call failed to connect (fail closed).

## Generic MCP (generic-mcp.md)
Same vault and daemon: the page's own `agent create --label myagent --token-file …/myagent.token` and
grant, then its `{"mcpServers": {"tremelay": {"command": …, "args": ["mcp","--daemon","--token-file",…]}}}`
JSON verbatim (paths substituted), consumed by `claude -p --strict-mcp-config --mcp-config` as the
client: status **200**, `"Authorization": "Bearer [redacted]"`.

## Codex (codex.md), run by a delegated subagent, isolated HOME
1–4 PASS: same CLI flow; `codex mcp add` wrote the page's config.toml block; `codex mcp list` shows it
enabled. 5: `codex exec` with the page's prompt as first written FAILED with
`MCP tool call requires approval, but approval policy is never`; with
`-c 'mcp_servers.tremelay.default_tools_approval_mode="approve"'` it returned 200,
`"Authorization": "Bearer [redacted]"`. The page now documents that flag for `codex exec` (interactive
Codex prompts for approval instead). 6 PASS: grant create/revoke (the revoked grant then lists as
`"status":"revoked"`), rotate with unchanged config → 200 redacted, `lock` → fails closed.

## Hermes (hermes.md), run by a delegated subagent, isolated HOME/HERMES_HOME
1–3 PASS. 4: the page's `mcp_servers` block; `hermes mcp test tremelay`: Connected, 3 tools.
5: `hermes -z` with the page's prompt: real `list_capabilities` and `invoke_capability` calls, 200,
`Bearer [redacted]`. 6 PASS: grant create/revoke, rotate with unchanged config.yaml → 200 redacted,
`lock` → fails closed. The real `~/.hermes/config.yaml` was not modified (mtime unchanged).
Note: the Hermes model turn used the OpenAI API key from `~/.hermes/.env` (copied into the isolated
home), i.e. a paid API key; this is disclosed in the orchestrator report.

## Install line, after the v1.0.0 tag (2026-10-14, orchestrator)

The one deviation above is closed. On render-1, with `go env GOPROXY` =
`https://proxy.golang.org,direct`:

- `go install github.com/CharitonMedia/Tremelay/cmd/tremelay@v1.0.0` downloaded
  `v1.0.0`, switched to go1.26.9 as the pages say it would, and wrote the binary;
  `tremelay -h` printed the control-plane usage.
- `go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest` resolved to
  `v1.0.0` and produced a byte-identical binary (`cmp` clean), so the pages'
  `@latest` line now installs this code rather than `v0.9.0-dryrun.1`.
- The published `tremelay_v1.0.0_linux_amd64.tar.gz`, downloaded from the release
  and checked by name against `SHA256SUMS`, verified OK, and the extracted binary
  printed the same usage.

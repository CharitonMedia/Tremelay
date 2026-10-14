# Headless daemon acceptance on render-1 (Linux), 2026-10-13

Commit under test: ae6e9a4 (branch `v1-headless-daemon`). Throwaway vault on tmpfs with a
generated passphrase and a disposable Ed25519 key; two agents (`claude-code`, `hermes`), each
with its own 0600 token file and one `local_artifact_attest` grant. `XDG_RUNTIME_DIR` pointed
at a private 0700 directory. All of it was deleted after the run.

1. `tremelay daemon --vault v.db --idle-timeout 2h` unlocked once; endpoint
   `run/tremelay/daemon.sock` created `srw-------` inside a `drwx------` directory.
2. Claude Code (`claude -p --strict-mcp-config --mcp-config ...`, server command
   `tremelay mcp --daemon --token-file cc.token`): `list_capabilities` returned the one grant;
   `invoke_capability` returned an Ed25519 signature over the payload. No prompt.
3. Hermes native MCP runtime (installed `~/.hermes/hermes-agent` modules
   `register_mcp_servers` / `_make_tool_handler`, isolated `HERMES_HOME`, no model turn), server
   command `tremelay mcp --daemon --token-file hermes.token`: same list and invoke, signature
   returned. No prompt.
4. A random 32-byte token file: `daemon refused the agent token`, exit 1; audit row
   `daemon_auth result=denied` with no agent attribution.
5. `tremelay lock` → `locked`; daemon process exited. The next `tremelay mcp --daemon` with the
   valid Claude Code token: `no unlocked daemon is reachable`, exit 1.
6. `tremelay audit list --action daemon_auth`: `allowed` rows name the authenticated agent; no
   token, digest or passphrase appears in any row or output.

Revoked/suspended-agent refusal and audit is covered by unit tests in this commit, not repeated
here. macOS peer-credential code is compiled and unit-tested only; Windows is deferred (ADR 0024).

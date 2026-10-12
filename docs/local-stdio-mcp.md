# Human-unlocked local stdio MCP

`tremelay mcp serve` lets a local MCP client launch a vault-bound subprocess.
The human chooses the vault, agent, and trusted pinentry executable before any
protocol request. The client gets three tools: `list_capabilities`,
`describe_capability`, and `invoke_capability`. Only existing exact
`local_artifact_attest` grants are available; private keys never leave the vault.
This does not provision grants or finish the broader M10 authentication work.
See [ADR 0020](adr/0020-local-stdio-mcp.md) for the security contract.

## Prerequisites and unlock

- Build the CLI with the repository-pinned Go toolchain. Linux and macOS process
  pipes are implemented; Windows `mcp serve` fails closed. Linux is runtime-tested;
  macOS compilation alone is not terminal/display validation.
- Create the agent and its narrowly scoped attestation grant using the human CLI.
  The chosen agent ID is host authority, not an identity proven by MCP.
- Select an already-installed, trusted pinentry executable by absolute path.
  A GUI helper needs a working local display. A curses helper needs a separate
  interactive terminal. The helper and display/terminal stack are trusted with
  the passphrase. Tremelay does not install or configure them.
- Launch from a client that owns stdin/stdout pipes. Do not run this command with
  terminal stdin, redirect the protocol into a file, or send a passphrase on stdin.

The client launches this command, substituting real absolute paths and an
existing agent ID:

```text
/absolute/tremelay mcp serve --path /absolute/vault.db --agent AGENT_ID --pinentry /absolute/gui-pinentry
```

The helper prompts once per process. Its private Assuan pipes are separate from
MCP stdin/stdout. The passphrase is never a flag, config value, MCP message, or
log value. `TREMELAY_PASSPHRASE` is ignored by `mcp serve` and is not passed to the
helper. No passphrase cache or unattended unlock is enabled. Passphrases are
limited to 1024 bytes. Interactive unlock defaults to two minutes; the host can
set `--unlock-timeout` from `1s` through `5m`. Set the client's startup timeout
long enough for human entry and the KDF (for example, 150 seconds for the default).

For curses, the host can add `--pinentry-tty /absolute/terminal-device` for an
interactive terminal the human controls. `tty` in that separate terminal prints
its device path. The terminal must remain available and must not simultaneously
be used for another prompt. Many clients detach children from their own
controlling terminal, so assuming `/dev/tty` will work is unreliable. An
available GUI helper is often the simpler client-launch choice. No display or
terminal means unlock fails closed; it does not fall back to protocol stdin.

Cancellation, timeout, unavailable UI, malformed helper output, or helper failure
produces a fixed error on stderr and closes the process. The helper is reaped and
captured terminal settings are restored, including after signals. A client that
closes its pipes during the prompt cancels it. After unlock, EOF, SIGINT/SIGTERM,
and broken output stop service and lock the session after its work is joined.

Physical Ctrl-C with official pinentry-curses 1.2.1 can produce the fixed
`pinentry failed; check the selected terminal or display` diagnostic instead of
`pinentry cancelled`: its curses stack can exit with status 1 and close the
helper pipe without a structured cancellation reply. Unlock still fails closed,
the helper is reaped, and captured terminal settings are restored. An unknown
EOF or ordinary exit 1 is not relabeled as cancellation. Upstream added graceful
SIGINT handling in [Pinentry 1.3.x](https://dev.gnupg.org/T7046.html), following
[the curses/tty signal issue](https://dev.gnupg.org/T6641.html).

## Client configuration examples

These examples contain no passphrase. Keep the executable, helper and vault
paths under the trusted host's control. Do not let tool input rewrite them.

### Codex

```toml
[mcp_servers.tremelay]
command = "/absolute/tremelay"
args = ["mcp", "serve", "--path", "/absolute/vault.db", "--agent", "AGENT_ID", "--pinentry", "/absolute/gui-pinentry"]
startup_timeout_sec = 150
tool_timeout_sec = 30
```

The tested Codex 0.159.2 path uses its real app-server MCP implementation with a
fresh ephemeral thread and direct `mcpServerStatus/list` / `mcpServer/tool/call`.
It does not need a model turn or login. This is subprocess compatibility
proof, not a claim that every Codex UI or a dot installation has been configured.

### Claude Code (configuration reviewed; runtime untested here)

```sh
claude mcp add --transport stdio --scope local tremelay -- /absolute/tremelay mcp serve --path /absolute/vault.db --agent AGENT_ID --pinentry /absolute/gui-pinentry
```

Give the MCP startup handshake enough time for human entry with Claude Code's
`MCP_TIMEOUT` setting (milliseconds). Its documented client-runtime selection
supports initialize-based MCP, including fallback from modern discovery. See
[Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

### Hermes (configuration reviewed; runtime untested here)

```yaml
mcp_servers:
  tremelay:
    command: /absolute/tremelay
    args: [mcp, serve, --path, /absolute/vault.db, --agent, AGENT_ID, --pinentry, /absolute/gui-pinentry]
    protocol: legacy
    connect_timeout: 150
    supports_parallel_tool_calls: false
```

This deliberately selects the initialize lifecycle. See the
[Hermes MCP transport implementation](https://github.com/NousResearch/hermes-agent/blob/main/tools/mcp_tool_transport.py).
Do not use a parallel-call setting as a substitute for exact grants.

## Protocol and retry contract

The process supports exactly MCP `2025-06-18` and `2025-11-25`, with initialize,
one initialized notification, ping, tools/list, tools/call and matching
cancellation. The existing modern in-memory `2026-07-28` reference remains
separate. A modern discovery probe receives method-not-found so clients with an
explicit fallback can negotiate the compatibility profile. Arbitrary modern
clients without fallback are not supported.

Client identity, tracing/progress metadata, and capabilities are bounded advisory
input. They cannot choose the bound agent or cause sampling, elicitation,
logging, network, or other callbacks. The strict raw scanner still rejects
arrays, fractional numbers, duplicate fields, oversized frames, and unknown
arguments; this is a narrow profile, not every optional MCP feature.

There is one admitted call and at most two retained output frames. While the
prior response writer finishes, the stdio reader may wait for that exact write's
completion with a **10ms deadline**, then recheck normal admission. This avoids
a normal sequential client's write-return scheduling race. It is not a hard OS
scheduling-latency guarantee, and never releases a call before output finishes.
A held write still expires to busy; concurrent work is not queued for later
execution. The modern reference retains immediate-busy behavior.

A busy response is a correlated pre-dispatch denial. A timeout, EOF, cancellation,
or missing response is ambiguous: an attestation may already have happened.
Never automatically replay an invocation because its response was missing.
Cancellation does not recall an already released signature. Review the vault
audit through the human CLI. Audit persistence failure stops service and takes
precedence over routine cancellation.

An abrupt input close interrupts outstanding output. Cleanup still joins
transport work and locks the session, but skipped, short or failed response
writes can produce exit 1 with the fixed `mcp session failed; inspect the vault
audit before retrying an operation` diagnostic. A full successful raw stdio
write keeps that result if close wins the accounting mutex just afterward;
the closed connection still cannot admit new work. This does not authorize
replaying an operation with a missing response.

The host owns the unlocked session for this process. This command does not add
cross-process locking, remote identity proof, host-compromise protection, a
network listener, a raw-secret API, or signed-release assurance.

## Reproduce synthetic client evidence

The Linux smoke script requires an already-built CLI, official Python `mcp` and
`cryptography` packages, Codex app-server, and official pinentry-curses. It does
not install anything. It creates fresh disposable vaults, keys, private client
homes and one dedicated PTY; all unlock input is synthetic. It does not read
user client configuration, contact a model, or use production credentials.

```sh
go build -o /absolute/tremelay ./cmd/tremelay
python3 scripts/mcp_stdio_smoke.py --binary /absolute/tremelay --client both --sessions 10 --read-rounds 10
```

The script checks actual subprocess initialize/tool-list/list/describe/invoke,
independent Ed25519 verification, an authenticated audit chain with exactly one
allowed/completed attestation pair, no retries, helper no-echo/terminal
restoration, and server/helper exit after client close. Fixture setup uses the
existing human CLI's environment shortcut with generated test-only material;
the tested MCP subprocess itself receives none of it.

Normal Python client closure must leave server stderr empty. The Codex check
explicitly enables its MCP child-stderr INFO forwarding and rejects the fixed
session-failed diagnostic; its app-server must exit 0 without forced shutdown.
Both checks observe that the Tremelay process has exited. Neither public client
API exposes the child's exit status here, so an app-server exit 0 is not claimed
as a directly observed Tremelay exit 0.

Runtime evidence on Linux used Codex 0.159.2, official Python MCP 1.29.0,
cryptography 50.0.0, pinentry-curses 1.3.1, and Go 1.26.9. Ten fresh sessions per
client each completed ten direct sequential list/describe rounds and one invoke:
400 read-only tool calls plus 20 invocations total, with zero retries or
client-side settling sleeps. The official Go SDK
v1.8.0 tests also cover both supported revisions and modern auto-fallback.
CLI process tests cover prompt cancellation by signals/EOF/output close/timeout,
wrong-passphrase denial, broken stdout/SIGPIPE, and full-pipe cancellation.
Claude Code and Hermes were not installed or runtime-tested; GUI pinentry and
macOS UI behavior were not runtime-tested. Those limits are deliberate evidence
boundaries, not interoperability claims.

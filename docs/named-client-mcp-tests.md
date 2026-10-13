# Named-client credential-broker integration

`scripts/mcp_named_client_smoke.py` drives actual client implementations without
a model turn or provider account. It does not install software. It uses a fresh
private home/config directory for each run and an explicit environment allowlist.
No protected credential or vault passphrase enters client configuration, client
environment, a command argument, or the control protocol.

## Evidence boundaries

These are distinct demonstrations:

1. `scripts/mcp_stdio_smoke.py`: shipping CLI, real human-unlock helper, artifact
   attestation, and process custody. Its existing Linux Codex/Python evidence
   does not demonstrate a network credential broker.
2. `scripts/mcp_named_client_smoke.py`: actual named-client MCP transport and
   tool-result handling, the real broker/authorization/audit implementation, and
   a test-only protected TLS upstream. The fixture inserts its transport through
   existing trusted test seams. Production destination controls are unchanged.
3. A stock CLI operation against a production/public network service is not
   established by either fixture. In particular, a local TLS fixture does not
   prove the shipping DNS, public-address pinning, or external-service behavior.

The fixture captures its complete MCP output and verifies the credential does
not cross that boundary. Its scan of the shallow `observations/` directory is a
bounded snapshot during fixture finalization, not a claim about files written
after the fixture exits. An explicit manifest requires every raw client capture
and generated command/environment/configuration/status file. Captures are
written there from launch; generated configuration is saved before use. Missing
files, unexpected files, or a fixture scan count different from the complete
manifest fail acceptance. Native-home bundled code, caches, and SQLite files
are outside this file-scan claim.
The driver flushes all correlated tool responses before teardown; Hermes also
writes its native processed results before shutting down its client runtime.
Raw client output is captured through its eventual EOF; late shutdown output is
retained but not covered by the earlier fixture secret-scan snapshot.
No token, token digest, or unlock material is exported to a separate auditor.

The process observer currently requires POSIX. No native Windows, macOS GUI,
WSL-to-Windows, or product UI compatibility is implied by a Linux run.

## Pinned actual runtimes

- Codex CLI/app-server **0.159.2**: `initialize`, ephemeral `thread/start`,
  `mcpServerStatus/list`, and `mcpServer/tool/call`. Codex owns the MCP subprocess.
  After the seven calls the driver unsubscribes the exact ephemeral thread,
  waits for `thread/closed`, and validates the fixture receipt and Linux PID
  termination before closing app-server stdin. The fresh configuration sets
  `thread_unload_delay_secs=0`; this is a supported idle-unload option.
- Claude Code **2.1.296**, with control types inspected from official Claude
  Agent SDK **0.3.296**: stream-json `initialize`, `mcp_status`, `mcp_call`.
  This is the real Claude Code CLI's native subprocess MCP client, not an
  SDK-hosted replacement server or Anthropic API client. The driver supplies no
  user messages. Builtin tools are disabled, `--strict-mcp-config` names only the
  synthetic fixture, and `--permission-mode dontAsk` does not bypass permissions.
  Claude turns an MCP tool error into a control error; the intended revoked
  operation is accepted as a denial only if the independent fixture audit agrees.
  Read-only status requests wait under one monotonic deadline for an explicitly
  connected server with the exact three tools. No credential call is replayed.
- Hermes **v0.21.7**, commit
  `71d34bad1045610252eda02ee79549436896e784`: its native
  `register_mcp_servers`, registered tool-handler machinery, and
  `shutdown_mcp_servers`. The release's package metadata says `0.0.0`, so record
  the release and source commit. This is native-runtime evidence, not a Hermes
  chat/model/UI turn. `protocol: legacy` chooses initialize-based MCP;
  sampling/elicitation and parallel tool calls are disabled.

Hermes's model-free MCP path works with CPython **3.12.14**. The isolated
46-package dependency closure is pinned in `scripts/mcp_hermes_requirements.txt`.
Direct Hermes/MCP requirements and transitive versions follow that release's
pyproject/lock; `ruamel-yaml-clib==0.2.15` supplies its Python 3.12-specific
dependency. A complete Hermes application install has additional requirements;
this intentionally installs only the native MCP runtime path exercised here.

## Isolated preparation

Use an operator-owned disposable tools directory, separate from the repository
and all real client homes. Do not run `claude login`, `hermes setup`, or any
provider/account setup. Do not copy a real user's environment or configuration.

The official Claude Linux x64 package and SDK source package are:

- https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64/-/claude-code-linux-x64-2.1.296.tgz
- https://registry.npmjs.org/@anthropic-ai/claude-agent-sdk/-/claude-agent-sdk-0.3.296.tgz

Fetch the exact-version registry metadata, verify the tarball's `dist.integrity`,
then extract into separate local directories. No npm lifecycle script is needed
for the platform-specific native CLI. The SDK archive is inspected for the
control schema; the driver does not run SDK install hooks. Claude use remains
subject to the vendor's [legal terms](https://code.claude.com/docs/en/legal-and-compliance).

Verified archive SHA-256 values for this assessment:

```text
Claude native: eef5a2e2b09a5e7d2ce784d1b3ba335ae7fc6c7f6256c802a0ebf2c21e4fd0e1
Claude SDK:    e966be99b6f047d56165e2ec03822f17a49beebd48ac8efb91dab1e48bcf69a7
```

Retrieve Hermes source from the official NousResearch repository at the exact
commit above. Its runtime dependencies can be prepared with an isolated venv:

```sh
UV_CACHE_DIR="$TOOLS/cache" uv venv --python python3 "$TOOLS/hermes-venv"
UV_CACHE_DIR="$TOOLS/cache" uv pip sync --python "$TOOLS/hermes-venv/bin/python" \
  --index-url https://pypi.org/simple scripts/mcp_hermes_requirements.txt
UV_CACHE_DIR="$TOOLS/cache" uv pip check --python "$TOOLS/hermes-venv/bin/python"
```

`PYTHONPATH` for the test points only to that pinned Hermes checkout. The driver
sets this internally for the child, along with a fresh `HERMES_HOME` and `HOME`.

## Running the broker fixture

Build the repository's test-only host (it is never linked into `tremelay`):

```sh
go test -c ./internal/vault -o "$TOOLS/credential-fixture.test"
python3 scripts/mcp_named_client_smoke.py --client codex \
  --fixture "$TOOLS/credential-fixture.test" --codex /absolute/codex \
  --output-dir "$TOOLS/results/codex-unique-run"
python3 scripts/mcp_named_client_smoke.py --client claude \
  --fixture "$TOOLS/credential-fixture.test" --claude "$TOOLS/claude/claude" \
  --output-dir "$TOOLS/results/claude-unique-run"
python3 scripts/mcp_named_client_smoke.py --client hermes \
  --fixture "$TOOLS/credential-fixture.test" \
  --hermes-python "$TOOLS/hermes-venv/bin/python" \
  --hermes-source "$TOOLS/hermes-source" \
  --output-dir "$TOOLS/results/hermes-unique-run"
```

Each output directory must be new. Each session performs seven sequential tool
calls: list once, describe three exact grants, invoke each once. The calls prove
one authorized HTTP operation, one authorized GitHub issue-state operation, and
one revoked HTTP denial. The agent receives HTTP status only or the four allowed
GitHub fields. The protected TLS service independently rejects missing and
incorrect credentials. These two service checks are not MCP broker attempts.

Acceptance requires exact broker audit counts, two authenticated upstream
requests, two negative service checks, no unexpected upstream requests, verified
audit integrity, and credential absence. Negotiation-related protocol denials
are reported separately. The driver never replays an operation after a timeout
or missing response. Record the native client's exit, any shutdown escalation,
the fixture's observed shutdown, and its launch marker separately.

### Shutdown interpretation

Codex 0.159.2's normal thread shutdown sends process termination and drops its
running MCP service without awaiting that service's asynchronous transport
cleanup. Keeping app-server alive for the final fixture receipt avoids treating
outer-client exit as proof of fixture completion. The driver checks the full
receipt and PID independently. A caught signal can be an accepted idle
shutdown, but it is not reported as clean EOF; the native client's exit code is
not the fixture's exit code.

An earlier EOF-only Codex run completed the calls but left no final receipt;
that run is incomplete evidence. Supported thread unsubscribe now retains the
client runtime until the audited fixture receipt and PID exit are verified.

Pinned source support for this lifecycle:

- [Supported zero-delay thread unloading](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/core/config.schema.json#L7654-L7658)
- [Thread unsubscribe implementation](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/app-server/src/request_processors/thread_processor.rs#L1020-L1046)
- [Shutdown and thread-closed notification](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/app-server/src/request_processors/thread_lifecycle.rs#L408-L468)
- [MCP termination and service-state drop](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/rmcp-client/src/rmcp_client.rs#L1059-L1072)

## Shipping CLI custody

`scripts/mcp_named_client_custody.py` separately launches the shipping executable
through each actual client. It reuses the existing `Fixture` and
`PinentryTerminal` helpers without changing them. The trusted outer setup
process holds the disposable passphrase and signing key; the temporary private
key file is deleted before client launch. Official `pinentry-curses` receives
the passphrase through a dedicated no-echo PTY, never MCP stdin. Hermes receives
only a public challenge file, not the outer fixture's private material.

Run the controller with an interpreter containing the pinned `mcp` and
`cryptography` dependencies above:

```sh
"$TOOLS/hermes-venv/bin/python" scripts/mcp_named_client_custody.py \
  --binary /absolute/tremelay --pinentry /usr/bin/pinentry-curses \
  --client codex --codex /absolute/codex \
  --output-dir "$TOOLS/results/codex-custody-unique-run"
```

For Claude use `--client claude --claude /absolute/claude`. For Hermes use
`--client hermes --hermes-python "$TOOLS/hermes-venv/bin/python"
--hermes-source "$TOOLS/hermes-source"`. Each run uses a new private directory
and performs exactly one list, describe, and attestation invocation. Acceptance
requires independent public-signature verification, one allowed/completed audit
pair and valid chain, complete manifest-listed client output scans after EOF,
observed server/helper exit, and terminal restoration. Success is written only
after the generated vault and setup key are removed. This is attestation and
subprocess/unlock custody evidence; it does not demonstrate a public-network
credential operation or a hostile-host isolation boundary.
The shipping server PID count is a connected-session snapshot, not an exclusive
launch marker or a count of every historical launch attempt.

## Measured Linux acceptance: 2026-10-13

All six Linux named-client scenarios passed on combined broker and Windows-support source tree
`2e042a970d6853155254ac025f4ae79e64cfbaee`. The
[machine-readable evidence](evidence/named-client-mcp-2026-10-13.json) records
binary/driver hashes, audit heads, exact counts, shutdown classification, and
scan coverage without retaining protected material. The unchanged
[October 12 evidence](evidence/named-client-mcp-2026-10-12.json) records the
previous source and binaries as historical results.

| Actual runtime | Protected HTTP/GitHub + revoked denial | Shipping CLI + official pinentry attestation | Negotiated MCP version |
| --- | --- | --- | --- |
| Codex app-server 0.159.2 | Pass: 7 calls, 18 audit rows, 9 scanned files | Pass: 3 calls, 10 scanned files | Not exposed by native control |
| Claude Code 2.1.296 | Pass: 7 calls, 19 audit rows, 10 scanned files | Pass: 3 calls, 11 scanned files | Not exposed by native control |
| Hermes v0.21.7 | Pass: 7 calls, 18 audit rows, 12 scanned files | Pass: 3 calls, 13 scanned files | 2025-11-25 |

Every broker session completed exactly two authenticated upstream operations,
two negative upstream authentication self-checks, and one audited revoked-grant
denial. Claude additionally recorded one protocol denial, separately from the
revoked-grant denial. The fixture accepted observed idle signal shutdown for
Claude (SIGINT); Codex and Hermes used clean EOF. All native clients exited zero
without driver escalation, and all fixture PIDs terminated. These
observations do not expose the fixture's exit status.

Every custody session independently verified its signature and exact
allowed/completed audit pair, used official `pinentry-curses` 1.3.1 with restored
terminal state, observed helper/server termination, and removed its generated
vault and key file. All scans were complete within their declared scope; no
passphrase, signing key, or bearer token was observed. There were no model turns,
provider accounts, or credential-operation retries.

These named-client runs are Linux evidence. Native Windows/macOS client runs,
product GUIs, and Grok Bot remain untested here. An earlier client run without a
complete receipt does not count toward the six passing scenarios.

## Grok Bot

[Grok Bot](https://docs.x.ai/grok-bot/overview) is a distinct product. Its own
[Command MCP documentation](https://docs.x.ai/grok-bot/team-bots) describes local
servers on the conversation's computer, but actual execution requires an
authenticated Grok Bot session, eligible access, an available computer, and a
usable trusted unlock surface. None is supplied by this harness. No account is
created and no bot is contacted. Grok Build CLI, a generic MCP SDK, and the xAI
API do not count as Grok Bot runtime evidence.

## References

- [Claude Code CLI](https://code.claude.com/docs/en/cli-reference)
- [Claude MCP](https://code.claude.com/docs/en/mcp)
- [Hermes native discovery at the pinned commit](https://github.com/NousResearch/hermes-agent/blob/71d34bad1045610252eda02ee79549436896e784/tools/mcp_tool_discovery.py)
- [Hermes native handlers at the pinned commit](https://github.com/NousResearch/hermes-agent/blob/71d34bad1045610252eda02ee79549436896e784/tools/mcp_tool_handlers.py)
- [Hermes native shutdown at the pinned commit](https://github.com/NousResearch/hermes-agent/blob/71d34bad1045610252eda02ee79549436896e784/tools/mcp_tool_lifecycle.py)

## Hostbound SSH runtime acceptance

The separate [SSH acceptance driver and fixed receipt](named-client-ssh-tests.md)
uses the same actual Linux client runtimes and lifecycle controls for the bounded
ADR 0023 bridge. It verifies identity hiding, host binding, one hostbound Ed25519
signature and exact-grant/context denials. It uses no network service or remote
SSH login and does not replace the shipping-CLI custody lane above.

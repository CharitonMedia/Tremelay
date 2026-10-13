# Native Windows named-client custody acceptance

Status: **prepared locally, not executed on Windows**. This is a prospective
acceptance lane, not another passing result. It changes no production code.
Local-only changes append preparation, required native checks and allowlisted
receipt retention to the existing Windows workflow, without changing triggers
or permissions. They have not been published or run.
The existing [Windows GUI/Go SDK result](windows-gui-custody.md)
and [Linux named-client results](named-client-mcp-tests.md) remain separate.

## Exact scope

`TestWindowsNamedClientShippingGUI` runs the shipping `tremelay.exe` through one
actual pinned native runtime, driven by `scripts/mcp_windows_named_client.py`:

- Codex 0.159.2 app-server: initialize, ephemeral thread, MCP status/tool calls,
  thread unsubscribe and closure, then app-server EOF.
- Claude Code 2.1.296: stream-json initialize, MCP status and MCP calls. No user
  message/model turn is supplied; built-in tools are disabled and only the
  synthetic server is configured.
- Hermes v0.21.7, source commit
  `71d34bad1045610252eda02ee79549436896e784`: native server registration,
  registered tool handlers and shutdown. Sampling/elicitation and parallel calls
  are disabled. The Python MCP SDK is a dependency of Hermes, not a replacement
  for its native runtime.

The shared client driver retains its existing vendor control requests. A narrow
process factory supplies Windows pipe readers because Python's
[`select()` does not support Windows subprocess pipes](https://docs.python.org/3/library/select.html).
The Windows reader continuously drains output, bounds retained captures at
4 MiB per stream, enforces request deadlines, and requires both streams' EOF.
Any shutdown escalation fails acceptance. This is ordinary-output lifecycle
coverage; it does not establish blocked-output process cancellation.

The Go controller creates an encrypted vault with random synthetic passphrase
and Ed25519 key in memory. Two exact grants belong to one fixed agent; one is
already revoked. No plaintext key file is created. Only public configuration
and the challenge reach the driver or named runtime. The shipping CLI directly
launches the same pinned official GUI helper as the existing Windows fixture.
The controller reuses that fixture's PID/image-bound Win32 GUI automation,
fixed prompt/masked-control checks, ordinary OK action and bounded messages.
The passphrase enters only that owned helper's native password control.

The controller retains handles for the driver, actual named runtime, shipping
CLI and helper, checks direct parent/image relationships, and joins cleanup.
For Hermes it also pins and retains the known venv-redirector → base-Python
link, using the same base interpreter that created the venv; see
[CPython 3.14.8's launcher source](https://github.com/python/cpython/blob/v3.14.8/PC/venvlauncher.c).
Other wrapper-launchers or an unexpected process hierarchy fail closed. This is a
connected-session process observation, not an exclusive historical launch count.
It does not establish safety against a compromised host or arbitrary descendant
trees. It neither changes ACLs nor creates persistent security/access settings.
The controller additionally checks the pinned official helper and two known
adjacent DLL hashes from the existing GUI package receipt; extraction must still
preserve the complete official package layout.

Acceptance requires all of the following:

1. Exact three-tool inventory; exactly five sequential calls: list once,
   describe each grant, invoke each grant once. No credential-operation replay.
2. Independent public Ed25519 verification of the permitted attestation and
   refusal of the revoked operation.
3. Verified audit chain, exactly one allowed/completed pair and one
   `denied_revoked`, all attributed to the fixed agent, credential and exact
   issued grants. A vendor control error alone cannot prove the denial.
4. Official helper exit, native runtime exit zero, completed controller and
   full client-output capture with no escalation. Claude Code and Hermes
   require shipping CLI exit zero. Pinned Codex 0.159.2 on Windows may instead
   terminate the owned MCP server with code 1 as described below; this is
   accepted only after the host independently verifies the server was still
   running *after* every tool response and *before* Codex unsubscribes.
5. Post-EOF scans for passphrase/private-key bytes, base64 and hex across the
   complete manifest-listed captures/configuration, public receipts, controller
   output/launch configuration, operation audit records and encrypted vault.
   Native-client home files, bundled code, caches and databases are explicitly
   outside this scan. Synthetic vault removal precedes the final receipt.

The allowlisted final receipt contains counts, booleans, executable/driver
hashes and scope. Raw synthetic logs stay private and temporary. A missing
receipt, helper, graphical session, client, supported control response or
process handle is a failure in a selected lane, never a successful skip.
The ordinary suite skips this optional lane only when it was not selected;
`TREMELAY_TEST_WINDOWS_NAMED_REQUIRED=1` makes a missing selection fatal.

## Pinned Codex Windows MCP child termination contract

The exact tested Codex CLI is v0.159.2. Its
[`StdioServerProcessHandleInner::drop`](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/rmcp-client/src/stdio_server_launcher.rs)
and transport shutdown call `LocalProcessTerminator::terminate()` on Windows.
The same version's
[`JobObject` implementation](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/utils/pty/src/win/job.rs)
hard-terminates with `TerminateJobObject(..., 1)`, falling back to
`TerminateProcess(..., 1)` if job containment is unavailable. A one-valued
Windows MCP subprocess exit code by itself is therefore ambiguous: it may be
pinned-client teardown rather than a Tremelay failure, but it must **never**
be interpreted as proof of client-driven termination without more evidence.

The selected Codex-only lane uses a two-party, model-free barrier. After
five successful fixed MCP tool RPCs and **before** `thread/unsubscribe`,
the isolated client driver atomically publishes the fixed
`codex-pre-unsubscribe.json` marker and waits. The Go controller retains
the actual Tremelay process handle, validates the marker's exact public fields
and checks that `WaitForSingleObject(serverHandle, 0)` reports the server
still active. Only then does it write the public
`codex-server-alive.json` acknowledgement. The driver performs its normal
unsubscribe, observes `thread/closed` and closes the pinned native Codex
runtime. The controller may accept server exit code 1 only for this Codex
version with that verified liveness barrier. The fixed process tree, helper
custody, no-escalation client exit, exact signed response, revoked-grant
denial, durable audit and every existing post-EOF secret scan remain required.
Both barrier files are included in that scan.

This establishes the externally observable **ordering**, not an ETW/kernel
trace of the exact Windows TerminateJobObject call. It does not establish a
graceful MCP server return or protection against abrupt loss of uncommitted
operations. Other clients still require server exit zero and may not borrow
Codex's pinned termination exception. If Codex changes its version or process
lifetime, this exact contract must be re-evaluated, not silently generalized.
No production process behavior, MCP broker or release path changes.

## Reviewed acquisition pins

Use a disposable hosted Windows x64 runner and isolated tools directories.
These are source/metadata-reviewed preparation pins, **not executed evidence**.
Do not use a real user's client home, account, provider key, credential,
subscription, login or model turn. Do not run installers or package lifecycle
scripts for the native clients. Do not accept new legal terms implicitly through
account setup. Claude use remains subject to its
[vendor terms](https://code.claude.com/docs/en/legal-and-compliance).

### Codex

The [official 0.159.2 release](https://github.com/openai/codex/releases/tag/rust-v0.159.2)
and [release API metadata](https://api.github.com/repos/openai/codex/releases/tags/rust-v0.159.2)
provide this standalone native executable, callable with `app-server --stdio`:

- [codex-x86_64-pc-windows-msvc.exe](https://github.com/openai/codex/releases/download/rust-v0.159.2/codex-x86_64-pc-windows-msvc.exe)
- Size: `324702000` bytes
- SHA-256: `52f75c649bebb8001102a1dd129c1ea6d02b0940321e6d7e82ee0526753bd58a`

Download to the isolated tools directory and verify both size and SHA-256
before launch. This pin does not claim Authenticode verification. No Codex
Windows sandbox setup/service, shell execution or persistent permissions are
requested by this model-free lane. Any request for such setup is a blocker.

### Claude Code

The official npm platform package is
[`@anthropic-ai/claude-code-win32-x64` 2.1.296](https://registry.npmjs.org/@anthropic-ai/claude-code-win32-x64/2.1.296).
The registry reports `os=[win32]`, `cpu=[x64]`, and:

- [Exact native tarball](https://registry.npmjs.org/@anthropic-ai/claude-code-win32-x64/-/claude-code-win32-x64-2.1.296.tgz)
- SHA-512 SRI:
  `sha512-g2aYBzYM5YTDio0ulAoGIGgtGRMa08WAecer4wuOUrKPwVPRfyRdmoZI01BNS8jF9yupDmQycBMuBcVui/VGNw==`
- Downloaded archive size: `117726124` bytes
- Downloaded archive SHA-256:
  `f04bb1c18698dc6562912a573b031306225f5e202df4fe6bd2317351f5e492c5`

Verify the downloaded bytes against that exact SHA-512 value, then extract
members into a fresh tools subdirectory without executing npm hooks. Preserve
the package layout and use its native `claude.exe`. Confirm the archive's member
names and the executable before setting its path; do not infer successful
extraction from registry metadata. The reviewed archive contains exactly
`package/claude.exe`, `package/package.json`, `package/LICENSE.md`, and
`package/README.md`, with no links. Its bytes were inspected on Linux without
executing the Windows binary. The driver additionally requires version
2.1.296. [Native Windows is supported by the vendor](https://code.claude.com/docs/en/setup).
Git Bash is optional for current Claude Code; this lane disables built-in
tools and does not install or execute a shell tool.

### Python and Hermes

The prospective Windows interpreter is **CPython 3.14.8 x64**, a new runtime
boundary. Tested Linux CPython 3.12.14 results do not establish this runtime.
Python 3.12.14 is security-source-only and has no Windows entry in the official
[Actions version manifest](https://github.com/actions/python-versions/blob/main/versions-manifest.json).
Hermes's pinned pyproject identifies 3.14 as its supported runtime.

The Windows workflow provisions exact CPython 3.14.8 x64 with the official
`actions/setup-python` action pinned to commit
`ece7cb06caefa5fff74198d8649806c4678c61a1` (v6.3.0).
The [official Python version manifest](https://github.com/actions/python-versions/blob/main/versions-manifest.json)
lists the Windows x64 3.14.8 archive. When the hosted runner image does not
have that exact patch level, the pinned action can obtain the distribution
through the official Actions toolchain path. The preparation script still
requires the interpreter at
`RUNNER_TOOL_CACHE\Python\3.14.8\x64\python.exe`, checks version and
64-bit architecture independently, and records runner image/version and the
observed executable hash. It does not select a different version, run a
fallback installer, delete the toolcache, or upgrade pip. If provisioning
fails, the named-client runtime tests do not run, and no compatibility claim
is made. The workflow uses only the existing `contents: read` permission.
The [Actions-hosted 3.14.8 release](https://github.com/actions/python-versions/releases/tag/3.14.8-36806082737)
has [Windows x64 archive](https://github.com/actions/python-versions/releases/download/3.14.8-36806082737/python-3.14.8-win32-x64.zip),
size `33100332`, SHA-256
`2b7a12a17729d1833b81f84396254fb4d5b4f239fd851e6e3f4e3407fe51599c`.
The archive was downloaded, size/hash-checked and inspected without execution;
it contains the official installer and Actions setup script, not a portable
Python tree. Its hash is a provenance reference, not proof that the actual
runner interpreter equals bytes extracted from that archive. The pinned
setup-python action and official toolchain distribution are trusted to
provision Python; the executable hash is an observation. The Python driver
rejects other versions.

Retrieve the exact [Hermes source commit](https://github.com/NousResearch/hermes-agent/tree/71d34bad1045610252eda02ee79549436896e784)
with unchanged file bytes. The preparation script pins the official
[commit archive](https://codeload.github.com/NousResearch/hermes-agent/tar.gz/71d34bad1045610252eda02ee79549436896e784)
to `81181089` bytes and SHA-256
`a88ae3f634a3fd45050d3418d80b30ee5af51c89b9de40ec1ea3039d3024d77a`.
Its inspected contents have one commit-named root and no symbolic/hard links.
The driver verifies its existing five MCP module
hashes. Preserve LF bytes rather than applying Git `autocrlf` conversion to
those source files. Do not run `hermes setup` or install the full application.

Prepare an isolated venv with the wheels-only pinned runtime closure:

```powershell
& $Python3148 -m venv "$Tools\hermes-venv"
& "$Tools\hermes-venv\Scripts\python.exe" -m pip install --only-binary=:all: --require-hashes `
  --index-url https://pypi.org/simple -r scripts/mcp_hermes_windows_lock.txt
& "$Tools\hermes-venv\Scripts\python.exe" -m pip check
```

Check every command's exit status. Dependency or wheel absence fails preparation;
do not silently build native source packages or change pins. The Windows
extension to the Linux MCP-only closure adds upstream-pinned `pywin32==311`
(MCP 2.0.0's Windows process/job-object code), `colorama==0.4.6` (Click),
`portalocker==3.2.0` (Hermes's Windows discovery lock), and `tzdata==2025.3`.
`ruamel-yaml-clib` is conditional on Python below 3.14, matching ruamel.yaml's
dependency marker. These pins come from Hermes's
[lockfile](https://github.com/NousResearch/hermes-agent/blob/71d34bad1045610252eda02ee79549436896e784/uv.lock),
[discovery lock source](https://github.com/NousResearch/hermes-agent/blob/71d34bad1045610252eda02ee79549436896e784/tools/mcp_tool_loop.py),
and [MCP 2.0.0 metadata](https://pypi.org/pypi/mcp/2.0.0/json).
No pywin32 post-install script, service registration, elevation or system-wide
Python change is needed by the venv lane. Native imports still require execution
on Windows to establish that all pinned wheels load.

`mcp_hermes_windows_requirements.txt` is the human-readable version input;
`mcp_hermes_windows_lock.txt` pins one compatible Windows x64 CPython 3.14 wheel
SHA-256 for each of the 49 resolved packages. Resolution and wheel metadata
selection were done without installing or executing those Windows packages.
The preparation script uses the hash lock, wheels only, isolated pip with no
ambient configuration, fresh homes and no inherited provider credentials. It
never runs npm lifecycle hooks or Hermes setup. Each preparation subprocess has
a deadline and continuously drained 256 KiB-per-stream captures. Those raw
captures remain outside the artifact directory.

`--isolated` alone does not disable machine/site pip configuration. The clean
preparation environment also sets `PIP_CONFIG_FILE` to Windows `os.devnull`
(`nul`), following the [official pip configuration contract](https://pip.pypa.io/en/stable/topics/configuration/#pip-config-file).
Before the first pip network operation, the selected venv interpreter checks
that exact null-device value and loads `Configuration(isolated=True)`, requiring
its option set to be empty. It prints only a fixed confirmation; configuration
contents are never printed. An unavailable/changed configuration API or nonempty
result fails preparation. This is supported configuration-file suppression,
not a system security-setting change.

## Prospective native invocation

After review and authorization to run ordinary Windows CI, prepare the
[official GUI helper](windows-gui-custody.md#pinned-helper-without-installation),
build the shipping CLI and command test binary from the exact candidate, and
provide absolute paths. Use a new evidence filename for each client:

```powershell
$env:TREMELAY_TEST_WINDOWS_NAMED_REQUIRED = '1'
$env:TREMELAY_TEST_WINDOWS_NAMED_CLIENT = 'codex' # separately: claude, hermes
$env:TREMELAY_TEST_WINDOWS_PYTHON = $Python3148
$env:TREMELAY_TEST_WINDOWS_NATIVE = $NativeClientExe
$env:TREMELAY_TEST_WINDOWS_NAMED_DRIVER = "$Repo\scripts\mcp_windows_named_client.py"
$env:TREMELAY_TEST_WINDOWS_NAMED_EVIDENCE = "$Results\codex-windows-custody.json"
# Existing GUI preparation supplies WINDOWS_CLI and WINDOWS_PINENTRY.
# For Hermes, WINDOWS_NATIVE is its venv Python executable, and additionally:
# $env:TREMELAY_TEST_WINDOWS_HERMES_SOURCE = "$Tools\hermes-source"
go test -count=1 ./cmd/tremelay -run '^TestWindowsNamedClientShippingGUI$'
if ($LASTEXITCODE -ne 0) { throw 'Native named-client acceptance failed.' }
```

The local workflow patch appends the extraction-only preparation script, builds
one command test binary and runs the required Codex, Claude and Hermes cases
sequentially. Existing test/vet steps, workflow triggers and `contents: read`
permissions are unchanged. There is no signing, OIDC, provider account or
model-turn setup. Only after all three cases succeed does artifact retention
upload the four exact allowlisted JSON paths: `preparation.json` and the three
client custody receipts. No vault, raw log, archive, client home or capture
directory is uploaded. Receipt retention is seven days.

The preparation receipt is explicitly preparation-only and records source
commit/tree, observed runner/Python provenance and the verified artifact/lock
hashes. Runtime receipts are still necessary. This wiring is local and inert
until separately published; nothing has triggered it. Cross-compilation,
resolver metadata and source review
cannot establish GUI availability, inherited-pipe behavior, runtime package
imports, process hierarchy, shutdown semantics or audit/scanning success.
Even a future passing result records `inherited_handle_modes_observed=false`:
the controller does not inspect another process's inherited handle modes.
ADR 0022's per-client mode-observation requirement therefore remains open.
Successful use of a particular native runtime must not be generalized to
arbitrary overlapped handles or completion-port associations.

Native Windows HTTP/GitHub broker calls remain **unproved**: the existing
`TestMCPSyntheticCredentialFixture` is Linux/macOS-only. This custody lane does
not port that fixture or weaken its transport/receipt requirements. Grok Bot
also remains untested without its own authenticated eligible conversation and
computer/unlock surface; neither a generic SDK nor another xAI product counts.

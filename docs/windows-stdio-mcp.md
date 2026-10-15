# Windows `mcp serve` (pinentry) custody

This page documents the **pinentry stdio** path: `tremelay mcp serve` with a
native GUI pinentry helper and an inherited Windows byte-stream pipe. It is not
the recommended Windows integration for named MCP clients.

For Claude Code, Codex, Hermes, and other stdio clients, use the headless
daemon plus `tremelay mcp --daemon` instead. That route is documented in the
[quickstarts](quickstarts/README.md) and was exercised on a Windows laptop in
[windows-daemon-laptop-20261013.md](evidence/windows-daemon-laptop-20261013.md).

Windows process custody for `mcp serve` follows
[ADR 0022](adr/0022-windows-mcp-custody.md). The native component suite passed
on the Windows custody candidate. The [official-GUI fixture](windows-gui-custody.md)
records its separate shipping-CLI evidence. The combined broker/Windows candidate
still requires fresh gates; neither compilation nor a component test is a
production-credential release.

The minimum contract is a client launching Tremelay with ordinary inherited
Windows byte-stream pipe stdin/stdout and a directly invoked, trusted local
native GUI pinentry `.exe`. The human selects the vault, exact agent, and helper. Passphrases
stay in the helper's private pipes and are never protocol input, arguments,
configuration, logs, or environment credentials. Helper startup is bounded by
the existing unlock timeout. The helper is terminated and reaped on failure;
captured console modes are restored before a successful passphrase can return.

Windows `--pinentry-tty` is unsupported and fails closed. A GUI helper can operate
without an attached console but still requires a usable desktop/display. No
helper is installed or configured by Tremelay. Relative paths, UNC/device paths,
mapped network drives, and batch/shell helper scripts are outside this minimum
contract. Keep the executable and its DLL/plugin directory under trusted host
control. Tremelay does not verify a release signature on the helper.

## Host configuration

Use real absolute drive paths for the built CLI, the existing vault, and the
trusted helper. Keep the helper's same-package DLLs beside it. The helper runs
from that directory with a restricted environment, no shell, and no inherited
PATH or passphrase variables. Tremelay neither installs GnuPG nor starts
gpg-agent. A native GUI still needs a usable desktop even without a console.

For example, a Codex TOML configuration can express the launch without a shell
or escaping Windows backslashes. This is a configuration example, not measured
native Windows Codex interoperability:

```toml
[mcp_servers.tremelay]
command = 'C:\Tools\Tremelay\tremelay.exe'
args = ['mcp', 'serve', '--path', 'C:\Vaults\vault.db', '--agent', 'AGENT_ID', '--pinentry', 'C:\Tools\GnuPG\bin\pinentry-basic.exe']
startup_timeout_sec = 150
tool_timeout_sec = 30
```

Other clients use the same executable and argument vector in their own stdio
configuration. Replace these placeholders with host-selected values, including
an existing agent ID and exact operation grants. Do not add the passphrase to
configuration, environment, arguments, or MCP input. Do not launch the command
directly with console stdin or redirect stdout into a file: both protocol ends
must be supported pipes. The human unlocks once for each server process.

Windows `--pinentry-tty` remains unsupported; do not supply a Unix `/dev/tty`
path or use WSL results as native Windows evidence. Leave sufficient client
startup time for the human prompt and vault KDF. A missing GUI, cancellation, or
timeout fails closed with a fixed diagnostic instead of requesting protocol
input. Native client shutdown by `TerminateProcess` or a job object is not
proof that normal Go cleanup ran.

## Runtime evidence and limits

The ordinary Windows suite covers owned-handle independence/noninheritance,
prompt disconnect with buffered-input preservation, private helper cleanup,
console-mode restoration, and official-Go-SDK traffic over real anonymous
pipes. Its GUI preparation additionally extracts one exact hash-verified
official archive, builds the shipping CLI, and requires the GUI test to run.
The acquisition and acceptance contract are in the
[official-GUI fixture](windows-gui-custody.md).

Native Windows Codex, Claude Code, and Hermes on **`mcp serve`** passed the
narrowed synthetic acceptance recorded in
[windows-named-client-custody.md](windows-named-client-custody.md); the
**`mcp --daemon`** quickstart path has its own evidence (linked above). The
measured [Linux integrations](named-client-mcp-tests.md) do not stand in for
either Windows path. Each Windows client needs versioned runtime evidence,
including actual inherited handle behavior and shutdown; do not infer
compatibility from its implementation language. Arbitrary externally configured
overlapped handles and completion-port associations are outside the validated
contract.

Full-output/blocked-output process cancellation is not established by this slice.
Successful ordinary cases and cross-compilation do not demonstrate that process
behavior. The existing security requirements remain unchanged.

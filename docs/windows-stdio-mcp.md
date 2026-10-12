# Windows stdio MCP custody candidate

Windows process custody is implemented on the development branch described in
[ADR 0022](adr/0022-windows-mcp-custody.md). Native Windows runtime evidence is
pending. Cross-compilation is not a Windows support claim, and this is not a
production-credential release.

The intended minimum contract is a client launching Tremelay with owned Windows
byte-stream pipe stdin/stdout and a directly invoked, trusted local native GUI
pinentry `.exe`. The human selects the vault, exact agent, and helper. Passphrases
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

The existing Windows CI suite will discover the new Windows-only tests without
workflow changes. They cover synthetic ownership, prompt disconnect, private
helper cleanup, console-mode restoration, and a normal official-Go-SDK session
over real Windows anonymous pipes. They do not prove official GUI usability,
subprocess unlock with a named client, or actual Codex/Claude Code/Hermes
interoperability. Each client needs versioned native runtime evidence; do not
infer its inherited handle mode from the programming language alone.

Full-output/blocked-output process cancellation is not established by this slice.
Successful ordinary cases and cross-compilation do not demonstrate that process
behavior. The existing security requirements remain unchanged. Native GUI and
named-client runtime evidence is still pending.

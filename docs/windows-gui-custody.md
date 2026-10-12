# Windows official-GUI custody fixture

Status: native GUI evidence pending. This fixture extends the candidate in
[ADR 0022](adr/0022-windows-mcp-custody.md); preparing the files or compiling the
CLI does not establish that the GUI works.

## Pinned helper, without installation

The ordinary Windows workflow extracts the official GnuPG Windows package into
a fresh runner-temporary directory using the runner's existing 7-Zip. It checks
both the exact size and SHA-256 before extraction:

- Package: `gnupg-w32-2.5.24_20260923.exe`
- Size: `5804864` bytes
- SHA-256: `ea6f9dee2cccd83287432625b8b399173805add81d27067fcaf019c0c4da1ad8`
- [Official download](https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-2.5.24_20260923.exe)
- [Official checksum](https://gnupg.org/download/integrity_check.html)
- [Release and matching source archive](https://lists.gnupg.org/pipermail/gnupg-announce/2026q3/000516.html)

The [release's installer source](https://github.com/gpg/gnupg/blob/gnupg-2.5.24/build-aux/speedo/w32/inst.nsi)
places the native Win32 helper at `bin/pinentry-basic.exe`. Preparation preserves
the extracted directory layout and DLLs, and requires that helper plus
`libassuan-9.dll` and `libgpg-error-0.dll`. Those member checks are not proof of
the complete PE import closure; native fixture validation must establish that
the pinned helper loads with Tremelay's existing restricted environment.

Only official-source SHA-256 verification is claimed. The installer is never
executed. No GnuPG keyring, real credentials, gpg-agent, registry entries,
services, ACL changes, Developer Mode, or security-setting changes are needed.
The [runner image](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md)
provides 7-Zip; its [NSIS extractor](https://github.com/ip7z/7zip/blob/main/CPP/7zip/Archive/Nsis/NsisHandler.cpp)
reads package members without running installer actions. Nothing is installed
on a user computer.

## Required native acceptance

The workflow builds the shipping `tremelay.exe` into runner-temporary storage
before the unchanged `go test ./...` step. Preparation exports
`TREMELAY_TEST_WINDOWS_PINENTRY`, `TREMELAY_TEST_WINDOWS_CLI`, and
`TREMELAY_TEST_WINDOWS_GUI_REQUIRED=1`. Missing fixture files or an unusable
desktop must fail required acceptance rather than count as a successful skip.

The fixture connects the official Go MCP SDK to the built CLI, unlocks
through the actual official GUI helper, and exercises synthetic local signing,
denial, and audit. Fresh passphrases are created only in test-process memory;
synthetic private keys remain inside the disposable local vault workflow.
Passphrases must never enter MCP input, command arguments, environment values,
clipboard, plaintext files, logs, or artifacts.

Automation must target the owned helper's process and native password control,
then use its ordinary OK/Cancel behavior. Widget automation is not physical
keyboard evidence. A usable graphical session is a runtime prerequisite:
[Microsoft's CI guidance](https://learn.microsoft.com/en-us/windows/apps/develop/ai-assisted/testing)
does not prove that a particular runner session has one. Missing archive
members, dependency-loading failures, and display failures remain explicit
blockers; the fixture must not change security settings to work around them.

The ordinary suite discovers `TestWindowsMCPShippingCLIWithOfficialGUI`. Its
two cases use a fresh encrypted vault and random in-memory values. The success
case checks the exact two grant bindings, verifies the returned Ed25519
signature against an independently rebuilt public message, requires the
pre-revoked operation to be denied, and verifies the audit chain and exact
allowed/completed/denied attribution after ordinary MCP EOF. The Cancel case
requires helper termination, joined CLI exit, no protocol output, and the fixed
cancellation diagnostic. Neither case performs model calls or needs an account.

The controller retains process handles, matches the helper's direct parent and
exact image, and checks each control's owning PID. It expects the
[documented Win32 control IDs](https://github.com/gpg/pinentry/blob/pinentry-1.3.3/w32/resource.h)
and checks the fixed prompt and masked edit before sending synthetic input.
The package archive is the exact tested version boundary; this source reference
does not independently establish the bundled component's version.
Each native message has a one-second timeout; prompt discovery and process
cleanup are bounded. Captures are capped, never printed, checked for synthetic
secret bytes and encodings, and wiped. No secret enters the protocol transport
before unlock. Outside the prepared acceptance lane, missing fixture paths
produce an explicit skip, which is not GUI evidence.

Even a passing fixture covers only this pinned helper, shipping CLI, official
SDK, and synthetic local operations on the recorded runner. It does not prove
network-broker behavior, production-credential safety, or Codex, Claude Code,
or Hermes interoperability. Those named clients require their own versioned
native evidence.

Full-output/blocked-output process cancellation is not established by this
fixture. Existing security requirements remain unchanged.

# Windows official-GUI custody fixture

Status: native GUI custody passed on the candidate recorded below. This fixture
extends [ADR 0022](adr/0022-windows-mcp-custody.md). Final integrated
broker/Windows validation remains separate; preparing files or compiling the
CLI alone does not establish that the GUI works.

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

## Measured native acceptance

All six ordinary workflows passed for commit
`7eabe383a72d7df3b20659462198f9b4c67574af`, tree
`cc464c3342a815b230d5d286f78b20ca13b14b12`. The
[native Windows job](https://github.com/CharitonMedia/Tremelay/actions/runs/38324770192/job/115060785160)
ran on Microsoft Windows Server 2025, image `windows-2025-vs2026`, version
`20260925.250.1`, with Go 1.26.9. Exact archive size/hash verification, extraction,
and shipping-CLI build passed. `TREMELAY_TEST_WINDOWS_GUI_REQUIRED=1` was set
for the ordinary whole suite, so a missing helper or desktop could not skip
the two GUI cases. The command package passed in 30.921 seconds, vault package
in 145.620 seconds, and root/tools tests and vet passed.

Verified same-archive member SHA-256 values:

```text
pinentry-basic.exe  e498f66104a286544488fb2ac4aec72ccd1e6de2c0ec7b7e7ae9fc733c54775a
libassuan-9.dll     479887bebb8929cc3e9cffaa4cc7140705fa2dcb57a3a5f3db90d949bf097052
libgpg-error-0.dll  dd0c8cd53fcc7745da4ee3f3227dc7e2a5257e9f1f7be490f88d9ff7a9353d2f
```

This establishes actual GUI unlock and Cancel through the shipping CLI on that
runner, with public attestation verification, revoked denial, audit, redaction
checks, and ordinary EOF cleanup described below. It also establishes that the
extracted helper loads under the production restricted environment for these
paths; it is not an exhaustive static inventory of dynamic dependencies. The
later combined broker/Windows tree needs its own gates and binary-bound Linux
client custody receipts because shared helper plumbing changes.

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
blockers on another environment; the fixture must not change security settings
to work around them.

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

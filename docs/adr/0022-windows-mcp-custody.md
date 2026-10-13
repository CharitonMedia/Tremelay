# ADR 0022: Windows MCP process custody

Status: Proposed; native custody and official-GUI candidate validated;
final integrated validation pending

## Scope and ordering

This is the platform custody slice after the MCP credential-broker connection
in ADR 0021. It changes neither the capability catalogue nor broker authority,
network policy, projections, audit, or the MCP protocol profiles in ADR 0020.
The host still selects one vault, agent, and trusted helper. The client cannot
select credentials, unlock material, host callbacks, or another principal.

The security criteria are: owned interruptible transport; no passphrase on
protocol stdin, argv, configuration, or inherited environment; bounded helper
exchange; termination and reaping before restoration; transport/dispatch join
before session lock; fixed diagnostics and no automatic credential-operation
replay. Security invariants 1, 3, 4, 5, 6A, 12 and 13 remain authoritative.

## Owned Windows handles

Stdin and stdout must be `*os.File` pipe handles. Each is duplicated with
`DUPLICATE_SAME_ACCESS` and inheritance disabled. The original handle is not
closed or reconfigured. Non-pipe handles and unsupported query/access behavior
fail closed. Windows completion-notification modes are never changed by this
implementation.

Duplication does not change synchronous versus overlapped mode. The pinned Go
1.26.9 implementation performs a single `CancelIoEx` during pipe `File.Close`.
A synchronous I/O operation may already hold an I/O reference but not yet have
entered its kernel call, so that cancellation alone is not a sufficient
close-versus-submission argument.

`windowsPipe` reserves each operation before submission. Each direction has at
most one reservation; unexpected overlap is rejected rather than queued. Close
atomically stops admission, repeatedly calls `CancelIoEx` at 10ms intervals
while the reservation exists, and waits for its completion. Only then does it
close the owned file. Cancellation and final native-handle release use the same
mutex, preventing cancellation from reaching a recycled handle. No I/O worker
goroutine is created per call and no request buffer is copied into an extra
queue. This is a bound on resources, not a hard OS scheduling deadline. A kernel
which cannot complete or cancel its I/O is not concealed by abandoning workers.

Real byte counts remain authoritative. A write which completed before
cancellation is not reclassified as never having happened. The existing MCP
single-call/two-frame bounds and retry contract are unchanged.

## Non-consuming startup observation

`PeekNamedPipe` requires read access and therefore cannot implement the stdout
check. `GetNamedPipeHandleState` describes modes rather than connection state.
Zero-byte writes are not used as disconnect probes.

The candidate uses `NtQueryInformationFile` class `FilePipeLocalInformation`
(24). Its reply is exactly ten 32-bit Windows `ULONG` fields, independent of
pointer size: 40 bytes; connection state is at offset 32 and endpoint role at
offset 36. Status, exact returned byte count, byte-stream type, configuration,
role, and known connection states are checked. Unknown/unsupported data is a
failure, not an inferred connection. Queries read no protocol bytes.

Microsoft documents `ZwQueryInformationFile` as an always-synchronous API,
including file objects opened for asynchronous I/O. The user-mode `Nt` and `Zw`
entry points have the same behavior. The native call itself therefore retains
control until completion; its buffers remain live through that call and the
wrapper keeps its reservation until it returns. Every nonzero status is a
failure. There is no speculative post-return pending wait or polling of a live
native output buffer. In particular, no file-event-only wait can hang because
an inherited handle uses `FILE_SKIP_SET_EVENT_ON_HANDLE`. This relies on the
documented metadata API contract, not on observing immediate returns in tests.

One watcher takes snapshots at 50ms intervals during unlock, before protocol
I/O starts. Its stopping caller repeatedly cancels outstanding queries and
joins it before service or handle release. Stopping can suppress only its own
native cancellation after an earlier complete successful snapshot; an observed
disconnect or another query failure still cancels unlock. A watcher stopped
before verifying both ends also fails closed.

### Native runtime evidence requirement

The measured runtime target is ordinary inherited synchronous byte-stream pipes.
No claim is made yet for arbitrary externally configured overlapped handles or
completion-port associations. Standard libuv child stdio is synchronous unless
nonblocking/IPC flags request otherwise; its parent pipe can be overlapped.
That source evidence is not proof of a particular installed client's behavior.
Establish each named client's actual inherited handle modes and collect native
runtime evidence before expanding the supported contract. No mode bootstrap
or mutation of shared completion modes is required for the metadata query.
The candidate's ordinary native suite and shipping-CLI GUI fixture passed on
Windows Server 2025; the exact commit, runner, and pinned helper are recorded in
[the GUI evidence](../windows-gui-custody.md#measured-native-acceptance).

## Named Codex client-owned termination versus server exit

The pinned Codex 0.159.2 Windows MCP launcher uses a JobObject (or a
process-handle fallback) and explicitly terminates it with **exit code 1**
when closing its owned MCP child; see the immutable
[`stdio_server_launcher.rs`](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/rmcp-client/src/stdio_server_launcher.rs)
and [`job.rs`](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/utils/pty/src/win/job.rs).
An observed one-valued exit code cannot distinguish a deliberate client kill
from a Tremelay failure. The earlier attempted idle EOF production change
did not solve this and was reverted; no transport/broker permission changed.

The Codex test independently observes the retained Tremelay process handle
alive after five successful RPC responses and before `thread/unsubscribe`.
It verifies the real native client's completed control sequence, exact
signature, authorized and revoked-grant audit, post-EOF secret scans and
synthetic vault removal. Those are **operation-level compatibility and
credential-custody observations**, not proof of process-termination cause.

Codex's version-pinned source identifies a Windows terminate-with-1 cleanup
path but does not establish that this path caused this specific exit. A
spontaneous server exit 1 between the liveness check and Codex cleanup remains
possible. A Codex operation-evidence receipt therefore explicitly reports:
`server_exit_mode: unattributed-nonzero-client-runtime`,
`server_graceful_exit_verified: false` and
`server_termination_caller_verified: false`.
Such evidence MUST NOT be cited as proof of successful server shutdown, a
verified client-origin kill, or safe interruption of in-flight operations.

The native-client operation-compatibility test verifies only the completed,
independently validated grant use, audit and no-leak claims. It does not assert
that the Codex process exited gracefully. The separate shipping CLI/Go SDK
Windows test checks graceful zero-exit process custody. Claude and Hermes
still require zero shipping server exit in their own named-client lanes.
A later project may add a pinned, non-secret OS/debug causal witness for Codex.
No agent-facing change, production shutdown alteration, or broader nonzero
exit exception is introduced.

## Windows helper and console

The initial helper contract is a directly invoked native GUI pinentry executable
on a local drive. Relative paths, UNC/device paths, mapped network drives,
alternate-data-stream paths, and non-`.exe` scripts are refused before helper
launch. The host remains responsible for the executable's provenance and its
trusted DLL/plugin directory; an absolute path is not signature verification.
No helper installation, signing, keychain, password cache, or gpg-agent is added.

The helper runs in its installation directory with `CREATE_NO_WINDOW`, no shell,
and only locale settings from the explicit allowlist. Go adds `SYSTEMROOT` for
Windows process startup. PATH, APPDATA, HOME, Qt plugin environment settings,
and passphrase variables are not inherited. Its standard streams are private
anonymous pipes and the null device; Go's explicit handle list is used without
additional inherited handles. The parent pipe ends get the same owned
cancellation wrapper as the MCP transport; original parent ends are closed.

On cancellation, helper termination is initiated before any joining pipe Close,
so one joining close cannot prevent Kill. The helper is still waited for, all
parent I/O is joined, and any successful passphrase is withheld until cleanup
and restoration succeed. Parser bounds, wiping, fixed diagnostics, and the
post-BYE timeout are unchanged.

Windows does not emulate `--pinentry-tty`; nonempty selections fail closed. If
a console exists, independently opened, non-inheritable `CONIN$`/`CONOUT$`
handles capture both modes and restore them after the helper is reaped. Missing
console is allowed for a GUI helper; display failure remains a bounded helper
failure. This never causes fallback to protocol input. Arbitrary console
helpers and wrapper-launched descendant trees are not claimed. GUI usability
is measured only for the exact package and runner in the linked fixture.
The trusted helper is expected to be the directly launched process.

## Native named-client test toolchain trust boundary

The separately gated Windows Codex/Claude Code/Hermes acceptance lane requires
CPython **3.14.8 x64** for its local control driver and isolated Hermes virtual
environment. GitHub's `windows-latest` runner does not guarantee that exact
patch version in the preinstalled tool cache. The workflow now runs the
official `actions/setup-python` action at immutable commit
`ece7cb06caefa5fff74198d8649806c4678c61a1` (v6.3.0), requesting
only `python-version: '3.14.8'`, `architecture: 'x64'`, immediately
before preparing the pinned native clients. This is a change to the
**test-runner supply-chain trust boundary**, not to the shipping Tremelay
program or broker authority.

On a cache miss, the action can download and install Python using the
`actions/python-versions` distribution and version manifest. Thus the
trusted CI inputs include the pinned setup action, the hosted runner and its
tool cache, the upstream GitHub-hosted version manifest (which can change),
and the selected official Python distribution. An exact action commit does
**not** cryptographically pin the mutable manifest or prove that the installed
interpreter has a particular vendor binary digest. The preparation script
independently rejects any missing, wrong-version or non-x64 interpreter and
records its observed executable SHA-256, runner image/version and source
commit/tree. Observing a hash is not equivalent to validating it against a
fixed independent release checksum; that provenance limitation must accompany
any native acceptance claim.

For source-revision evidence the preparation script invokes exactly one
`git.exe` application resolved first on the hosted runner's trusted
`PATH`. PowerShell can return multiple application matches; their
`Source` properties must never be implicitly concatenated into a process
filename. The selected path must be absolute and an existing regular file.
The workflow does not independently attest the runner-provided Git executable;
it is an explicit hosted-runner trust assumption, not a shipping dependency.

The action retains the existing `contents: read` workflow permission and
runs on GitHub's ephemeral Windows runner with only synthetic vault contents;
there are no account credentials, model-provider calls or release signing
rights. No second-version fallback, unpinned ad-hoc installer, silent skip or
substitution of the earlier Go SDK GUI fixture is allowed. If Python
provisioning or any downstream locked-wheel/native-client step fails, the
native acceptance is **not established**, even when ordinary CI passes.
Shipping credential-broker risk and process custody remain governed by this
ADR, ADRs 0020-0021 and the security invariants. This lane does not establish
live SSH login, arbitrary handle modes, production identity or end-user
credential custody.

## Evidence boundaries

New Windows-only tests cover owned-handle independence/noninheritance,
reservation/close state, empty-read cancellation, prompt-time disconnect with
buffered input preservation, private synthetic helper results and cleanup,
path/environment restrictions, isolated console-mode restoration, and a normal
official-Go-SDK session over real anonymous Windows pipes. The SDK test does
not claim subprocess unlock or Codex/Claude Code/Hermes integration.

The test helper is a copy of the test executable, not a symlink requiring extra
privilege. Synthetic passphrase bytes are generated in memory and traverse only
private helper pipes; there are no real credentials or user-host operations.
The component tests are collected by the existing ordinary Windows suite. Its
GUI lane additionally extracts a pinned official package and builds the shipping
CLI before that same suite; no installer, account, or security change is needed.

Cross-compilation proves compilation only. Native Windows CI and official GUI
pinentry behavior passed on the recorded candidate. Actual native named-client
integrations and final combined broker/Windows gates remain separate evidence
requirements. Full-output/blocked-output process cancellation is not established
by this slice. The new reservation and reader tests do not demonstrate that
process behavior. The existing security requirements remain unchanged.

## Primary sources

- [Pinned Go Windows I/O](https://github.com/golang/go/blob/go1.26.9/src/internal/poll/fd_windows.go)
- [Pinned Go poller preparation](https://github.com/golang/go/blob/go1.26.9/src/internal/poll/fd_poll_runtime.go)
- [CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)
- [Native query](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile)
- [Native reply ABI](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_pipe_local_information)
- [Native completion status](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block)
- [Always-synchronous metadata API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioisoperationsynchronous)
- [User-mode Nt/Zw equivalence](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines)
- [Completion notification modes](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes)
- [libuv child pipe creation](https://github.com/libuv/libuv/blob/v1.x/src/win/pipe.c)
- [Console handles](https://learn.microsoft.com/en-us/windows/console/console-handles)
- [Pinned Python setup action](https://github.com/actions/setup-python/tree/ece7cb06caefa5fff74198d8649806c4678c61a1)
- [Official Python distribution manifest](https://github.com/actions/python-versions/blob/main/versions-manifest.json)

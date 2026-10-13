# Named-client SSH authentication-signing acceptance

The Linux `scripts/mcp_named_client_ssh.py` driver exercises the actual installed
Codex, Claude Code and Hermes MCP runtimes, without a model turn, provider
account, user configuration, production credential or software installation.
It reuses the native control APIs and bounded process lifecycle documented in
[named-client MCP tests](named-client-mcp-tests.md). The only shared-driver change
adds the explicit `ssh-userauth` observation manifest, including its public
challenge file.

## Scope and custody

`TestMCPSyntheticSSHFixture` is an explicitly gated test-binary host, never linked
into the shipping CLI. It generates a fresh passphrase, Ed25519 user private key,
Ed25519 host private key and session identifier in fixture memory. The user key
is ingested into a disposable encrypted vault; its original buffers are then
wiped. Only the existing broker uses that user private key after ingestion.
The host signs the synthetic binding proof and wipes its original private key.
Secret-equality forms are retained only in the trusted fixture for its scan and
are never exported. No credential or passphrase enters argv, environment,
configuration, public challenge or client control messages.

The public challenge supplies the resource, username, host public key, session
identifier and signed host-binding message. It does not supply the user public
key: the client must obtain that from the post-bind identity response. This is
synthetic hostbound authentication signing, with no HTTP service, network
listener, remote SSH host, completed login, shell, command, SFTP, repository or
forwarding policy. The opaque resource label does not enforce those policies.

This direct test host proves named-client MCP transport into the real SSH
broker, its authorization and audit. It does not prove shipping-CLI unlock or
custody. That is the separately measured
[shipping-CLI named-client custody lane](named-client-mcp-tests.md#shipping-cli-custody).
It also does not prove native Windows/macOS SSH client behavior or production
cutover. The original SSH authority and replay limits in
[ADR 0023](adr/0023-mcp-ssh-userauth.md) remain in force.

## Exact acceptance

Every run uses a fresh private client home, work directory and explicit minimal
environment. An exclusive PID-only launch marker refuses fixture reconnect.
Each client performs exactly ten sequential tool calls, with zero driver
retries: one catalogue, two descriptions and seven SSH message invocations.

1. The catalogue/description disclose only handle, operation, resource, status
   and expiry for two exact grants with identical SSH scope. One was revoked
   before the client started; the other remains active.
2. Identity listing before binding returns no key and records a denial.
3. A valid host proof binds the active handle. Post-bind identity lists exactly
   one canonical Ed25519 key with an empty comment.
4. One hostbound authentication signature is returned and independently
   verified by Python `cryptography` Ed25519. The same signature fails on a
   changed preimage.
5. Wrong-session and wrong-username signing requests return the fixed SSH
   failure response and are audited.
6. Binding the pre-revoked exact handle returns failure despite the active
   duplicate. It cannot fall back to the other grant.

The host checks each retained handle against its host-selected principal,
exact grant, credential ID and generation, public-key ID, operation, resource,
username and host key. Every SSH audit row must identify that principal,
credential and the corresponding exact grant. Expected SSH rows are:

- Active grant: `allowed=3`, `completed=1`, `denied=3`
- Revoked grant: `denied_revoked=1`

There are seven attempted SSH messages and eight SSH audit rows. One signature
was approved for release and the driver independently received and verified it.
These are distinct observations: an audit `completed` alone would not establish
receipt or remote authentication. Grant setup, discovery/description and replay
response-control rows account for other audit rows. Negotiation-related sparse
protocol denials are recorded separately.

## Measured Linux receipt

All three passed on 2026-10-13 using Go **1.26.9**, official MCP Go SDK **v1.8.0**,
CPython **3.12.14**, and `cryptography` **50.0.1**. The SSH production source was
unchanged from reviewed staged tree
`3233c7e0c4c138297eb73454380ef3fdb2b675dd`, based on
`3668666356aae9c8a31cd949bf5e605b415fe355`.
The fixed, redacted [machine-readable receipt](named-client-ssh-receipt.json)
contains no key, passphrase, handle, session identifier, public proof, PID,
absolute path or client transcript.

- Codex **0.159.2**: ten calls passed, native exit 0 with no escalation;
  `thread/closed` arrived before app-server EOF. The fixture observed idle
  **SIGTERM** cancellation and joined teardown, not clean EOF. Nineteen audit
  rows, zero sparse protocol denials, ten manifest files scanned.
- Claude Code **2.1.296**: ten calls passed, native exit 0 with no escalation.
  The fixture observed idle **SIGINT** cancellation and joined teardown, not
  clean EOF. Twenty audit rows, one sparse protocol denial, eleven files scanned.
- Hermes **v0.21.7**, commit
  `71d34bad1045610252eda02ee79549436896e784`, MCP Python **2.0.0**: ten calls passed,
  native-runtime child exit 0 with no escalation. The fixture observed clean
  **EOF**. Nineteen audit rows, zero sparse protocol denials, thirteen files
  scanned. Its native initialize result directly reported **2025-11-25**.

Codex and Claude's selected protocol revision was not directly observed by this
driver; the endpoint admits only its two documented stdio revisions. Do not
infer their exact negotiated revision from successful calls. All three fixture
PIDs were observed exited and their synthetic vault directories removed. The
fixture exit status was not directly observed by the outer driver; the native
client's exit 0 is not a fixture exit-code claim.

## Leak-scan and teardown limits

The fixture scans its bounded complete MCP output, audit serialization,
encrypted vault file, and all manifest-listed raw client captures and generated
command/environment/configuration/status files present during finalization.
It checks raw, JSON-escaped, URL-escaped, hexadecimal and base64 forms of the
fresh passphrase, user private key/seed/PKCS#8 and host private key/seed.
Audit additionally excludes the username, host key and session identifier.
The driver requires the exact manifest file set and the same scanned file count.
Symlinks, missing/unexpected files and size-budget overflow fail acceptance.

This is a **pre-exit snapshot**. All correlated tool responses are flushed before
teardown, and Hermes writes processed results before closing its native runtime.
Raw client stdout/stderr is retained through EOF, but late client shutdown
output is outside the earlier fixture secret scan. Native-home bundled code,
caches and SQLite are also outside that claim. No fixture secrets or
secret-derived digests are sent to the controller to extend the scan.

The existing capture limits are retained: 4 MiB per declared capture, 64 scanned
files/16 MiB aggregate, and 2 MiB retained fixture output. The fixture has one
three-minute endpoint deadline. The established drivers bound control requests,
process cleanup and PID-exit observation. The copied approved signal lifecycle
accepts cancellation only after idle, unchanged audit count and joined Serve;
it does not relabel an error as clean EOF. This adds no custom callback,
persistence, audit-observer, blocked-output, tracing or transport-refactor probe.

## Reproduction

Use the isolated, pinned client installations described in
[named-client MCP tests](named-client-mcp-tests.md#isolated-preparation).
No runtime login or setup is required. Build the test-only fixture reproducibly:

```sh
CGO_ENABLED=1 GOTOOLCHAIN=local go test -c -trimpath -buildvcs=false \
  -mod=readonly -pgo=off ./internal/vault -o "$TOOLS/ssh-fixture.test"
"$TOOLS/hermes/.venv/bin/python" scripts/mcp_named_client_ssh.py \
  --client codex --codex /absolute/codex --fixture "$TOOLS/ssh-fixture.test" \
  --output-dir "$TOOLS/results/ssh-codex-new"
"$TOOLS/hermes/.venv/bin/python" scripts/mcp_named_client_ssh.py \
  --client claude --claude "$TOOLS/claude/cli/claude" \
  --fixture "$TOOLS/ssh-fixture.test" --output-dir "$TOOLS/results/ssh-claude-new"
"$TOOLS/hermes/.venv/bin/python" scripts/mcp_named_client_ssh.py \
  --client hermes --hermes-python "$TOOLS/hermes/.venv/bin/python" \
  --hermes-source "$TOOLS/hermes/source" --fixture "$TOOLS/ssh-fixture.test" \
  --output-dir "$TOOLS/results/ssh-hermes-new"
```

Each output root must be new. Keep raw captures private; publish only the fixed
receipt after separate source-publication approval. Selected ordinary SSH tests,
package compilation and vet are separate checks, not whole-suite/race or native
Windows/macOS acceptance. No excluded tests or root full/race retry were run for
this fixture task.

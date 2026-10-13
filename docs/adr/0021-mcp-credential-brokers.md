# ADR 0021: Exact credential-use capabilities over local MCP

Status: Accepted

## Contract and threats

Extend the bound adapter and the same three MCP tools from ADRs 0017, 0018 and
0020 to existing `http_request` and `github_issue_state` brokers. The host still
selects one agent, vault and helper. No new identity, callback, listener, grant,
secret retrieval or production credential is introduced. This addresses secret
extraction, scope escalation, credential forwarding, replay and audit suppression.

Network discovery includes only canonical, single-operation, exact credential-ID
grants in single-user vaults. Credential-class and mixed-operation grants are
excluded. Shared approval still authorizes only local attestation; network grants
are neither synthesized nor admitted in shared mode. SSH is excluded: its
host-signed session binding and host-bound userauth preimage require a separately
reviewed stateful adapter. A one-shot generic signer would violate ADR 0013.

A network handle pins agent, grant ID, operation, credential ID and generation,
and exact resource. Listing again never retargets it, including after credential
replacement. A fresh adapter may discover the replacement generation. Invoke
checks the selected grant only, before use and after unlocked callbacks; another
matching grant cannot rescue revocation, expiry, suspension or replacement.

Network invocation has only a handle. Method, origin/path/query, credential and
response projection come from that grant. Caller headers, bodies, URLs, selectors,
credentials and callbacks are never accepted. Existing attestation invocation
still requires a nonempty bounded payload. A payload on a network handle or an
absent payload on an attestation handle is denied and audited.

The existing broker enforces public-IP DNS and pinned TLS destination, redirects,
proxy refusal, destructive-action and abuse policies. HTTP returns only
`status_code`; GitHub returns exactly `number`, `state`, `locked`, `comments`.
Raw bodies, headers and upstream errors never cross the adapter. `allowed` is
durable before credential injection; `completed` precedes result release. Audit
failure overrides ordinary denial/cancellation and withholds all result data.

MCP request cancellation reaches network DNS/transport via context, capped by the
existing ten-second timeout. Cancellation before transmission denies; cancellation
after transmission is ambiguous and cannot undo an external action. There are no
retries or alternate-grant fallback. A missing response is never permission to
replay. Existing bounded admission/output and session shutdown remain unchanged.

## Wire and audit compatibility

Version-1 capability framing retains its size, field-count and catalogue bounds.
Catalogue and describe entries have the existing fields, with `key_id` present
only for attestation. Network invoke omits field 2 (payload). HTTP success has
field 15 (`status_code`, canonical decimal string). GitHub success has fields
16–19 (`number`, `state`, `locked`, `comments`, canonical strings). These closed
results are projected to their existing numeric/boolean JSON types by MCP.
No credential ID, generation or secret-derived digest is exposed.

Protocol denials use sparse `agent_capability` rows attributed only to the
bound agent; no operation can be inferred from an unknown handle. This also
includes a resolved handle with the wrong invocation field set: parsing and
operation-shape rejection never become a broker attempt. Accepted network
invocations, including authority denials, use `broker_http` and the exact grant's
operation. Existing attestation operation audit remains unchanged. Describe
allows only the three explicitly supported operations with their credential
metadata. Audit encodings and hash versions do not change.

## Acceptance

Use the official MCP SDK over both local profiles and a test-only protected
upstream that actually verifies a fresh synthetic bearer credential. Prove
successful projected results without secret disclosure, scope/foreign-handle
and malformed-field denial, exact duplicate-grant revocation/expiry behavior,
credential replacement, suspension, destination controls, hostile upstream
reflection/error handling, cancellation and fail-closed audit. Existing shared,
attestation and transport suites must continue to pass. Such a fixture is real
MCP execution with a synthetic trusted transport, not proof of live GitHub or
stock-CLI network connectivity. Runtime client and platform evidence is separate.


## Synthetic client-host fixture

The test-only `TestMCPSyntheticCredentialFixture` host is enabled only by an
explicit environment gate in a compiled vault test binary. It binds the actual
stdio endpoint to fresh single-user HTTP/GitHub grants. The existing trusted
transport seam routes already-authorized synthetic origins to one disposable
loopback TLS service with a trusted test certificate. The service rejects both
missing and wrong credentials before the MCP session starts, then checks the
fresh vault-held token on each broker request. The shipping binary contains no
such origin override, environment gate, fixture unlock, or observation scanner.

The host records secret-free operation counts and audit verification after EOF.
An optional trusted observation root is scanned only for regular bounded text
files, without following symlinks. Incomplete/oversized observations are not
reported as a successful leak check. This demonstrates client-to-MCP-to-broker
credential use with a protected synthetic TLS service, separately from shipping
CLI pinentry/custody evidence and default-network destination verification.


Fixture success additionally requires exactly one HTTP and one GitHub
allowed/completed pair, one selected revoked-grant denial, two authenticated
TLS requests, and both negative-authentication selfchecks. Every request checks
its most recent broker allow against the exact issued grant, principal,
credential, operation and canonical resource. An exclusive PID-only launch
marker prevents a second fixture process from hiding a client reconnect.

The test host records clean EOF separately from an observed SIGINT/SIGTERM
cancellation. Expected signal cancellation is accepted only after all exact
counts, with no admitted/pending output or audit failure at signal receipt, no
new shutdown audit row, and `context.Canceled` from the joined endpoint. It is
not reported as clean EOF. Other transport, partial/pending, timeout or audit
errors remain failures. The signal watcher is joined before evidence inspection.
Client drivers must independently receive all expected responses, flush their
observation files before teardown, and report native-client shutdown separately.
Observation scanning is a bounded pre-exit snapshot; later client diagnostics
and post-exit writes are not covered by the secret-equality claim.


The process fixture and its ordinary-EOF subprocess regression are compiled
only on Linux/macOS. They duplicate inherited pipe descriptors with CLOEXEC,
enable nonblocking mode before constructing Go files, verify read/write deadline
support, and own their closure, matching the established shipping Unix pipe
sequence. Passing inherited blocking standard files directly would violate
`Serve`'s close-interruptible transport precondition, even when normal EOF works.
The fixture adds no unlock-stage poller or production refactor. Its measured
runtime evidence is Linux; macOS compilation is not runtime proof. Existing
cross-platform capability/MCP tests remain unchanged by this fixture limit.

# ADR 0017: Bound local agent capability interface

Status: Accepted

## Context

M10 asks for a caller-facing way to discover and invoke capabilities. M10a is only the local reference for `local_artifact_attest`. It is not a public SDK, a network service, or a demonstrated MCP transport. M9 and M10 both remain open.

[ADR 0004](0004-agent-capability-grants.md) binds an `AgentPrincipal` in process. The host chooses the principal. [ADR 0012](0012-local-ed25519-attestation.md) signs one bounded payload and returns only public verification metadata. `AgentPrincipal.LocalAttest` may select another matching grant when the named credential's current key does not match the first candidate. A list-and-`LocalAttest` wrapper would therefore not keep a caller on the grant it discovered. [ADR 0015](0015-local-shared-vault-authorization.md) still requires the requester and approving owner to be active at the generations stored on a shared grant. Backup and restore stay as published in [ADR 0016](0016-local-checkpoint-backup.md).

## Decision

### Host binding

The trusted host unlocks the vault, binds an `AgentPrincipal`, and calls `BindAgentCapability`. That adapter does not hold `*Session`. Messages cannot choose or replace the principal, a human identity, the vault path, unlock material, the clock, a notifier, or any other host callback. No new persistent credential and no live access provisioning are added. Host binding remains the existing local assertion, not remote authentication.

### Message contract

`Exchange` accepts one complete message and returns one complete message. The encoding is version 1:

```
u8     version = 1
u8     method
u16be  field_count
field  repeated field_count times
```

A field is `u8 id || u8 type || u32be length || bytes`. Type 1 is bytes. Type 2 is a UTF-8 string with no NUL. Field ids must be unique. The method's field set and types must match exactly. Bytes after the last field are rejected. Input shorter than one version byte, or longer than `MaxAgentCapMessage` (`MaxAttestPayload` + 512), is rejected before a field body is interpreted. A declared length past the remaining bytes is rejected and is not allocated. The attestation payload limit stays 1 through 64 KiB. A longer payload is a malformed message. It is not truncated.

| Method | Id | Fields |
| --- | --- | --- |
| `list_capabilities` | 1 | none |
| `describe_capability` | 2 | 1 `handle` |
| `invoke_capability` | 3 | 1 `handle`; 2 `payload` |
| `request_capability` | 4 | none, then rejected |

Field ids, types, and lengths:

| Id | Name | Type | Length and value |
| --- | --- | --- | --- |
| 1 | `handle` | bytes | 32 opaque bytes |
| 2 | `payload` | bytes | 1 through 65536 bytes |
| 3 | `operation` | string | `local_artifact_attest` |
| 4 | `resource` | string | the granted resource |
| 5 | `key_id` | string | 64 lowercase hex characters of the 32-byte Ed25519 public key |
| 6 | `status` | string | `active`, `revoked`, or `expired` |
| 7 | `expiry` | string | UTC `time.RFC3339Nano` |
| 8 | `catalog` | bytes | the catalog framing below |
| 9 | `signature` | bytes | 64 |
| 10 | `public_key` | bytes | 32 |
| 11 | `domain` | string | `tremelay/local-artifact-attestation/v1` |
| 12 | `purpose` | string | `local-artifact-attestation` |
| 13 | `code` | string | one closed error code |
| 14 | `message` | string | the fixed message for that code |

Id 0 and any other id are malformed. A message has at most 8 fields. Encoders write fields in ascending id order. Decoders accept any order. `key_id` is the lowercase hex of the public key and must decode back to those same 32 bytes. `expiry` is the grant expiry in UTC, formatted so that parsing it as RFC3339Nano and formatting it again yields the same text. Fractional trailing zeros are omitted and the zone is `Z`.

Any other method id is an unknown method. `request_capability` is recognized and unsupported. A call does not create a request, a grant, or a human assertion. An `AgentID` on an M9a request remains the intended beneficiary of a human requester. It does not let the agent impersonate that human. A future agent-originated request needs its own sponsorship and provenance design.

Success responses use the same envelope and the request's method id. The field set is exact.

`list_capabilities` returns one field, id 8, type bytes. Its value is `u16be entry_count` (0 through 64) and then that many entries. An entry is not a length-prefixed blob. It is `u16be field_count`, which is 6, and then these fields in the same TLV: 1 `handle`, 3 `operation`, 4 `resource`, 5 `key_id`, 6 `status`, 7 `expiry`. Bytes after the last entry are rejected. A catalog of more than 64 grants is denied in full and is not truncated into this framing.

`describe_capability` returns exactly fields 1, 3, 4, 5, 6, and 7, with the same types and values as one catalog entry.

`invoke_capability` returns exactly field 4 `resource`, field 9 `signature`, field 10 `public_key`, field 11 `domain`, and field 12 `purpose`.

An error response uses method 0 and exactly field 13 `code` and field 14 `message`, from this closed set:

| Code | Message |
| --- | --- |
| `unsupported_version` | unsupported version |
| `unknown_method` | unknown method |
| `malformed` | malformed message |
| `unsupported` | method is not supported |
| `unknown_handle` | unknown handle |
| `denied` | request denied |
| `denied_agent` | agent is not active |
| `denied_revoked` | grant is revoked |
| `denied_expired` | grant is expired |
| `denied_key` | key identity does not match |
| `failed` | attestation failed |

Caller bytes are not copied into those strings. A locked session, a stale session, or a failed required audit returns no response bytes. That Go error does not mean an event was recorded.

### Catalog and handles

`list_capabilities` returns only this principal's `local_artifact_attest` grants, at most 64. A larger catalog is denied in full. Each entry has a handle, the operation, the exact resource, the public key id, a lifecycle status (`active`, `revoked`, or `expired`), and the expiry. Credential ids, labels, other principals' grants, human requester and approver ids, and HTTP or SSH metadata are not fields. A shared grant whose membership generation is no longer live is shown as `revoked`. That status is advisory. Invocation checks authority again.

A handle is 32 random bytes stored in the adapter. It locates one grant, credential, key id, and resource for this adapter and this principal. It is not an authentication credential. Listing again does not point an existing handle at a different grant or key. A handle from another adapter, a handle that was never issued, and a handle whose stored binding no longer matches that grant are the same client result, `unknown_handle`. The denial does not copy the handle or another agent's grant.

`describe_capability` reads the current status and expiry for that binding. It does not authorize use.

### Exact invocation

`invoke_capability` passes only the bound grant id and the payload into the session. The caller cannot supply a resource, credential, grant, domain, purpose, or key. Under the session lock the named grant is checked for this agent, the sole `local_artifact_attest` operation, revocation, expiry on the session clock, the current credential and its pinned key, and, in a shared vault, approval provenance and membership generations. A different matching grant is not selected. `LocalAttest` is unchanged and may still retarget for its existing callers. HTTP, SSH, legacy grants, and shared approval authority are not widened.

The release path is the existing one. `allowed` commits before signing. A callback runs without the lock. `attestStillBound` then rechecks that same grant, agent, membership, expiry, credential generation, and key before a signature can be released. `completed` commits before the response is returned. A failed `allowed` or `completed` write returns no signature. The response is the existing public projection: signature, public key, fixed domain, fixed purpose, and the granted resource. Errors carry no secret, private key, payload, parser text, or partial signature.

### Audit

`list_capabilities` records `capability_list`. The row does not contain handles or resources. `describe_capability` of a resolved handle records `agent_capability` / `allowed` with the agent, grant, credential, and operation `local_artifact_attest`. An unknown, foreign, or stale describe records `agent_capability` / `denied` with the verified agent only.

An invoke of a known handle records `local_attest` for that grant, including `allowed` and `completed` or the fixed denial. A malformed invoke and an unknown invoke handle record `local_attest` / `denied` with the verified agent only. That includes a version-1 `invoke_capability` whose header is shorter than four bytes or whose message is longer than `MaxAgentCapMessage`: the method byte is kept and the field body is not parsed. An oversized message whose version byte is not 1 stays `malformed` and is not an unsupported-version result. Unsupported version, unknown method, other malformed messages, and `request_capability` record `agent_capability` / `denied` in that same sparse shape. Audit version 2 is unchanged. The new action uses it. Payloads, keys, unlock material, handles, and caller text are not audit fields. `denied_revoked` on `local_attest` remains `replay` / `high`. These rows are not `broker_http` rows.

## Alternatives considered

- **Call `LocalAttest` with the discovered credential and resource.** Rejected. That path can select another matching grant or key.
- **Use the grant id as the handle.** Rejected. The caller would be choosing authority, and a foreign id would be a probe.
- **JSON.** Rejected for this slice. A single length-prefixed field encoding makes duplicate fields, trailing bytes, and the size cap explicit.
- **Advertise `request_capability`.** Rejected. M9a requests belong to a human principal. An agent beneficiary is not that human.

## Security implications

- The adapter cannot retrieve a secret, issue a grant, bind a human, or switch principal.
- A handle does not authorize a different grant when its own grant is revoked, expired, or left behind a replaced key.
- Another principal's catalog and handles are not visible, and a foreign handle is not attributed to that other grant.
- Malformed input fails closed with a fixed response. The payload is not echoed.
- A stale or locked session, or a failed audit write, withholds the signature and is not reported as a recorded success.
- The host that holds the process and the passphrase remains the custody boundary. This slice does not add agent authentication.

## Consequences

- Operators do not get a new CLI command. The demonstration is in-process.
- M10 remains open for a real transport, SDK distribution, and `request_capability`.
- M9 remains open for authentication, recovery, and production shared access.
- Callers of `LocalAttest` keep the previous selection behavior.

## Tests

`TestAgentCapSyntheticDemo` is the shared-vault path: the host approves one local attestation, and the client lists, describes, and invokes only through `Exchange`, then verifies the public signature. `request_capability` records a denial and creates no request or grant. The other `TestAgentCap*` tests cover two-principal isolation, foreign and stale handles, strict framing, fixed errors, revocation, expiry, suspension, key replacement, membership-generation invalidation, a stale session, audit-write failure, a withheld completion, the 64-grant ceiling, and two matching grants whose old handle cannot fall back. The existing callback and reentry tests are unchanged. The exact-grant path uses the same final `attestStillBound` check, covered by `TestAgentCapExactGrantDoesNotRetarget`.

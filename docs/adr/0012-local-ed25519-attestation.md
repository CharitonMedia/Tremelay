# ADR 0012: Local Ed25519 artifact attestation

Status: Accepted

## Context

M8 asks for authorized signing while private key material stays inside Tremelay. This ADR is the local slice only. It does not implement SSH-agent compatibility, SSH wire format, agent forwarding, OS sockets, or live keys.

The security criteria for this slice are:

1. Authority is an explicit, versioned signing operation. It matches one principal, one credential, that credential's key identity, one resource, the fixed purpose, and the grant's expiry and revocation. Class-wide and wildcard authority are denied. A `sign`, `http_request`, or `github_issue_state` grant does not authorize the operation, including after reopen. Replacing key bytes under the same credential id does not move the old grant onto the new key. Agents cannot issue grants, select another principal, supply the policy clock, or retrieve private keys.
2. Signing is standard Ed25519. One credential type and one key encoding are accepted. The signed bytes bind a versioned Tremelay domain, the approved purpose, the exact resource, and the payload. A purpose check that happens only before signing is not domain separation. There is no raw-message or caller-chosen mode.
3. Payload, resource, key-input, and response sizes are bounded before the key is parsed or the signature is produced. The agent receives a 64-byte signature and a fixed set of public metadata. Failures return an empty result and a fixed error. Payloads, payload hashes, private keys, and free-form scope strings stay out of plaintext persistence, audit, notifications, logs, and errors.
4. Allowed, denied, failed, and completed attempts are audited with fixed codes. The allowed row commits before signing. The completed row commits before the signature is returned. An authorization-audit failure does not sign. A completion-audit failure withholds the signature. An incomplete durable attempt is not a completion. An event that could not be written is not claimed as recorded.
5. The same active grant may sign again. Each call has its own audit rows. This slice does not issue single-use signatures and does not bind freshness. Revocation and expiry stop later calls. They do not invalidate a signature already returned. The verifier has to know the expected public key and the application context.
6. Locked and suspended principals, a stale key binding, and a credential lifecycle state other than `active` fail closed. Credential health findings stay advisory.

The threats in view are secret extraction, scope escalation, replay, excessive but nominally valid use, audit tampering, and response disclosure. Credential forwarding is not in this slice because the operation does not open a network connection.

## Decision

`local_artifact_attest` is a grant operation distinct from `sign`, `http_request`, and `github_issue_state`. `AgentPrincipal.LocalAttest` is the only caller. The human session does not export it. The request names a credential id, a resource, and a payload. It has no purpose, algorithm, mode, header, or key field.

The credential type is `ed25519`. The secret is the 48-byte PKCS#8 DER that `crypto/x509.MarshalPKCS8PrivateKey` writes for an Ed25519 private key (RFC 8410). PEM, OpenSSH, a raw 32-byte seed, a raw 64-byte private key, other algorithms, trailing bytes, and any other length are rejected before or during that check. The parser error is not returned. No module was added. Signing and verification use `crypto/ed25519`.

### Key identity

Issuing the operation requires a credential id, not a class, and that operation alone. The grant stores `key_id`, the lowercase hex encoding of the 32-byte public key at issuance. A class grant, a combined operation list, a wildcard resource, or key material that is not the canonical encoding is rejected and does not create a grant. A document that carries this operation without that binding, or that carries `key_id` on another operation, fails unlock.

`Replace` keeps the credential id and does not rewrite `key_id`. The next attestation parses the current secret and compares the public key with the grant. A different key is `denied_key`. Unparseable or oversized material is `failed` and is not signed. `Authorize` for this operation performs the same comparison and does not return the private key.

### Signed bytes

The signed message is exactly:

```
"TREMELAY1" ||
u32be(len(domain)) || domain ||
u32be(len(purpose)) || purpose ||
u32be(len(resource)) || resource ||
u32be(len(payload)) || payload
```

`domain` is `tremelay/local-artifact-attestation/v1`. `purpose` is `local-artifact-attestation`. Lengths are byte lengths. `AttestMessage` builds this encoding and does not accept another domain or purpose. `VerifyLocalAttestation` rebuilds it from the expected public key, resource, and payload. The verification example is [docs/m8-local-attest.md](../m8-local-attest.md).

### Bounds

Empty payloads and payloads larger than 64 KiB are rejected before the key is parsed. Resources use the existing 256-byte exact-match rule and still reject `*`. Key input longer or shorter than 48 bytes is rejected before PKCS#8 parsing. The response is a 64-byte signature, a 32-byte public key, the two constants, and the granted resource. It has no payload field.

### Audit and failure

Rows use action `local_attest` and hash version 2. The version-1 through version-4 preimages are unchanged. The operation field is `local_artifact_attest`. The payload, its hash, the private key, and the resource are not audit fields.

`allowed` commits before `ed25519.Sign`. `completed` commits before the signature is returned. `denied` and `denied_key` commit instead of `allowed` when the call is refused. `failed` records an unusable key, a non-active credential lifecycle state, or a signing fault after `allowed`. A fault after `allowed` still withholds the signature.

If the `allowed` write fails, nothing is signed and the caller receives a fixed error: `ErrAudit` for audit validation or the audit fault hook, or `ErrIO` for a storage-write failure. That attempt is not in the chain. If the process stops after `allowed` and before `completed`, the chain shows an authorization and not a completion. The signature is not stored, so it cannot be recovered from the vault. The grant remains usable for a later call. If the `completed` write fails, the signature is discarded. The earlier `allowed` row is not rewritten into a completion. A locked session cannot write; the caller receives `ErrUnauthenticated` and no new row.

`denied_revoked` on this action is `replay` / `high`, the same class used for a revoked broker or authorize call, so the existing notify and containment policy applies. `denied_key`, `failed`, and the other ordinary denials are `expected_denial` / `low`. These rows are not `broker_http` rows. They do not enter the broker denial lookback, so they do not create or suppress a repeated HTTP denial. Health findings, including credential expiry, do not allow or deny the signature.

### Replay and lifecycle

A repeated call with the same active grant succeeds and appends a new allowed and completed pair. Ed25519 is deterministic, so the same key and payload produce the same signature bytes. The new audit pair is the record of the repeat. There is no nonce and no single-use counter. After revocation or expiry, later calls fail and an already returned signature still verifies under Ed25519. The verifier must use the expected public key, resource, and payload. Tremelay does not decide whether that artifact is still current.

A suspended agent is `denied_agent` before the payload is inspected. A credential whose lifecycle state is not `active` fails closed. A locked vault does not sign.

## Alternatives considered

- **Reuse the `sign` placeholder.** Rejected. Existing grants would gain an operation they were not issued for.
- **Authorize every `ed25519` credential by class.** Rejected. The grant has to name the key, not the type.
- **Treat a purpose string checked before signing as domain separation.** Rejected. The purpose and domain are inside the signed bytes, and the caller cannot choose them.
- **Return the signature and keep the payload hash in the audit row.** Rejected. Verification needs the payload from the caller. A hash in the audit chain is a plaintext record of the artifact.
- **Put attestation rows on `broker_http`.** Rejected. That would let signing denials change the HTTP repeated-denial window.
- **A new audit hash version for the signature.** Rejected. The signature is not an audit field. Version 2 already authenticates the action, result, and operation.

## Security implications

- The agent method set grows by one call that returns a signature and public metadata. It still has no private-key retrieval, grant issuance, or clock argument.
- A grant for one key and one resource does not sign with a replaced key, another credential, another resource, or another operation.
- `sign`, `http_request`, and `github_issue_state` stay on their previous meaning after reopen.
- The signed bytes do not verify as a raw signature over the payload, or under another domain or purpose.
- Private keys and payloads stay out of audit rows, errors, logs, and notifications. Tests use unique sentinels, including on malformed input.
- An allowed row without a completed row is not a released signature. A failed audit write returns a fixed error such as `ErrAudit` or `ErrIO`, never success.
- Revocation is replay and can notify or suspend through the existing policy. Ordinary attestation denials do not weaken broker detection. Health remains advisory.

## Consequences

- Humans issue `local_artifact_attest` against one `ed25519` credential and one resource. The CLI allowlist lists the operation and the type. There is no new agent command and no SSH interface.
- Callers that need SSH signing, arbitrary messages, or another algorithm need a later operation. This one will not grow a mode argument.
- Payloads above 64 KiB and keys that are not the 48-byte encoding fail closed.
- A returned signature remains verifiable after the grant ends. Applications that need freshness or revocation of an artifact have to enforce that outside the signature.
- Live keys and network SSH were not used. Acceptance is `TestLocalAttest` and `ExampleVerifyLocalAttestation`.

## Tests

- `TestLocalAttest` stores a generated key through `Put`, issues the exact grant, and checks an independent verify with the expected public key and `AttestMessage`. Changing the payload, resource, purpose, domain, signature, or key fails verification. A raw signature over the payload does not verify.
- The same test refuses legacy `sign`, `http_request`, and `github_issue_state` grants before and after reopen, and refuses class, wildcard, combined, malformed, and `ssh_key` issuance.
- It covers empty and oversized payloads, a 64 KiB payload, the wrong principal, credential, and resource, repeated use, expiry, revocation, suspension, a locked session, key replacement, restoration of the original key, and an advisory health expiry that does not block signing.
- An induced failure of the allowed write does not sign and leaves no attestation row. A failure of the completed write leaves `allowed` without `completed` and returns no signature. A fault after `allowed` records `failed` and returns no signature.
- `TestParseEd25519Private` rejects PEM, seed, expanded key, other algorithms, trailing bytes, and a sentinel-filled buffer without copying that input into the error.
- `TestAttestGrantDocument` rejects class, unbound, combined, and cross-operation key ids, and accepts a legacy `sign` grant with no key id.
- `TestLocalAttestAuditShape` keeps the version-2 preimage, rejects the operation on a `broker_http` row, and rejects a tampered result.
- `TestLocalAttestDetection` shows attestation denials do not move the broker repeated-denial threshold.
- `TestLocalAttestContainment` notifies `replay` for a revoked grant and does not put the payload or private key in the alert. An ordinary scope denial does not notify.
- `TestLocalAttestInvalidLifecycle` refuses a non-active credential state, records `failed`, and does not reopen that document as valid.
- `TestLocalAttestRotationOrderReopenAndLifecycle` checks both relative grant-ID orderings, successful reopening, and current-key revocation/expiry while stale-key grants remain present. It verifies the selected public key and grant IDs in the audit rows.
- `ExampleVerifyLocalAttestation` verifies the published test vector.

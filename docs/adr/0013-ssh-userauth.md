# ADR 0013: Host-bound SSH userauth reference adapter

Status: Accepted

## Context

M8 already signs a local artifact with a vault-held Ed25519 key ([ADR 0012](0012-local-ed25519-attestation.md)). This ADR adds a separate operation: an already-bound agent principal obtains one SSH Ed25519 authentication signature through a bounded agent stream. The private key stays in the broker. The demonstration uses synthetic keys, synthetic session-binding proofs, and in-memory byte streams. It does not log in to a server.

The security criteria are:

1. Authority is SSH authentication for one exact username and one pinned Ed25519 server host public key. It is not a remote command, path, repository, SFTP, shell, or forwarding-channel policy. The opaque resource label does not enforce those limits. The destination identity is the host public key, not a name, address, or port. Destinations that share that key and username cannot be told apart by this evidence.
2. The caller is adversarial, including on a first hop. Ordinary `publickey` authentication is denied. Clients that cannot speak the host-bound method fail closed.
3. One stream is constructed against one existing grant for the bound principal. It does not search for another grant, prefer the lowest id, or follow a replaced key. A new grant needs a new stream. Construction does not itself authorize an invalid grant.
4. A binding is a checked Ed25519 signature by the pinned host key over a bounded session identifier, with forwarding false. It can be replayed onto a new stream. It does not prove a live local transport, an honest path, server liveness, or single use. A caller that copies bytes is outside the stream's view.
5. Revocation and expiry stop later signatures. They do not pull back a signature already approved for release, and they do not end an SSH session that already authenticated. Repeated valid requests succeed while the grant is active, each with its own audit pair. `completed` means the signature was approved for release, not that a server accepted it or that the client received every byte.

## Decision

`ssh_userauth` is an operation distinct from `sign`, `local_artifact_attest`, `http_request`, and `github_issue_state`. No alias promotes those grants. Issuance requires one principal, one `ed25519` credential id, that credential's public-key id, one exact resource, one username, and one canonical `ssh-ed25519` host public-key blob, plus expiry. Class scope, wildcard resources, combined operations, empty context, and a missing or non-canonical key binding are rejected. The host key is stored separately from the credential key id. Both live in the encrypted grant document. A document that puts SSH fields on another operation, or that omits them from this operation, fails unlock. Older documents with no SSH fields still open and gain no SSH authority.

The user private key remains the 48-byte PKCS#8 encoding from ADR 0012. There is no import or conversion path. The host public key is supplied by the control plane at issuance. The signing request cannot supply a different one.

`AgentPrincipal.SSHUserAuth(grantID)` binds one stream to that grant. The wire cannot choose the principal, grant, credential, resource, clock, or host policy. `Authorize` may describe the same grant policy, including a key mismatch, and is not a substitute for the binding and the userauth checks. There is no caller boolean that marks a host or a session as trusted.

The stream implements a small codec. It does not call `ssh/agent.ServeAgent`. The pinned `golang.org/x/crypto` v0.41.0 server logs parser errors with `log.Printf`, parses key-add material before `Agent.Add`, and answers legacy identity messages itself. Those paths are outside this boundary. The standard client is used only as an in-memory peer in tests. Production signing uses `crypto/ed25519`.

### Protocol subset

Handled messages:

- `SSH_AGENTC_REQUEST_IDENTITIES` (11). Before a successful binding, or when the selected grant or key is not currently usable, the answer lists no key. After a binding, and only while ownership, expiry, revocation, suspension, active lifecycle, and both key bindings pass, the answer is the one granted `ssh-ed25519` public key and an empty comment.
- `SSH_AGENTC_SIGN_REQUEST` (13) with flags zero. The data must be exactly one host-bound userauth preimage, with no trailing bytes and no attached signature.
- `SSH_AGENTC_EXTENSION` (27) for `session-bind@openssh.com` only. A second bind, a rebind, a forwarding flag, a non-canonical flag byte, a bad signature, another host key, or trailing bytes does not create or replace context.

Unknown extension names, including `query`, return `SSH_AGENT_EXTENSION_FAILURE` (28). Every other opcode returns `SSH_AGENT_FAILURE` (5) from the opcode byte alone. The payload is not parsed as a key, password, certificate, or provider. Failures carry no parser text.

The signed bytes are the validated preimage and nothing else. The local-attestation domain is not prepended. The preimage is:

```
string    session identifier
byte      SSH_MSG_USERAUTH_REQUEST (50)
string    username
string    "ssh-connection"
string    "publickey-hostbound-v00@openssh.com"
byte      1
string    "ssh-ed25519"
string    user public key
string    server host key
```

The username, both public keys, and the session identifier must match the grant and the binding. Ordinary `publickey`, a raw payload, an SSHSIG envelope, a certificate, another algorithm, another service, a false or non-canonical boolean, and a non-zero sign flag are denied. The response signature is the SSH encoding of `ssh-ed25519` and the 64-byte Ed25519 signature (RFC 8709). The host binding signature uses that same encoding over the raw session identifier, which is the exchange hash a server signs in the key-exchange reply.

### Bounds

| Limit | Value |
| --- | --- |
| Agent frame length field | 4096 bytes |
| Userauth preimage | 1024 bytes |
| Session identifier | 1–64 bytes |
| Username | 1–256 UTF-8 bytes, no NUL or control character |
| Resource | existing 256-byte exact resource |
| User and host public keys | canonical 51-byte `ssh-ed25519` blob |
| Host and user signatures | canonical 83-byte `ssh-ed25519` signature |

Advertised lengths above those caps are rejected before a buffer of that size is allocated. A frame that fails its length check does not fall through into another parser. Sixty-four byte session identifiers cover a SHA-512 exchange hash; OpenSSH's usual SHA-256 hash is 32 bytes. The preimage cap holds one host-bound Ed25519 request and rejects certificate-sized material. These caps are an interoperability ceiling, not a claim that every SSH peer will fit.

### Audit, lifecycle, and concurrency

Rows use action `ssh_userauth`, operation `ssh_userauth`, and hash version 2. The version-1 through version-4 preimages are unchanged. Username, host key, resource, session identifier, preimage, digest, signature, and private key are not audit fields.

Rejected stream construction records the fixed result `denied`. It records a principal ID only after confirming that ID exists in the unlocked session, and omits the grant and credential fields even for an existing target. Unknown or malformed principals have no attributed actor; caller-supplied, missing, foreign, and wrong-operation grant IDs are never copied into this denial. The audit validator accepts that sparse shape only for version-2 `ssh_userauth` / `denied` rows. An audit or storage failure replaces the ordinary constructor error, and no adapter is returned. A locked session cannot record the denial and returns `ErrUnauthenticated`. Successful construction writes no allow row; expired and revoked grants retain their construction behavior and still fail the checks on actual use.

`allowed` commits before `ed25519.Sign`. `completed` commits before any signature response is written. A failed `allowed` write does not sign. A failed `completed` write discards the signature. A write error after `completed` means the release was approved and does not mean the peer received it or a server accepted authentication. A locked session or a storage failure that cannot append a row is returned as `ErrUnauthenticated` or the storage error, and is not described as recorded. `ErrAudit`, `ErrIO`, and `ErrCorrupt` stop the stream without a protocol response, including during identity listing.

A successful session bind records `allowed` before the stream keeps the host proof. That row is the credential check, not a signature release, and it has no `completed` partner. If that write fails, the stream stays unbound.

`denied_revoked` on this action is `replay` / `high`, so the existing notify and containment policy applies. Other denials and `failed` are `expected_denial` / `low`. These rows are not `broker_http` rows and do not move the HTTP denial window. Health findings stay advisory. A non-active credential lifecycle fails closed. Replacing the key bytes does not move this stream onto another grant, in either id order, including after reopen. A revoked or expired selected grant is not rescued by a different active grant.

Each stream holds at most one binding. `Serve` and `roundTrip` serialize that stream's state and its calls into the session. The unlocked `Session` is still not safe for a second caller at the same time; the host must not use it from another goroutine during `Serve`. A clean EOF before the next frame ends `Serve`, and `Close` wipes the binding and the stream buffers. EOF after a length field, a partial frame, or an oversize length stops the stream with `ErrInvalid` and records a denial when the session can store one. Any other read or write failure stops the stream with a fixed transport error. The reader or writer error text is not returned. Tests drive `Serve` to exit and do not leave its goroutine running. No socket is opened.

`Close` does not interrupt a blocked read or write. Cancellation belongs to the host: close the adapter, interrupt its transport using that transport's close, deadline, or cancellation mechanism, and wait for `Serve` to return before using or locking the session. A response already approved for release may still be written until the transport is interrupted.

## Alternatives considered

- **Reuse `sign` or `local_artifact_attest`.** Rejected. Existing grants would gain SSH authority, and the attestation domain is not an SSH userauth encoding.
- **Pass the restrictive agent to `ServeAgent`.** Rejected for this dependency version. The server parses and logs before the callback, so the Tremelay boundary would not hold.
- **Retarget the stream to the current key's grant.** Rejected. That is the ambiguity ADR 0012's attestation path still has, and this operation pins the grant at construction instead.
- **Accept ordinary publickey on a first hop.** Rejected. OpenSSH allows it in some trusted cases. This adapter assumes the caller can forge or replay a binding.
- **Treat a binding as a live local session.** Rejected. The process cannot see the SSH transport. The guarantee is the signed username, host key, and session identifier.

## Security implications

- The agent method set grows by one constructor that returns a stream. The stream has no private-key export, no generic signer, and no grant or clock argument.
- A grant for one key, username, and host key does not sign with a replaced key, another grant, or another operation. Attestation and SSH do not authorize each other.
- Identity listing discloses at most the granted public key, and only after the binding and the current checks. Sign responses are the standard signature encoding or a fixed failure byte.
- Private keys, usernames, host keys, session identifiers, and preimages stay out of audit rows, errors, logs, and notifications. Tests use unique sentinels, including on a key-add frame that is never parsed.
- An `allowed` row without `completed` is not a released signature. `completed` is not a successful login.
- Revocation remains replay and can notify or suspend through the existing policy. SSH denials do not weaken broker detection.

## Consequences

- Humans issue `ssh_userauth` with `--ssh-user` and `--ssh-host-key` (hex of the canonical host public-key blob). The CLI allowlist includes the operation. There is no socket listener and no live login command.
- Peers that need certificates, agent constraints, key insertion, forwarding, or the `query` extension are refused. A later operation would have to add them explicitly.
- Frames above 4 KiB, preimages above 1 KiB, and session identifiers outside 1–64 bytes fail closed.
- A returned signature remains verifiable after the grant ends. Applications that need freshness or session revocation enforce that outside this signature.
- Acceptance is `TestSSHUserAuthInterop` and the denial, lifecycle, malformed, and audit tests beside it. No live network and no user SSH files are used.
- `golang.org/x/crypto` stays at v0.41.0. `govulncheck` reports SSH transport and agent-client findings in that already-pinned module, including a client panic on pathological agent input. This codec does not import the SSH transport or `ServeAgent`, and the scan does not mark those symbols as called. The test peer is `NewClient` against the small responses this codec emits. A module bump is not part of this slice.

## Tests

- `TestSSHUserAuthInterop` uses `agent.NewClient` on an in-memory pipe, lists only the granted key after a synthetic host binding, and verifies the signature with `ssh.ParsePublicKey` and `ed25519.Verify`. The serve goroutine exits.
- Context tests refuse a bad binding, another host key, the wrong username, host key, session id, or user key, ordinary publickey, a raw payload, SSHSIG, bad booleans, trailing bytes, non-zero flags, certificates, rebinding, forwarding, and a second stream using the first stream's session.
- Legacy `sign`, `http_request`, `github_issue_state`, and `local_artifact_attest` grants fail before and after reopen. Class, wildcard, combined, and cross-operation documents are rejected. The attestation tests still pass.
- Expiry, revocation, suspension, lock, and a non-active lifecycle fail between requests on an already-bound stream. Key replacement is tested in both grant-id orderings. The stream stays on the selected grant. Repeats are audited separately.
- Malformed, oversize, truncated, multi-frame, write-failure, and unsupported add/remove/lock/provider messages are exercised. A key-add frame carrying a sentinel is not parsed, logged, or stored.
- Allowed and completed audit failures and a signing fault produce no signature bytes at those boundaries. Revoked-grant replay still notifies. SSH denials do not move the HTTP denial window. A tampered `completed` row fails verification.
- A no-row vault update producing `ErrCorrupt` stops identity listing and signing without writing a response. Failure at completed preserves only the preceding allowed row. Notification output is scanned directly for the private keys, username, host key, session identifier, preimage, and signature.
- Constructor denials cover missing, foreign, wrong-operation, and malformed grant IDs and unknown or malformed principals. They persist across reopening without reflecting target IDs or inventing an actor. Audit/storage failures return no adapter and publish no row; malformed sparse rows and older audit versions are rejected.

## Dependency review addendum — 2026-10-10

The application now pins `golang.org/x/crypto` v0.56.0 and its required `golang.org/x/term` v0.45.0, superseding the historical pins above and in ADR 0002. The [tagged module](https://github.com/golang/crypto/blob/v0.56.0/go.mod) requires Go 1.26.0, compatible with the retained Go 1.26.9 pin. The existing `x/sys` v0.48.0 satisfies its v0.47.0 minimum. The tools module is unchanged.

Official Go vulnerability records put the fixes for 19 findings against the former v0.41.0 pin at or below v0.56.0: GO-2025-4116 (v0.43.0); GO-2025-4134 and GO-2025-4135 (v0.45.0); GO-2026-5005, GO-2026-5006, GO-2026-5013 through GO-2026-5021, GO-2026-5023 and GO-2026-5033 (v0.52.0); GO-2026-6303 (v0.55.0); and [GO-2026-6354](https://vuln.go.dev/ID/GO-2026-6354.json) and [GO-2026-6355](https://vuln.go.dev/ID/GO-2026-6355.json) (v0.56.0). [GO-2026-5932](https://vuln.go.dev/ID/GO-2026-5932.json) remains: it covers seven unmaintained OpenPGP package paths and has no fixed version. Tremelay imports none of those packages, including in tests, so this remains a module-level finding, not a claim of vulnerability absence. Dated scanner reports must distinguish required modules, imported packages and called symbols; a test-inclusive source scan is separate from the candidate's source scan, which omits tests.

Production uses `x/crypto/argon2` and its `blake2b` dependency; SSH imports remain test-only. KDF parameters, vault encodings, signature authority and the custom stream codec are unchanged. The [tagged official agent client](https://github.com/golang/crypto/blob/v0.56.0/ssh/agent/client.go) starts a reader and supports up to 32 outstanding requests on an `io.ReadWriteCloser`. `TestSSHUserAuthInterop` therefore also checks bounded concurrent identity/sign requests, their signatures and audit counts, clean EOF, closed-client rejection, and transport/goroutine cleanup. This remains synthetic in-memory compatibility, not a completed SSH login or production-security assurance.

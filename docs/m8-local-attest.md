# M8 local Ed25519 attestation

An agent with one expiring `local_artifact_attest` grant can obtain an Ed25519 signature over a bounded local payload. The private key stays in the vault. This is not an SSH agent. It does not open a socket, forward a key, or accept a caller-chosen message.

The grant names one agent, one `ed25519` credential, and one resource. At issuance Tremelay records the public key. A later replacement of the credential bytes keeps the credential id and does not move the grant onto the new key. `sign`, `http_request`, and `github_issue_state` do not authorize this call.

## Signed bytes

`AttestMessage` builds the only encoding this operation signs:

```
TREMELAY1 ||
u32be(len(domain)) || domain ||
u32be(len(purpose)) || purpose ||
u32be(len(resource)) || resource ||
u32be(len(payload)) || payload
```

Lengths are unsigned 32-bit big-endian byte counts.

| Field | Value |
| --- | --- |
| Prefix | `TREMELAY1` |
| Domain | `tremelay/local-artifact-attestation/v1` |
| Purpose | `local-artifact-attestation` |
| Resource | the granted resource, exact |
| Payload | the artifact bytes, 1 through 65536 |

The private key is the 48-byte PKCS#8 DER from `crypto/x509.MarshalPKCS8PrivateKey` for an Ed25519 key. The signature is 64 bytes. The public key is 32 bytes.

`VerifyLocalAttestation` rebuilds that message. It does not take a domain or purpose argument. A signature over the raw payload, or over a message with a different domain, purpose, resource, or payload, does not verify.

The verifier has to already know the expected public key and which artifact the signature belongs to. Revoking or expiring the grant stops the next call. It does not make a signature that was already returned fail Ed25519 verification. This operation does not add a nonce or a single-use counter.

## Verification example

This uses a published test seed, not a vault key. `go test` runs the same vector in `ExampleVerifyLocalAttestation`.

```go
priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
pub := priv.Public().(ed25519.PublicKey)
msg, err := vault.AttestMessage("artifact:demo", []byte("demo-artifact"))
if err != nil {
    // resource or payload was rejected
}
ok := vault.VerifyLocalAttestation(pub, "artifact:demo", []byte("demo-artifact"), ed25519.Sign(priv, msg))
```

`ok` is true only for that public key, resource, and payload. The vault path that produces a signature is `AgentPrincipal.LocalAttest` after a human `Put` and `IssueGrant`. `TestLocalAttest` is that demonstration. It does not use a live key or a network service.

## What remains

SSH-agent compatibility, SSH certificates, agent forwarding, and deployment with real keys are a separate scope. General-purpose signing, decryption, and HMAC are not this operation.

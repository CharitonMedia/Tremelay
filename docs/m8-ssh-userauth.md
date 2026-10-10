# M8 host-bound SSH userauth

An agent principal that already holds one expiring `ssh_userauth` grant can obtain an SSH Ed25519 signature through an in-memory agent stream. The private key stays in the vault. This is synthetic compatibility with a small part of the SSH agent protocol. It is not a live login, a socket listener, or a general-purpose agent.

The human control plane chooses the principal and one existing grant when it builds the stream. A wire message cannot choose the principal, grant, credential, resource, clock, or host key. `Authorize` can describe that grant and does not replace the checks performed at signing.

## What the grant allows

The grant authorizes SSH authentication as one exact username to the server identified by one Ed25519 host public key. That is account authentication only. It does not limit a remote command, path, repository, SFTP session, shell, or forwarding channel. The resource string is an opaque label stored with the grant. It does not add those limits.

The destination that can be enforced is the host public key. A DNS name, address, or port is not the identity. Two servers that present the same host key and accept the same username cannot be distinguished by this signature. Choosing or rotating that host key is a control-plane action. The adapter does not discover hosts, trust a key on first use, edit `known_hosts`, or accept a host certificate.

The caller is treated as adversarial, including on a first hop. Ordinary `publickey` authentication is refused. A client or server that cannot use `publickey-hostbound-v00@openssh.com` gets a failure and no signature.

## What a binding proves

Before a signature, the stream requires `session-bind@openssh.com`: the pinned host key's signature over a 1–64 byte session identifier, with the forwarding flag clear. The check is cryptographic. The same proof can be presented again on a new stream. Tremelay does not see the SSH connection, so the proof is not a live local session, an honest forwarding path, proof that the server is up, or a single-use token. A caller that copies the bytes itself is not something this stream can detect. A second bind on the same stream is refused and does not replace the first. A successful bind records an `allowed` audit row and does not release a signature. A frame that ends after its length, or in the middle of its body, is a denial. A clean end is only an EOF before the next frame. Stream errors are fixed strings; reader and writer text is not returned.

Revoking or expiring the grant stops the next signature. It does not make an already released signature fail verification, and it does not close an SSH session that already authenticated. While the grant remains active, the same request may be signed again. Each request has its own audit rows. `completed` means the signature was approved for release. It does not mean the server accepted authentication or that the client received every response byte.

The host owns transport cancellation. Calling the adapter's `Close` clears its binding but does not interrupt a blocked read or write. The host must also interrupt the transport and wait for `Serve` to return before using or locking the vault session. An already approved response may still be written until the transport is interrupted.

Replacing the credential's key bytes does not move this stream onto a newer grant. The stream keeps the grant named at construction. Another active grant is not a fallback.

## Protocol subset

| Message | Result |
| --- | --- |
| `SSH_AGENTC_REQUEST_IDENTITIES` | No key until a binding succeeds and the grant, key, and lifecycle checks still pass. Then the one granted `ssh-ed25519` public key and an empty comment. |
| `SSH_AGENTC_SIGN_REQUEST` with flags `0` | Signature over the one validated host-bound userauth preimage, or a fixed failure. |
| `session-bind@openssh.com` | Binds this stream once, or fails. |
| Any other extension, including `query` | `SSH_AGENT_EXTENSION_FAILURE` |
| Add, remove, lock, unlock, smartcard, provider, and legacy messages | `SSH_AGENT_FAILURE`, from the opcode, without parsing a key or password |

Frames are at most 4 KiB. The authentication preimage is at most 1 KiB. Usernames are at most 256 UTF-8 bytes and cannot contain NUL or other control characters. User and host keys must be the canonical 51-byte `ssh-ed25519` blob. These caps are fixed in [ADR 0013](adr/0013-ssh-userauth.md).

The signed preimage is the SSH userauth encoding, not the local-artifact domain:

```
string    session identifier
byte      SSH_MSG_USERAUTH_REQUEST (50)
string    exact granted username
string    "ssh-connection"
string    "publickey-hostbound-v00@openssh.com"
byte      1
string    "ssh-ed25519"
string    granted user public key
string    pinned server host key
```

The private key is the same 48-byte PKCS#8 Ed25519 encoding used for local attestation. The signature returned to the peer is the standard SSH `ssh-ed25519` signature blob.

## What this demonstration is not

`TestSSHUserAuthInterop` builds disposable user and host keys, issues the grant, feeds a synthetic host signature over a session identifier, and checks the result with public verification APIs. The peer is `golang.org/x/crypto/ssh/agent.NewClient` on an in-memory pipe. The test does not read `SSH_AUTH_SOCK`, `known_hosts`, or a real key file, and it does not listen on a socket or open an SSH session.

Deployment still excludes a Unix socket, a real OpenSSH client or server, agent forwarding, certificates, host-key rotation, and any post-authentication session control. Those need a later design. Local artifact attestation remains a different operation and does not authorize this one.

# Threat Model

## Security objective

Permit authorized humans and software agents to exercise narrowly scoped credential-backed authority while minimizing disclosure and limiting damage from a compromised or malicious caller.

## Trust boundaries

1. Human user / administrator
2. Agent or workload
3. Tremelay control plane
4. Tremelay credential broker
5. Encrypted credential store
6. Audit subsystem
7. Notification subsystem
8. External destination/service

These boundaries may share a process in early development, but the architecture MUST keep them conceptually separable.

## Adversary assumptions

Tremelay MUST assume an agent can be prompt-injected, maliciously instructed, compromised by dependency or tool behavior, induced to call unauthorized endpoints, induced to request destructive actions, induced to probe for secrets, or induced to redirect traffic to an attacker-controlled destination.

Tremelay MUST NOT rely on an agent following policy voluntarily.

## Primary threats

### Secret extraction
Attempts to obtain raw secrets through APIs, error messages, logs, environment variables, debug endpoints, process inspection, broker introspection, malformed requests, or response reflection.

### Scope escalation
Attempts to use a valid capability for another credential, account, resource, organization, host, method, path, or action.

### Credential forwarding/exfiltration
Redirects, SSRF, DNS rebinding, alternate hostnames, proxy chains, or malicious service definitions that cause credentials to be presented to an unintended destination.

### Replay and stolen capabilities
Use of copied bearer capabilities outside their intended client, device, time window, or request context.

### Excessive but nominally valid use
High-volume enumeration, scraping, destructive loops, or unusual access patterns that remain technically within a broad capability.

### Audit tampering
Modification, deletion, truncation, backdating, or suppression of audit events.

### Notification suppression
Preventing or delaying alerts following high-risk events.

### Host compromise
Full host compromise may defeat software-only secrecy; the design SHOULD support external roots of trust and remote audit/checkpoint systems to reduce this risk.

## SSH userauth reference limits

The `ssh_userauth` adapter releases an Ed25519 signature for SSH account authentication. The trusted control plane pins one principal, one credential, that credential's public key, one opaque resource label, one username, and one Ed25519 server host public key. The resource label does not enforce a command, path, repository, SFTP session, shell, or forwarding channel. The enforceable destination is the host public key, not a DNS name, address, or port. Two destinations that share that host key and username are not distinguished. Pinning the host key is a control-plane action; the adapter does not discover hosts, trust on first use, edit known_hosts, or accept host certificates.

The caller is treated as adversarial, including on a first hop. Signing requires `publickey-hostbound-v00@openssh.com` and a host signature over the session identifier with `is_forwarding` false. Ordinary publickey authentication is denied. The binding is checked cryptographically and can be replayed on a new in-memory stream. It is not evidence of a live local session, an honest forwarding path, server liveness, or global single use. A caller that relays bytes itself is outside what this stream can observe. Revocation and expiry stop later signatures. They do not invalidate a signature already released or close an SSH session that already authenticated. Each permitted request has its own audit rows.

Wire messages cannot choose the principal, grant, credential, clock, or host key. One stream is tied to the grant selected at construction and is not retargeted when the vault key changes or another grant would match. The private key does not leave the broker. Username, host key, session identifier, preimage, and signature stay out of plaintext audit, notifications, logs, and errors. This is synthetic in-memory compatibility with a protocol subset, not a deployable general SSH agent and not a completed login.

## Shared-vault reference limits

M9a is one local approval path for `local_artifact_attest`. The host that holds the process and the vault passphrase asserts synthetic human identities. Two records do not prove two people and do not confine that host. Bound humans cannot retrieve plaintext, switch actor, or mint assertions. Agents still cannot retrieve a raw secret.

A shared grant is usable only while the requester and the approving owner remain active at the generations stored on the grant. Removal, demotion, re-enrollment, and re-promotion invalidate that authority. They do not recall a signature already released. Legacy single-user grants are not given approval provenance and are not accepted in a shared vault. An older reader fails closed on shared storage instead of treating it as an unrestricted single-user vault.

This does not decide production enrollment, recovery, offboarding, or independent custody. Those remain open under M9.

## Out of scope for initial milestone

The first vertical slice does not promise protection against an attacker with arbitrary kernel/hypervisor access to the host containing decrypted secrets.

## Required adversarial tests before HTTP broker completion

- raw-secret retrieval attempts
- unauthorized host
- unauthorized HTTP method
- unauthorized resource/path
- redirect to unauthorized origin
- redirect chains
- localhost/private-address SSRF attempts
- DNS/destination validation strategy
- malformed capability
- expired capability
- revoked capability
- replay behavior according to chosen capability design
- error-path secret leakage
- audit logging for success and denial
- log redaction

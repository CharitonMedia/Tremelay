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

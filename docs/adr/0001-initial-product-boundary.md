# ADR 0001: Capability Broker as the Core Product Boundary

Status: Accepted

## Context

Agents frequently need to act using credentials but do not need to know the credential value. Traditional secret retrieval increases exposure and makes prompt injection or agent compromise more damaging.

## Decision

Tremelay's primary agent abstraction is a scoped capability to perform credential-backed operations. Agent-facing raw-secret retrieval is not part of the normal product interface.

The credential broker, capability system, policy enforcement, audit, and lifecycle controls are the stable product core. Secret storage is replaceable.

## Consequences

- Integrations may require broker/adaptor work rather than simple environment-variable injection.
- Service-specific semantics can be modeled as capabilities.
- Credential exfiltration through ordinary agent interfaces is materially reduced.
- Network and response handling become security-sensitive trust boundaries.

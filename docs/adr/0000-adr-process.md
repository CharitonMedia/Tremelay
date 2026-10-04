# ADR 0000: Architecture Decision Records

Status: Accepted

## Context

Tremelay is security infrastructure. Decisions affecting trust boundaries, secret handling, cryptography, identity, authorization, audit integrity, or network brokering require durable rationale.

## Decision

Use short Architecture Decision Records under `docs/adr/`.

An ADR should state status, context/problem, decision, alternatives considered, security implications, consequences, and tests/verification required.

## Changes requiring an ADR

At minimum: cryptographic primitive or key hierarchy, authentication model, capability format, policy model, broker trust-boundary changes, redirect/DNS/SSRF strategy, audit-chain format, secret-store backend contract, and new agent-facing credential-backed operations.

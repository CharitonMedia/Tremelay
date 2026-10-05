# Security Invariants

These requirements outrank implementation convenience.

## 1. No agent-facing raw-secret retrieval

Normal agent-facing APIs, tools, SDKs, CLIs, logs, errors, prompts, environment variables, and responses MUST NOT expose raw credential values. The core abstraction is an authorized **operation**, not secret retrieval.

## 2. Explicit capability grants

Every agent credential use MUST be authorized by an explicit capability grant identifying, at minimum: principal/agent identity, credential or credential class, permitted operation(s), resource/service scope, expiration or lifecycle, and revocation state.

Where applicable, policies SHOULD additionally constrain host, method, path, account, repository, project, tenant, request rate, and destructive actions.

## 3. Deny by default

Any operation not affirmatively authorized is denied.

## 4. Every attempt is auditable

Every attempted credential operation—allowed or denied—MUST produce an audit event. Security-relevant denials are first-class events.

## 5. Audit records must not contain secrets

Audit records may identify credentials by stable internal identifier and human-readable label, but MUST NOT record raw secrets, decrypted payloads, authorization headers, private keys, passwords, or equivalent material.

## 6. Audit integrity

The audit design MUST be append-oriented and tamper-evident. The initial implementation SHOULD hash-chain events. Designs MUST permit external or independent checkpointing.

## 6A. Transactional audit/state durability

Any credential-state mutation and its corresponding audit event MUST become durable atomically. A crash or storage error may leave the operation entirely unapplied, but MUST NOT leave credential state and the authoritative audit history disagreeing about whether the operation occurred.

Locked-state authentication denials that cannot update encrypted credential state MAY append independently, but the next successful unlock MUST validate and incorporate that suffix before advancing the authenticated audit head.

## 7. Detection and notification

Tremelay MUST distinguish ordinary denials from suspicious behavior. High-risk events MUST be capable of notifying the responsible owner promptly and referencing the complete audit record. Automated containment must be configurable.

## 8. Credential health at ingest and change

Credentials MUST be evaluated according to type when added or changed. Human-chosen passwords SHOULD be checked for strength/predictability, known compromise, internal reuse, and organizational policy. Known-compromise checks MUST NOT disclose the plaintext password to an external service.

Machine credentials SHOULD be evaluated for relevant properties such as issuer format, algorithm/key length, age, expiry, public exposure where reasonably detectable, and rotation policy.

## 9. Lifecycle policy

Long-lived credentials SHOULD have an explicit lifecycle policy covering creation, review, rotation, revocation, expiration, and archival. Static API credentials SHOULD support configurable rotation reminders. Automated rotation MUST validate the new credential before revoking the old one when safe overlap is possible.

## 10. No custom cryptography

Tremelay MUST use mature, reviewed cryptographic libraries and standard constructions.

## 11. Network destination controls

Credential use through network brokers MUST defend against destination confusion, redirects, DNS rebinding, SSRF, proxy abuse, and equivalent mechanisms. Credentials authorized for one service MUST NOT be silently forwarded to another origin.

## 12. Least disclosure in responses

The broker MUST consider response data part of the security boundary. An allowed upstream operation MUST NOT automatically imply that all upstream response data may be returned to the agent.

## 13. Tests are security controls

Security and adversarial tests MUST NOT be weakened, skipped, or deleted merely to make an implementation pass. A change to a security expectation requires documented review of the relevant invariant and threat model.

# Tremelay Vision

## Problem

Existing password managers and secret stores generally answer some version of: **who may retrieve this secret?**

Autonomous and semi-autonomous agents create a different requirement. In many cases an agent needs authority to perform an action using a credential, but it does not need—and should not receive—the credential itself.

## Product thesis

Tremelay separates **possession of a secret** from **authority to use a secret**.

Humans manage credentials in vaults. Agents receive short-lived, scoped capabilities. A trusted broker performs authorized operations using protected credentials and returns only the operation result that policy allows the caller to observe.

## Intended credential types

- passwords
- API keys and bearer tokens
- OAuth refresh/access credentials
- SSH private keys
- certificates and signing keys
- database credentials
- TOTP seeds
- arbitrary encrypted secrets

## Intended use mechanisms

- HTTP/API credential broker
- OAuth token broker
- SSH-agent-compatible signing
- cryptographic signing/decryption/HMAC operations
- database/session brokering
- controlled browser/form credential submission

## Non-goals for early releases

- Becoming a general-purpose endpoint protection product.
- Inventing custom cryptographic primitives.
- Replacing every enterprise IAM product.
- Exposing a general-purpose `getSecret()` operation to agents.

## Naming

Tremelay is named for Bernard de Tremelay, a 12th-century Grand Master of the Knights Templar. The name reflects the project's central metaphor: protected custody combined with controlled passage through dangerous territory. The project should use that history lightly and keep its visual and technical identity modern.

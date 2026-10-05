# Tremelay

**Open-source credential custody and delegated access for humans and agents.**

Tremelay is a self-hosted credential vault and capability broker. Humans can store and manage passwords, API keys, SSH keys, certificates, tokens, and other secrets in familiar vaults. Software agents receive narrowly scoped authority to *use* credentials without receiving the underlying secret value.

> The broker possesses secrets. Agents possess capabilities.

## Project status

M1 is a local single-user vault. A human can create a vault, unlock it with a passphrase, and store and retrieve a credential with the `tremelay` CLI. That CLI is the human control plane: it has no agent interface and no raw-secret retrieval for agents. Later milestones add capabilities, the HTTP broker, audit review, and credential health. See [MILESTONES.md](MILESTONES.md).

```
tremelay vault create --path vault.db
tremelay credential put --path vault.db --label ci --type api_key --secret-file ./secret
tremelay credential get --path vault.db --id CREDENTIAL_ID
tremelay credential list --path vault.db
tremelay audit verify --path vault.db
```

The path is one local SQLite database. Credential bytes are encrypted; the file does not store plaintext secrets. The passphrase comes from `TREMELAY_PASSPHRASE` or a no-echo terminal prompt. It is not a command-line argument. `audit verify` uses that passphrase to authenticate the sealed audit head. `credential get` writes the raw secret to stdout.

## Core goals

- Self-hosted and open source from day one.
- Human-friendly credential vaults.
- Agent-safe delegated credential use.
- Raw secrets never exposed through normal agent-facing interfaces.
- Fine-grained capability grants with expiry and revocation.
- Comprehensive, tamper-evident audit logging of allowed and denied credential operations.
- Risk detection and owner notification for questionable activity.
- Credential health checks, including password strength, known-compromise checks, reuse detection, expiration, and rotation policy.
- Provider-assisted credential rotation where safe and supported.
- Replaceable secret-storage backends.

## Security model in one sentence

A caller may be authorized to perform an operation with a credential without being authorized to retrieve that credential.

## Initial milestones

See [MILESTONES.md](MILESTONES.md).

## Security

Read [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) and [THREAT_MODEL.md](THREAT_MODEL.md) before contributing code that touches credentials, authorization, networking, audit records, or agent interfaces.

## License

Apache License 2.0. See [LICENSE](LICENSE).

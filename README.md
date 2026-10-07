# Tremelay

**Open-source credential custody and delegated access for humans and agents.**

Tremelay is a self-hosted credential vault and capability broker. Humans can store and manage passwords, API keys, SSH keys, certificates, tokens, and other secrets in familiar vaults. Software agents receive narrowly scoped authority to *use* credentials without receiving the underlying secret value.

> The broker possesses secrets. Agents possess capabilities.

## Project status

M1 is a local single-user vault. A human can create a vault, unlock it with a passphrase, and store and retrieve a credential with the `tremelay` CLI. M2 adds distinct agent principals and revocable, expiring capability grants. M3 adds an in-process HTTP broker on an agent principal: the broker injects a stored credential into one authorized HTTPS request and does not return the credential. An `http_request` grant used by the broker names the exact method and canonical URL, for example `GET https://svc.example/v1/ping`. The CLI remains the human control plane: agent and grant commands do not retrieve raw secrets, and there is no agent-facing `getSecret`. Later milestones add policy hardening, audit review, and credential health. See [MILESTONES.md](MILESTONES.md).

```
tremelay vault create --path vault.db
tremelay credential put --path vault.db --label ci --type api_key --secret-file ./secret
tremelay credential get --path vault.db --id CREDENTIAL_ID
tremelay credential list --path vault.db
tremelay agent create --path vault.db --label worker
tremelay grant create --path vault.db --agent AGENT_ID --credential CREDENTIAL_ID --operation http_request --resource svc:example --expires 2030-01-01T00:00:00Z
tremelay capability list --path vault.db --agent AGENT_ID
tremelay capability authorize --path vault.db --agent AGENT_ID --credential CREDENTIAL_ID --operation http_request --resource svc:example
tremelay grant revoke --path vault.db --id GRANT_ID
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

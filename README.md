# Tremelay

**Open-source credential custody and delegated access for humans and agents.**

Tremelay is a self-hosted credential vault and capability broker. Humans can store and manage passwords, API keys, SSH keys, certificates, tokens, and other secrets in familiar vaults. Software agents receive narrowly scoped authority to *use* credentials without receiving the underlying secret value.

> The broker possesses secrets. Agents possess capabilities.

## Install

Tremelay is pre-release security software. No release is published yet, so
`go install` from source is the only install path today; the download commands
below are the shape of the published one.

```
go install github.com/CharitonMedia/Tremelay/cmd/tremelay@latest
```

Each release will carry a `tar.gz` (linux, macOS) or `zip` (windows) for
amd64 and arm64, a CycloneDX SBOM per binary, and a `SHA256SUMS` file. To
download and verify on linux or macOS, with `OS` as `linux` or `darwin` and
`ARCH` as `amd64` or `arm64`:

```
VERSION=v1.0.0 OS=linux ARCH=amd64 && name=tremelay_${VERSION}_${OS}_${ARCH} &&
base=https://github.com/CharitonMedia/Tremelay/releases/download/$VERSION &&
curl -fsSL -O $base/$name.tar.gz -O $base/SHA256SUMS &&
grep "  $name.tar.gz$" SHA256SUMS | shasum -a 256 -c - &&
tar -xzf $name.tar.gz && install -m 755 $name ~/.local/bin/tremelay
```

`SHA256SUMS` is a checksum file, not a signature: it detects a corrupted or
truncated download, not a substituted release. Signed releases are out of v1.
`make release-dry` builds the same artifacts into `dist/release` locally. See
[ADR 0027](docs/adr/0027-release-artifacts.md).

## Project status

M1 is a local single-user vault. A human can create a vault, unlock it with a passphrase, and store and retrieve a credential with the `tremelay` CLI. M2 adds distinct agent principals and revocable, expiring capability grants. M3 adds an in-process HTTP broker on an agent principal: the broker injects a stored credential into one authorized HTTPS request and does not return the credential. An `http_request` grant used by the broker names the exact method and canonical URL, for example `GET https://svc.example/v1/ping`. M4 enforces that text as origin, method, path, and action policy, and refuses SSRF, DNS rebinding, proxy bypass, and redirects before a credential can follow them. M5 adds human audit views, a fixed risk classification, a secret-free notification interface, and optional containment. M6 evaluates credentials when they are added or replaced and records secret-free health, review, expiry, and rotation reminders. Health is advisory and is not available to agents. M7 adds one scoped GitHub issue-state read: an agent with a `github_issue_state` grant for a single issue receives that issue's number, open or closed state, lock flag, and comment count. The credential stays in the broker, and an existing `http_request` grant does not receive those fields. The local demonstration uses a synthetic credential and does not call GitHub. See [docs/m7-github-issue.md](docs/m7-github-issue.md). M8 adds one local Ed25519 attestation and one host-bound SSH userauth signature. An agent with a `local_artifact_attest` grant receives a signature over a bounded payload. An agent with an `ssh_userauth` grant can obtain an SSH Ed25519 authentication signature for one username and one pinned host key through an in-memory agent stream. The private key stays in the vault. Neither operation authorizes the other, and older grants do not gain either one. Both demonstrations use disposable keys. The SSH demonstration does not open a socket or complete a login. See [docs/m8-local-attest.md](docs/m8-local-attest.md) and [docs/m8-ssh-userauth.md](docs/m8-ssh-userauth.md). M9b adds a local checkpoint-bound snapshot of the vault. The host keeps the checkpoint outside the encrypted file. An old snapshot with its own old checkpoint is not detected as stale, and this slice does not recover a lost passphrase. See [docs/m9b-local-backup.md](docs/m9b-local-backup.md). M10a adds an in-process capability interface for one bound agent: it can list, describe, and invoke that agent's `local_artifact_attest` grants by an exact handle, and it rejects `request_capability`. This is not a public SDK or an MCP transport. See [docs/m10a-agent-capability.md](docs/m10a-agent-capability.md). The CLI remains the human control plane and has no human-id flag: agent and grant commands do not retrieve raw secrets, and there is no agent-facing `getSecret`. See [MILESTONES.md](MILESTONES.md).

```
tremelay vault create --path vault.db
tremelay vault change-passphrase --path vault.db
tremelay vault backup --path vault.db --output snapshot.db
tremelay vault restore --input snapshot.db --path restored.db --checkpoint-file /independent/checkpoint.txt
tremelay credential put --path vault.db --label ci --type api_key --secret-file ./secret
tremelay credential get --path vault.db --id CREDENTIAL_ID
tremelay credential list --path vault.db
tremelay credential replace --path vault.db --id CREDENTIAL_ID --secret-file ./secret
tremelay credential lifecycle --path vault.db --id CREDENTIAL_ID --rotation-every 2160h --review-every 8760h
tremelay credential health --path vault.db
tremelay credential refresh --path vault.db
tremelay credential policy --path vault.db --freshness 24h --compromise-opt-in false
tremelay agent create --path vault.db --label worker
tremelay grant create --path vault.db --agent AGENT_ID --credential CREDENTIAL_ID --operation http_request --resource svc:example --expires 2030-01-01T00:00:00Z
tremelay capability list --path vault.db --agent AGENT_ID
tremelay capability authorize --path vault.db --agent AGENT_ID --credential CREDENTIAL_ID --operation http_request --resource svc:example
tremelay grant revoke --path vault.db --id GRANT_ID
tremelay audit verify --path vault.db
tremelay audit list --path vault.db
tremelay audit get --path vault.db --seq 1
```

The path is one local SQLite database. Credential bytes are encrypted; the file does not store plaintext secrets. The passphrase comes from `TREMELAY_PASSPHRASE` or a no-echo terminal prompt. It is not a command-line argument. `audit verify` uses that passphrase to authenticate the sealed audit head. `audit list` and `audit get` are the same human view of the chain and do not return credential plaintext. `credential get` writes the raw secret to stdout. `credential list` includes `rotation_every` and `review_every` as Go durations; `0s` means that interval is disabled. `credential health` returns findings without secrets. `credential refresh` runs only while the vault is unlocked; a locked or stopped process does not evaluate credentials.

Passphrase change requires old/new/confirmation through no-echo terminal prompts and ignores the environment. Backup emits a checkpoint to stdout for independent retention; restore requires that explicit checkpoint and a new target. Existing snapshots retain their original passphrase. See [the lifecycle guide](docs/vault-lifecycle.md) before using these commands.

## Local MCP clients

`tremelay mcp serve` is a human-unlocked local stdio subprocess for one
host-selected agent. It uses an explicitly trusted pinentry helper, with
passphrase input separate from MCP, and exposes only the same three exact-grant
credential-use tools for exact `local_artifact_attest`, `http_request` and
`github_issue_state` grants. Network calls accept only a discovered handle and
return status-only HTTP or the four-field GitHub summary; credentials stay in
the broker. The initialize-based profile supports `2025-06-18` and
`2025-11-25`; the modern in-memory reference remains separate. See the
[stdio setup, client examples, tested versions and limitations](docs/local-stdio-mcp.md)
and [measured Codex, Claude Code and Hermes integration](docs/named-client-mcp-tests.md).
This command ignores the environment-passphrase shortcut described above.

Unattended agents cannot answer a prompt, so `tremelay daemon --vault PATH`
unlocks once in your terminal and serves agents on a user-only local endpoint
until `tremelay lock`, its idle timeout, or process loss zeroises the session.
Each agent gets its own token file from `tremelay agent create --token-file`,
and `tremelay mcp --daemon --token-file FILE` is the stdio command the client
launches. The daemon derives the agent principal only from that token, serves
only the same three tools, and exposes no human operation and no raw secret.
Linux and macOS only; elsewhere these commands fail closed. See
[the headless daemon guide](docs/headless-daemon.md) and
[ADR 0024](docs/adr/0024-headless-unlock-daemon.md) for the trust boundary this
moves: while unlocked, code running as you can use your agents' authority.

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

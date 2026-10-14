# Headless unlock: one daemon, many agents

`tremelay mcp serve` prompts for the passphrase every time a client launches it
([ADR 0020](adr/0020-local-stdio-mcp.md)). Unattended agents cannot answer a
prompt, so `tremelay daemon` moves the unlock to you, once, in your terminal:
it holds the unlocked vault in memory and serves agents on a user-only local
endpoint until you lock it. Each agent authenticates with its own token file
and gets exactly the three MCP tools it already had — `list_capabilities`,
`describe_capability`, `invoke_capability` — scoped to its own grants.

No raw secret, no passphrase, and no human control-plane operation is reachable
over that endpoint. See [ADR 0024](adr/0024-headless-unlock-daemon.md) for the
trust boundary this moves and the tradeoff you are accepting.

Linux, macOS and Windows. `tremelay ssh-agent` is the exception: it is Unix
only, and on Windows it fails closed. Pinentry stays available everywhere as
the option it was; see [local stdio MCP](local-stdio-mcp.md).

## Give an agent a token

Create the agent with a token file, then grant it the operations it needs. The
token is 32 random bytes; the vault seals only its SHA-256. The command prints
the agent ID and the token path — never the token itself.

```sh
tremelay agent create --path /absolute/vault.db --label claude-code --token-file ~/.tremelay/claude-code.token
tremelay grant create --path /absolute/vault.db --agent AGENT_ID --credential CRED_ID \
  --operation local_artifact_attest --resource build/release.tar.gz --expires 2027-01-01T00:00:00Z
```

The token file is written so that only you can read it — 0600 with `O_EXCL` on
Linux and macOS, an owner-only descriptor created with `CREATE_NEW` on Windows
— and it will not overwrite an existing file. A token file that anyone else can
read is refused when it is used. It is a bearer secret: anything that can read
it can use that agent's grants while the daemon is unlocked. Without `--token-file` no token
copy survives the command, and that agent can only be used through pinentry.

An agent created before this feature has no token digest and cannot
authenticate to the daemon. Create a new agent for it. There is no
`agent token rotate` yet; revoke the agent and create another.

## Unlock

```sh
tremelay daemon --vault /absolute/vault.db --idle-timeout 8h
```

It prompts for the passphrase on your terminal, then prints the endpoint path
and serves. `--idle-timeout` accepts `1s` through `24h`, defaults to `1h`, and
counts only time with no agent connected. Keep this terminal, a `tmux` window,
or a user service running — the key lives nowhere else, so closing the process
or rebooting locks the vault.

The control plane stays usable while it runs. Creating an agent, issuing a
grant or revoking one commits to the same vault; the daemon re-reads and
re-verifies the file with the key it already holds, and the change takes
effect on the agent's next call. Nothing re-prompts, and open client
connections stay up. If a command reports a stale session, an agent call
committed at the same moment and nothing of your command was written: run it
again.

The daemon still locks and exits when it cannot verify the file — a tampered
document, a broken audit chain or a rolled-back audit head.

## Register the stdio command with a client

`tremelay mcp --daemon --token-file FILE` is what the client launches. It
connects to the daemon, authenticates with the token, and relays MCP. It never
prompts.

### Claude Code

```sh
claude mcp add --transport stdio --scope local tremelay -- /absolute/tremelay mcp --daemon --token-file /absolute/claude-code.token
```

### Hermes

```yaml
mcp_servers:
  tremelay:
    command: /absolute/tremelay
    args: [mcp, --daemon, --token-file, /absolute/claude-code.token]
    protocol: legacy
    connect_timeout: 10
    supports_parallel_tool_calls: false
```

### Codex

```toml
[mcp_servers.tremelay]
command = "/absolute/tremelay"
args = ["mcp", "--daemon", "--token-file", "/absolute/codex.token"]
startup_timeout_sec = 10
tool_timeout_sec = 30
```

Give each client its own agent and its own token file. Startup timeouts can be
short here: there is no human entry and no KDF in this path. The protocol
profile, retry contract and ambiguous-outcome rules are unchanged from
[local stdio MCP](local-stdio-mcp.md#protocol-and-retry-contract) — in
particular, never automatically replay an invocation whose response went
missing; read the audit.

## Sign SSH with the same daemon

On Linux and macOS, an agent that holds an `ssh_userauth` grant can also get an
`SSH_AUTH_SOCK` from this daemon, for `git push` and plain `ssh`, with the key
still inside it. See [SSH signing for agents](ssh-agent.md). On Windows
`tremelay ssh-agent` fails closed; the MCP path above is unaffected.

## Lock

```sh
tremelay lock
```

The daemon zeroises the session and exits, and the next client call fails
closed with a generic error. The idle timeout and losing the process do the
same thing. Nothing survives to be unlocked without your passphrase.

## What gets audited

Every authentication attempt lands in the audit chain as `daemon_auth`:
accepted and inactive-agent attempts name the agent, an unknown token names
nobody because there is nobody to name. The token never appears in a row, a log
line, or an error. Capability use is audited exactly as before.

```sh
tremelay audit list --path /absolute/vault.db --action daemon_auth
```

## Endpoint custody

On Linux and macOS the socket lives in `$XDG_RUNTIME_DIR/tremelay`, or
`tremelay-<uid>` under the system temporary directory when that variable is
unset. The directory is 0700 and the socket is 0600, both verified at startup:
a path owned by another user, of the wrong type, or readable by group or other
refuses to start, and a socket that still answers a dial is treated as a live
daemon rather than replaced. Every connection's peer uid must equal the
daemon's before any byte is read.

On Windows the endpoint is the named pipe `\\.\pipe\tremelay-<your SID>`. It is
created with a descriptor you own that grants read and write to your SID and to
nothing else — not Everyone, not Authenticated Users, not Administrators — and
it refuses remote clients. The daemon claims the name as a first pipe instance,
so if something else already holds that name the daemon refuses to start rather
than share it. Every connection's client process must run as your SID before
any byte is read, and in the other direction `mcp --daemon` and `lock` check
that the pipe they opened is owned by you before sending your agent token. Set
`TREMELAY_DAEMON_INSTANCE` to a short `[A-Za-z0-9_-]` label to run a second
daemon on its own pipe; the label is appended to your SID, never instead of it.

Your account is the boundary. Code already running as you, while the daemon is
unlocked, can use your agents' granted capabilities — it still cannot read a
credential, change a grant, or learn your passphrase, and everything it does is
in the audit chain.

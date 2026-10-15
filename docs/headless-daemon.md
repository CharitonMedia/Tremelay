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

## Give an existing agent a token, or replace one

No agent ever has to be recreated to get a working token, and no client
configuration has to change: the three commands below keep the agent's id,
its state and every grant it holds.

```sh
# An agent that has no token: one created before this feature, or one whose
# token was revoked. The token file must not exist yet; delete the file a
# revoked token left behind and reuse its path.
tremelay agent token issue --path /absolute/vault.db --agent AGENT_ID --token-file ~/.tremelay/claude-code.token

# Replace a live token at the path the client already points at.
tremelay agent token rotate --path /absolute/vault.db --agent AGENT_ID --token-file ~/.tremelay/claude-code.token

# Take daemon access away and leave the agent and its grants in place.
tremelay agent token revoke --path /absolute/vault.db --agent AGENT_ID
```

Each command prints the token path, or the agent id for `revoke`, and never
the token. `issue` refuses an agent that still holds a token and refuses a
token file that already exists, so it cannot retire a working client by
accident; `rotate` is the command that replaces one in place. Rotation writes
a user-only temporary file beside the target and renames it over it, so a
reader gets the whole old token or the whole new one. A `rotate` path that is
not already a token file is refused before the vault commits, so a mistyped
`--token-file` cannot overwrite something else.

The replaced or revoked token stops authenticating at once, including in a
daemon that is already serving and including on a connection that agent
already has open: its next call is refused and audited, and it does not have
to reconnect for that to happen.

## Unlock

```sh
tremelay daemon --vault /absolute/vault.db --idle-timeout 8h
```

At a terminal it prompts for the passphrase with no echo (see [Passphrase from
the environment](#passphrase-from-the-environment) for `TREMELAY_PASSPHRASE`,
which is not recommended). It then prints the endpoint path and serves.
`--idle-timeout` accepts `1s` through `24h`, defaults to `1h`, and counts only
time with no agent connected. There is no unattended reboot or auto-unlock: after
a reboot you start `tremelay daemon` again and type the passphrase; see [Keeping the daemon running](#keeping-the-daemon-running).

The control plane stays usable while it runs. Creating an agent, issuing a
grant or revoking one commits to the same vault; the daemon re-reads and
re-verifies the file with the key it already holds, and the change takes
effect on the agent's next call. Nothing re-prompts, and open client
connections stay up. If a command reports a stale session, an agent call
committed at the same moment and nothing of your command was written: run it
again.

The daemon still locks and exits when it cannot verify the file — a tampered
document, a broken audit chain, a rolled-back audit head, or a chain that no
longer contains the audit event the daemon last served, which is what an
older copy of the vault restored underneath it looks like.

## Passphrase from the environment

`tremelay daemon` reads `TREMELAY_PASSPHRASE` from the process environment.
Unlock order: a **non-empty**
`TREMELAY_PASSPHRASE` wins and **no prompt is shown**, even when stdin is a
terminal; if the variable is unset or empty and stdin is a TTY, you get a
no-echo prompt; otherwise unlock fails. It works, but it is **not
recommended**: the value stays readable in the daemon's process environment
(for example `/proc/<pid>/environ` on Linux) for the daemon's lifetime, visible
to other processes running as your uid, and anything that stores it (shell rc,
env file, unit, plist) puts the passphrase on disk. After unlock the daemon
zeroes its own copy of the passphrase; the environment variable is not removed.
`tremelay mcp --daemon` and `tremelay mcp serve` never read
`TREMELAY_PASSPHRASE`; `vault change-passphrase` never reads it either
(terminal only).

There is **no** unattended-reboot or auto-unlock mode. After a reboot you run
`tremelay daemon` once and type the passphrase. `tremelay lock` and the idle
timeout end the daemon; after a passphrase change it locks and exits on its
next agent call. The vault stays locked until you start it again.

## Keeping the daemon running

On Linux and macOS, run `tremelay daemon` in a terminal you leave open, or in
`tmux` or `screen` (no passphrase stored). MCP clients must resolve the same
socket as the daemon (see [Endpoint custody](#endpoint-custody)); when their
environments may differ, set the same absolute `TREMELAY_DAEMON_SOCKET` for the
daemon and every client.

On Windows, start `tremelay daemon` in its own console window you leave open on
the desktop. A daemon started inside an SSH session (Windows OpenSSH) is killed
when that session ends. There is no supported Windows service or Task Scheduler
recipe. `tremelay ssh-agent` is not
available on Windows; agents there use `tremelay mcp --daemon`.

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

Token custody is audited the same way, as `agent_token_issue`,
`agent_token_rotate` and `agent_token_revoke`. Each row names the agent and
nothing else: no credential, no grant, and nothing derived from the token.

## Endpoint custody

On Linux and macOS the socket lives in `$XDG_RUNTIME_DIR/tremelay/daemon.sock`,
or `tremelay-<uid>/daemon.sock` under the system temporary directory when that
variable is unset. Unix domain sockets cannot use paths longer than about 107
bytes on Linux (104 bytes on macOS, counting the terminating NUL in the kernel
limit). When the default path would exceed that limit — for example a very long
`XDG_RUNTIME_DIR` — startup reports that the path is too long instead of a
misleading permissions error. Set `TREMELAY_DAEMON_SOCKET` to a shorter absolute
path; `tremelay daemon`, `tremelay mcp --daemon`, `tremelay lock`, and
`tremelay ssh-agent` all read the same variable when connecting to the daemon.
Relative values are refused. At startup the daemon creates the socket's parent
directory with `MkdirAll` mode 0700 when it is missing; an existing parent that
you do not own exclusively, or that grants group or other access, refuses to
start. The socket file is 0600, both verified at startup: a path owned by
another user, of the wrong type, or readable by group or other refuses to start,
and a socket that still answers a dial is treated as a live daemon rather than
replaced. Every connection's peer uid must equal the
daemon's before any byte is read.

`TREMELAY_DAEMON_SOCKET` is Unix-only; Windows always uses the named pipe below.

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
in the audit chain. That holds only if you type the passphrase: with
`TREMELAY_PASSPHRASE` set for the daemon, same-uid code can read it from the
daemon's environment and then unlock the vault itself.

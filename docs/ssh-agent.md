# SSH signing for agents

`tremelay ssh-agent` publishes an `SSH_AUTH_SOCK` that `ssh` and `git` can
use. The signing key stays inside the unlocked daemon
([ADR 0024](adr/0024-headless-unlock-daemon.md)); the socket releases one
authentication signature at a time, for one username, to one server host key,
under one `ssh_userauth` grant ([ADR 0013](adr/0013-ssh-userauth.md),
[ADR 0026](adr/0026-ssh-agent-socket.md)). Revoking the grant stops it.

**Linux and macOS only.** The daemon itself also runs on Windows, but this
command does not and fails closed there; see
[ADR 0024](adr/0024-headless-unlock-daemon.md).

**Your client must be OpenSSH 8.9 or later.** The agent authorizes a signature
against the `session-bind@openssh.com` the client sends after key exchange: the
pinned host key's signature over that connection's session identifier. A client
that sends no binding is told about no key and gets no signature, because
without it there is no proof of which destination the signature is for. The
server can be anything, including GitHub and other hosted forges, which do not
implement `publickey-hostbound-v00@openssh.com`
([ADR 0013](adr/0013-ssh-userauth.md), amendment of 2026-10-14). Forwarded
agent connections (`ssh -A` on a second hop) are still refused.

## Create the key and the grant

The credential is an Ed25519 private key in PKCS#8 DER, the same shape local
attestation uses. Generate it, store it, and delete your copy — nothing but
the vault needs it again.

```sh
D=$(mktemp -d)   # private dir: a fixed /tmp name can be pre-created by another user
openssl genpkey -algorithm ed25519 -outform DER -out "$D/git-key.der"
tremelay credential put --path /absolute/vault.db --label "git signing key" \
  --type ed25519 --secret-file "$D/git-key.der"
shred -u "$D/git-key.der" && rmdir "$D"
```

Pin the server. The grant stores the host public key itself, not a hostname:
that is the destination this signature can reach, and it is the only thing
standing between your agent and a signature for somewhere else.

`ssh-keyscan` asks the host you are about to trust what its key is, which
proves nothing on its own. **Never pin keyscan output you have not compared
against a fingerprint from the operator.** For your own server, read the key
out of `/etc/ssh/ssh_host_ed25519_key.pub` on the box itself. Otherwise
keyscan it and check the fingerprint:

```sh
ssh-keyscan -t ed25519 -p 22 git.example.com > /tmp/hostkey.pub
ssh-keygen -lf /tmp/hostkey.pub          # compare with the operator's published fingerprint
HOST_KEY_HEX=$(awk '{print $3}' /tmp/hostkey.pub | base64 -d | xxd -p -c 0)
```

### Pinning github.com

GitHub publishes its host keys in two places you can check independently of
whatever answered your keyscan: the [SSH key fingerprints
page](https://docs.github.com/authentication/keeping-your-account-secure/githubs-ssh-key-fingerprints)
and `https://api.github.com/meta` (field `ssh_keys`), both over TLS. The
Ed25519 fingerprint published there at the time of writing is
`SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`; treat that page, not this
file, as the authority, and expect it to change when GitHub rotates.

```sh
curl -fsS https://api.github.com/meta |
  python3 -c 'import json,sys; print([k for k in json.load(sys.stdin)["ssh_keys"] if k.startswith("ssh-ed25519")][0])' \
  > /tmp/github.pub
ssh-keygen -lf /tmp/github.pub   # must match the fingerprint on GitHub's page
HOST_KEY_HEX=$(awk '{print $2}' /tmp/github.pub | base64 -d | xxd -p -c 0)
```

The field order differs: `api.github.com/meta` gives `ssh-ed25519 AAAA...`
(key in field 2), while `ssh-keyscan` prefixes the hostname (key in field 3).
If the two sources disagree, stop; do not pin either. Use `--ssh-user git` for
GitHub, and note that the grant authorizes authentication to github.com as a
whole, not one repository.

The agent only accepts the pinned Ed25519 host key, so make OpenSSH negotiate
Ed25519 with GitHub. Otherwise OpenSSH may prefer an ECDSA or RSA key already in
`known_hosts`, the bind carries that key, the agent refuses it, and you see a bare
`Permission denied (publickey)`. Keep only GitHub's `ssh-ed25519` line for
github.com in `known_hosts`, and add to `~/.ssh/config`:

```
Host github.com
  HostKeyAlgorithms ssh-ed25519
```

Create the agent, its token file and the grant. `--ssh-user` is the account on
that server (`git` for a hosted forge, your login name for your own box). The
resource label is recorded with the grant; it does not restrict the repository
or the command, so keep expectations honest.

```sh
tremelay agent create --path /absolute/vault.db --label codex \
  --token-file ~/.tremelay/codex.token

tremelay grant create --path /absolute/vault.db --agent AGENT_ID \
  --credential CREDENTIAL_ID --operation ssh_userauth \
  --resource "git.example.com push" --ssh-user git \
  --ssh-host-key "$HOST_KEY_HEX" \
  --expires 2027-01-01T00:00:00Z
```

## Install the public key on the server

The grant's `key_id` is the hex Ed25519 public key. Turn it into an
`authorized_keys` line (on macOS, replace `base64 -w0` with
`base64 | tr -d '\n'`):

```sh
KEY_ID=$(tremelay capability list --path /absolute/vault.db --agent AGENT_ID |
  grep ssh_userauth | sed 's/.*"key_id":"\([0-9a-f]*\)".*/\1/')
printf 'ssh-ed25519 %s tremelay\n' \
  "$({ printf '\0\0\0\vssh-ed25519\0\0\0\040'; printf %s "$KEY_ID" | xxd -r -p; } | base64 -w0)"
```

Add that line to the server's `authorized_keys`, or paste it into your forge's
SSH key settings. `ssh-add -L` will not show it: the agent discloses no
identity until a connection has proved the pinned host key, so there is
nothing to list outside a real SSH connection.

## Start the socket

The daemon must already be unlocked ([headless unlock](headless-daemon.md)).

```sh
tremelay daemon --vault /absolute/vault.db --idle-timeout 8h   # terminal 1
tremelay ssh-agent --token-file ~/.tremelay/codex.token        # terminal 2
```

`ssh-agent` prints the socket path it is serving, by default
`$XDG_RUNTIME_DIR/tremelay/ssh-agent.sock`. Use `--socket /absolute/path` to
put it elsewhere, which you need when more than one agent token is in use —
one process serves one agent. The directory must be yours and 0700; the socket
is created 0600, every connection's peer uid is checked, and a socket that is
already answering is never replaced.

It refuses to start without a reachable daemon, with a token file that group
or other can read, or on a directory anyone else can enter.

## Use it

```sh
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/tremelay/ssh-agent.sock
git push origin main
```

If you would rather not export anything globally, point git at the socket for
one command:

```sh
GIT_SSH_COMMAND="ssh -o IdentityAgent=$XDG_RUNTIME_DIR/tremelay/ssh-agent.sock" \
  git push origin main
```

Both work for `git clone`, `git fetch` and plain `ssh`. Nothing else changes:
the client sends the agent its host binding, the agent answers with the
granted key, and the signature is produced inside the daemon.

## Stopping it

```sh
tremelay grant revoke --path /absolute/vault.db --id GRANT_ID
```

The next signature is refused, and the key stops being listed, on the
connection the client already has: the running daemon re-reads the vault and
picks the revocation up without a restart. `tremelay lock`, the idle timeout,
losing the daemon, or stopping `tremelay ssh-agent` each stop it as well.

## Slow or loaded hosts

The relay waits up to ninety seconds for the daemon to finish token
authentication and answer `OK` on a new connection. That covers SQLite
`busy_timeout` and audit I/O when the machine is CPU- or disk-saturated. If the
daemon still does not answer in time, the client reports a timeout — not an audit
denial. A refused token still has no detail on the wire; inspect `daemon_auth`
rows for the reason.

## What is audited

Every signing attempt, allowed or refused, is an `ssh_userauth` row. Each SSH
connection also records its token authentication and its grant enumeration.

```sh
tremelay audit list --path /absolute/vault.db --action ssh_userauth
```

`allowed` means the grant checks passed, `completed` means a signature was
released — not that the server accepted it. No username, host key, session
identifier, preimage, signature or key material appears in a row.

## What this does not do

The grant authorizes authentication as one username to one host key. It does
not limit the repository, the command, the branch, SFTP, port forwarding, or
anything else that happens after login — two servers sharing that host key and
username are the same destination as far as this evidence goes. Agent
forwarding, certificates, key insertion and `ssh-add` management are refused.
A signature already released stays valid, and revoking a grant does not close
an SSH session that already authenticated.

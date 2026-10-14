# SSH agent socket acceptance on render-1 (Linux), 2026-10-13

Commit under test: b80b8ad rebased onto v1 9c0ebbc (branch `v1-ssh-agent`). Throwaway tmpfs
vault, generated passphrase and Ed25519 key (key file shredded after `credential put`), all
deleted after the run.

Test server: a private, unprivileged OpenSSH 9.6p1 `sshd` on 127.0.0.1:22422 with its own host
key and an `authorized_keys` holding only the vault key's public half (built from the grant's
`key_id` as `docs/ssh-agent.md` shows). The system sshd and the operator's keys were untouched.
Test repo: a bare git repository on tmpfs.

1. `ssh_userauth` grant for user `patrick`, pinned to the test server's host key.
   `tremelay daemon` unlocked once; `tremelay ssh-agent --token-file ...` served
   `run/tremelay/ssh-agent.sock` (0600 in a 0700 dir).
2. `git push origin HEAD:refs/heads/main` over `ssh://patrick@127.0.0.1:22422/...` with
   `IdentityAgent` set to that socket and strict host-key checking: **succeeded**; the bare
   repository's `main` held the pushed commit. Audit: `ssh_userauth` `allowed` and `completed`.
3. `tremelay grant revoke` on that grant, daemon re-unlocked, `ssh-agent` restarted, second
   push: **failed** (`Please make sure you have the correct access rights`). The revoked grant
   contributes no identity, so no signature was requested or released.

Limit (ADR 0026): only `publickey-hostbound-v00@openssh.com` requests are signed, so the server
must be OpenSSH 8.9+. Hosted forges whose SSH servers do not offer that method get no signature.

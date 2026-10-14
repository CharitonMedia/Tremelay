# SSH with GitHub (V1 item 5b) on render-1 (Linux), 2026-10-14

Commit under test: 25febaa (branch `v1-ssh-github`, rebased on v1 6c119b4). Client OpenSSH 9.6p1.
Script: [ssh-github-render1-accept.sh](ssh-github-render1-accept.sh). Throwaway tmpfs vault, generated
passphrase in a 0600 file, private `XDG_RUNTIME_DIR` and `HOME`. The ssh client ran with `-F /dev/null
-o IdentityFile=none -o HostKeyAlgorithms=ssh-ed25519` and a known_hosts holding only GitHub's Ed25519
key, so the tremelay socket was the only identity source. Target: private repo
`CharitonMedia/tremelay-ssh-test`, with a write deploy key added for the run and deleted after it.

1. github.com Ed25519 host key taken from `https://api.github.com/meta`; fingerprint
   `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` matched GitHub's published fingerprint, else the
   script stops. Grant 1: `ssh_userauth`, `--ssh-user git`, that host key pinned.
2. `git clone` and `git push` over `IdentityAgent=<tremelay ssh-agent socket>`: exit 0. Commit `7e2a663`
   ("5b live push via tremelay ssh-agent") is on the repo's `main` (confirmed through the GitHub API).
   GitHub does not implement `publickey-hostbound`, so this is the plain-publickey path bound to the
   verified `session-bind@openssh.com`. Audit: `ssh_userauth` rows `allowed` then `completed`, grant 1.
3. `grant revoke` of grant 1 while daemon and socket kept running: next `git push` failed
   `Permission denied (publickey)`, exit 128. The agent lists no key once the grant is gone, so the
   client had nothing to offer (no signing attempt, hence no `ssh_userauth` row for this step).
4. Grant 2 pinned to a different (freshly generated) Ed25519 host key: `git push` failed
   `Permission denied (publickey)`, exit 128. Audit: `ssh_userauth` rows `denied`
   (`expected_denial`), grant 2. Nothing was pushed after `7e2a663`.
5. Deploy key deleted after the run (repo key list empty); the vault directory was removed.

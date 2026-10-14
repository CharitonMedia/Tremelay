# Contributing

Thanks for helping build Tremelay. It is security infrastructure, so a correct
boundary matters more than a fast merge.

## Build and test

Use the pinned toolchain, Go 1.26.9 (see [go.mod](go.mod)). Everything CI runs is
in the [Makefile](Makefile):

```sh
make build   # go build ./cmd/tremelay
make test    # go test ./... plus the tools module
make vet     # go vet ./... plus the tools module
make race    # go test -race ./...
```

Many tests create real vault files and run the argon2 key derivation, so they are
slow on a spinning or network-mounted `TMPDIR`. Point it at tmpfs:

```sh
TMPDIR=/dev/shm/$USER-tremelay go test ./...
```

CI additionally runs `govulncheck ./...` and builds the reproducible Linux
candidate (`make candidate`) on Linux, Windows and macOS.

## Pull requests

Fork the repository, branch from `main`, and open a pull request into `main`.
Keep it to one coherent change. In the description, cover:

- the problem and the intended behavior
- security impact, and which threat-model sections it touches
- tests added or changed
- migration or compatibility impact, where applicable

## Security rules

These come from [AGENTS.md](AGENTS.md) and are not negotiable:

1. Never add an agent-facing raw-secret retrieval path, not even as a shortcut.
2. Security invariants outrank implementation convenience.
3. Deny by default.
4. Every attempted credential-backed operation must be auditable.
5. Never put raw credentials in logs, errors, traces, fixtures, or committed test
   data.
6. Do not invent cryptography — use mature libraries and standard constructions.
7. Do not weaken, skip, or delete a security test to make CI pass. Changing a
   security expectation requires documented review of the invariant it covers.
8. A change that affects a trust boundary needs an ADR under
   [docs/adr/](docs/adr/) ([the process](docs/adr/0000-adr-process.md)).
9. If a goal conflicts with the threat model or the invariants, stop that part and
   document the conflict instead of working around it.
10. Prefer the smallest implementation that satisfies the acceptance criteria.

A new dependency touching cryptography, authentication, authorization, network
proxying, parsing of untrusted data, or persistent secrets needs explicit
justification in the PR or ADR.

Read [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) and
[THREAT_MODEL.md](THREAT_MODEL.md) before touching credential, authorization,
network, audit, identity, cryptographic, or agent-facing code. [V1.md](V1.md) is
the current definition of done; anything not on that list is roadmap, not v1.

## Reporting a vulnerability

Do not open a public issue for an exploitable vulnerability. See
[SECURITY.md](SECURITY.md) for the current reporting posture.

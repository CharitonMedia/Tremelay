# M11a — unsigned Linux CLI candidate

M11a builds one unsigned linux/amd64 `tremelay` human CLI and a local evidence directory. It does not publish a release, sign a binary, or complete M9, M10, or M11. Tremelay is pre-release security software and should not yet be trusted with production credentials.

The profile is Go 1.26.9, `GOOS=linux`, `GOARCH=amd64`, `GOAMD64=v1`, `CGO_ENABLED=0`, and:

```text
go build -trimpath -buildvcs=false -mod=readonly -pgo=off -o OUTPUT ./cmd/tremelay
```

`GOTOOLCHAIN=go1.26.9` selects that toolchain and refuses a newer one. The application `go` line is already `1.26.9`. A `toolchain` directive is not added: current `go mod tidy` removes it, and `-mod=readonly` then refuses the module. The candidate checks `go version` before it builds. `-buildvcs=false` omits VCS metadata from the executable; the evidence manifest records the git commit and tree. Two matching builds are the reproducibility check. The flag list is not that check.

## Rerun

From a clean checkout of the commit being evidenced:

```text
make candidate
```

`make candidate` first captures one clean Git commit and its tree, then archives that commit before compiling anything. The helper and its tools module inputs come from that archive. The helper's link-time commit/tree must match the checkout at startup; a later clean checkout cannot be relabeled as the source that compiled the helper. Direct `go run` or an ordinary helper build has no bound source identity and is refused. Bootstrap checks the pinned Go version, derives the host OS/architecture after clearing inherited targets, uses conservative architecture settings and `CGO_ENABLED=0`, and disables persisted Go settings, workspaces, flag overlays, experiments and external build caches. It verifies the archived tools module cache before and after compiling the helper, checks that its module files stay unchanged, and removes its temporary helper, source and compilation cache when it exits.

The helper materializes the same captured commit in two absolute workspaces. Both builds and tool evidence use that tree. Each build has its own empty compilation cache. `GOENV=off`, `GOWORK=off`, an empty `GOEXPERIMENT`, an empty `GOCACHEPROG`, and `GOFIPS140=off` are set explicitly. The shared module download cache is populated from the committed application and tools graphs and checked with `go mod verify` before either build uses it. A later modification fails the candidate. Successful module verification is recorded in the receipt.

Output is `dist/m11a-candidate/`. The helper prepares the complete verified replacement, including any cross-filesystem copy, and then rechecks HEAD, tree and worktree immediately before modifying the previous candidate. Observed source drift leaves the previous candidate intact. Replacement failures attempt to restore it; an unsuccessful restore reports the retained backup path, and a cleanup failure after installation says that the new candidate was already installed. Temporary incoming directories and uniquely named backups are limited to this attempt. These checks assume a quiescent, trusted host with one candidate writer: they are observations, not an atomic lock against concurrent checkout changes, cache mutation, output writers, process termination or storage failure. Reconcile any reported uncertain filesystem outcome before retrying. The output is local or ordinary CI evidence and is not uploaded, signed, or published.

`make candidate` fails if the executables differ, the SBOM does not match the binary, the schema check fails, go.mod or go.sum changes, or govulncheck reports a called vulnerable symbol. Module-level findings are kept in the reports and the assurance note. They block any claim that the candidate has no vulnerabilities. They do not by themselves fail the symbol-level gate, which is the same positive result govulncheck uses for a non-zero text-mode exit. JSON and SARIF modes can exit 0 when findings exist; the gate reads the findings.

## Evidence

| File | What it is |
| --- | --- |
| `tremelay` | One of the two identical executables |
| `SHA256SUMS` | Checksums of the named files. Not a signature |
| `sbom.cdx.json` | CycloneDX 1.6 JSON from `cyclonedx-gomod bin`, then bound to this candidate |
| `sbom-validation.json` | Pinned schema, generator, and validator result |
| `binary-buildinfo.json` | `debug/buildinfo` read of the executable. The CLI is not run |
| `source-inventory.json` | `go list -m all` plus the build-tool module graph. Not the binary inventory |
| `build-inputs.json` | Commit, tree, module hashes, flags, Go settings, tool pins, builder image |
| `two-build-receipt.json` | Both paths, both caches, both SHA-256 values |
| `govulncheck-source.json` | Full-source `./...` scan, JSON |
| `govulncheck-binary.json` | Binary-mode scan of this executable, JSON |
| `govulncheck-*-meta.json` | Times, exit status, database endpoint, findings, limits |
| `README.md` | Short assurance note for this candidate |

`cyclonedx-gomod` `bin` is the binary inventory. It reads build information and does not execute the CLI. `app` would build again and would have to repeat these constraints. `mod` is the whole module graph, which is the separate source inventory instead. `-std` adds the standard library. The SBOM is checked against CycloneDX specification `1.6.2` commit `e833d732337dd33aceb45ff1991f896796f1e5e7`, including `spdx.schema.json` and `jsf-0.82.schema.json`, using `github.com/santhosh-tekuri/jsonschema/v6` v6.0.3. Generator, validator, and schema identities are in `sbom-validation.json` and `tools/schema/cyclonedx/PIN`.

The official MCP Go SDK v1.8.0 is classified from the binary. If build information lists it, the SBOM includes it. If a future binary omits it, the source inventory still lists it when `go.mod` requires it. Presence is not proof that every function remains linked or reachable. M10b stays an in-memory peer for protocol `2026-07-28`. It is not a network deployment or production authentication.

govulncheck is `golang.org/x/vuln` v1.8.0. The source scan is `./...`. The binary scan is `-mode=binary` on the candidate. Reports record UTC start and end, the scanner version and module sum, the exit status, the database endpoint, and `db_last_modified` when the tool reports it. That time is not an immutable database snapshot, and none is invented. The verifier reads `scan_mode`, `scanner_name`, and `scanner_version` from each raw report and accepts only that scope's `govulncheck-<scope>.json`. A called symbol blocks the candidate. An incomplete or non-zero scan also blocks it. Module-level findings stay in the report and do not by themselves fail that gate. Every failed attempt after a scan starts, including a called finding, parseable non-zero scan exit, or later cache/source/write/verification/publication failure, retains the available raw reports and unchanged scan metadata under `dist/m11a-failed-attempt-<UTC>-<unique>/`. `FAILED.txt` records the attempt failure before the reports are written. A completed source report is retained if the binary scan fails, and both completed reports are retained if a later step fails. Passing scan results remain passing scan results inside this explicitly failed attempt; they do not claim successful candidate completion. Failure evidence is separate from the verified candidate and contains no success README. If storage prevents saving all records, the error identifies the partial evidence or inability to save it.

The builder section records `/etc/os-release` and `uname` when present. `runner_image_revision` is the GitHub `ImageVersion` value, or `not exposed by this builder` when the environment has no image revision. A runner label is not an immutable image. Two paths on one builder do not prove independent-builder or cross-platform reproducibility.

CI pins for this job are `actions/checkout` `11d5960a326750d5838078e36cf38b85af677262` (v4.4.0) and `actions/setup-go` `40f1582b2485089dde7abd97c1529aa768e1baff` (v5.6.0). Tool versions and `h1` sums live in `tools/go.sum`, separate from the application module. The job has `contents: read` and does not upload the directory.

## What this does not show

These synthetic compatibility cases exercise older audit schemas in temporary databases. They are not historical-binary compatibility, independent security review, production authentication, or operational recovery:

- `TestM5MigratesPriorAuditSchema`
- `TestHealthAuditTamperTruncationAndMigration`
- `TestSharedTamperLegacyAndOldReader`
- `TestBackupMigratesLegacyAuditSchema`

Related limits that remain in force are documented in [ADR 0016](adr/0016-local-checkpoint-backup.md) and [docs/m9b-local-backup.md](m9b-local-backup.md): an old snapshot paired with the checkpoint issued for it is not detected as stale; a lost passphrase is not recovered; after an uncertain restore the host must reconcile single-active-instance state before retry or cutover; Windows directory-entry durability is only what the platform syncs; there is no backup CLI. M9a shared authorization is [ADR 0015](adr/0015-local-shared-vault-authorization.md). M10a and M10b are [ADR 0017](adr/0017-agent-capability-interface.md) and [ADR 0018](adr/0018-local-mcp-capability.md). The production-credential warning in `SECURITY.md` is unchanged.

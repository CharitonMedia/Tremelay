# ADR 0027: Release artifacts and the dry-run release workflow

Status: Accepted pending owner veto

## Context

V1.md item 6 is "install in one line": a release workflow that builds
linux/macOS/windows on amd64/arm64 with checksums and an SBOM, a working
`go install`, and a dry run on a tag on `v1` that produces all artifacts. V1.md
item 9 — merging to `main`, tagging `v1.0.0`, and announcing — is Patrick-gated,
and signed releases are explicitly out of v1.

So this slice has to build everything a release needs and publish none of it.
That split is the only consequential decision here, and it is what this ADR
records.

## Decision

`tools/release-dry.sh` builds the artifacts; `make release-dry` runs it locally
and `.github/workflows/release.yml` runs the same script in CI on a `v*` tag
push or a manual dispatch. One script, so a local run and the CI run cannot
drift.

For each of `linux`, `darwin`, `windows` × `amd64`, `arm64` it produces:

| Artifact | Notes |
| --- | --- |
| `tremelay_<version>_<os>_<arch>.tar.gz` / `.zip` | Contains `tremelay` (`tremelay.exe` on windows) and `LICENSE` |
| `tremelay_<version>_<os>_<arch>.cdx.json` | CycloneDX 1.6 JSON, one per binary |
| `SHA256SUMS` | Over all archives and SBOMs. Not a signature |

`<version>` is the tag name in CI (`github.ref_name`) and `git describe` locally.
It becomes part of every artifact path, so the script refuses anything outside
`[A-Za-z0-9._-]`.

## This workflow must not publish

The workflow has `permissions: contents: read`. It does not create a GitHub
Release, upload release assets, sign a binary, or push a commit, tag or branch.
Artifacts leave the job only as workflow artifacts, which expire and are not an
install channel. Publishing is V1 item 9 and owner-gated; a signed release is
out of v1 entirely. The same statement is a comment at the top of the workflow,
because that is where someone adding a publish step will be looking.

A read-only token is the enforcement, not the comment. Granting
`contents: write` to this workflow is the change that needs owner sign-off, not
the publish step that would follow it.

## Build profile

```text
GOTOOLCHAIN=go1.26.9 CGO_ENABLED=0 GOFLAGS=-mod=readonly GOAMD64=v1 GOARM64=v8.0
go build -trimpath -buildvcs=false -pgo=off \
  -ldflags "-X main.versionOverride=VERSION -X main.vcsRevisionOverride=COMMIT_OR_EMPTY" \
  -o OUTPUT ./cmd/tremelay
```

This is the M11a candidate profile (docs/m11a-unsigned-linux-candidate.md)
applied to six targets, for the same reasons: a pinned toolchain that refuses a
newer one, no cgo so the host's C toolchain is not an input, `-trimpath` so
build paths are not, `-mod=readonly` so a build cannot edit the module graph,
and default architecture baselines so two builders agree.

`-buildvcs=false` keeps the executable independent of git state, which is what
makes a local `make release-dry` and the CI run comparable. The version is
carried by the artifact names and, since #113, by `-ldflags -X` into
`tremelay version`. The commit is embedded the same way only when the checkout
is clean (`git status --porcelain --untracked-files=all` empty); otherwise the
binary names no commit. Git-ignored files are not seen by that check; CI builds
from a fresh checkout, where there are none. Two builds of the same commit and version still agree. `go version -m`
still reports the module graph.

Archives use fixed member names, zeroed ownership and a fixed 1980-01-01
timestamp so the archive bytes, not just the binaries, are reproducible.

Two matching builds are what would demonstrate reproducibility; the flag list is
not that demonstration. This slice does not add a second build — `make candidate`
already does that for linux/amd64, and item 6 asks for artifacts, not a
six-target reproducibility proof.

## SBOM tool

`github.com/CycloneDX/cyclonedx-gomod` v1.12.0, already pinned in `tools/go.mod`
with its `h1` sum in `tools/go.sum` and already the SBOM generator for the M11a
candidate. Invoked as `go tool cyclonedx-gomod bin -json -output-version 1.6
-std -noserial -notimestamp -version <version>`.

Reusing it adds no dependency and no second SBOM format to reason about. `bin`
mode reads the executable's build information and does not run it, which is also
why it works for the cross-compiled darwin and windows binaries on a Linux
runner. `-noserial -notimestamp` keep the output deterministic; `-std` includes
the standard library. SPDX was not considered seriously: CycloneDX is what this
repository already produces and validates.

The validation that `tools/evidence` performs for the candidate SBOM — pinned
schema check, generator identity, binary binding — is **not** applied here. That
machinery is bound to the candidate's evidence directory and single target.
Consequence, stated rather than implied: the release SBOMs are generator output,
not schema-validated evidence.

## Install path

`go install github.com/CharitonMedia/Tremelay/cmd/tremelay@<ref>` resolves the
module from its import path through the module proxy. It therefore depends on
the module path matching the GitHub path and on `go.mod` carrying no `replace`
directive — neither of which a local `go build` would catch.
`tools/release/install_test.go` asserts both, plus that `cmd/tremelay` is where
the documented path says it is. README documents `go install` and a
download-and-verify-checksum one-liner for linux/macOS.

## Alternatives considered

- **GoReleaser.** Rejected. It is a new dependency whose main value — creating
  GitHub Releases, signing, publishing to package managers — is exactly the part
  v1 must not do. What remains is a cross-compile loop and `sha256sum`.
- **A matrix job per target, building natively.** Rejected. Six runners for a
  CGO-free Go binary, and the checksum file would then have to be assembled
  across jobs.
- **Reuse the M11a candidate pipeline for all six targets.** Rejected. It is
  built around two-build comparison, govulncheck gating and a bound evidence
  directory for one target; widening it to six is a much larger change than item
  6 asks for, and the gating belongs to the candidate, not to artifact assembly.
- **Generate the SBOM from source (`cyclonedx-gomod mod`).** Rejected. That is
  the module graph, not what is in the shipped binary. The candidate already
  draws this distinction.
- **Embed the version with `-ldflags -X`.** Rejected at first (no version
  variable existed); adopted for #113 as described above.

## Consequences

- The item 6 acceptance line is demonstrable: a tag push on `v1`, or a manual
  dispatch, produces all 13 artifacts and uploads them without publishing.
- Users on a release get an unsigned artifact verified by a checksum file that
  is published the same way. That is the v1 state; signing is out of v1 and the
  production-credential warning in `SECURITY.md` still applies.
- `make release-dry` needs GNU tar, Info-ZIP `zip`, and `sha256sum` or `shasum`.
  The CI runner and render-1 have them; a BSD-tar-only host does not get
  byte-identical archives.
- Publishing remains one deliberate, owner-gated change: a permissions edit plus
  a new step.

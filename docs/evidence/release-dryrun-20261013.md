# Release dry run, 2026-10-13

Tag `v0.9.0-dryrun.1` on v1 commit 89b0c4e (merge of PR #49) triggered
`.github/workflows/release.yml`, run 38506327547: conclusion `success`. The single workflow
artifact `tremelay-v0.9.0-dryrun.1-artifacts` held 13 files: tar.gz for linux and darwin
amd64/arm64, zip for windows amd64/arm64, one CycloneDX SBOM per binary, and `SHA256SUMS`.
`sha256sum -c SHA256SUMS` on the downloaded files: all OK. `gh release list`: no releases;
the workflow created none.

`go install github.com/CharitonMedia/Tremelay/cmd/tremelay@89b0c4ebc28b` with a clean GOPATH,
GOMODCACHE and `GOPROXY=direct` built a working binary (`tremelay help` runs; `go version -m`
reports module version `v0.9.0-dryrun.1`). The direct fetch kept this pre-release tag out of
the public module proxy.

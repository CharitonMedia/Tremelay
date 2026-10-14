.PHONY: test vet race build candidate release-dry

test:
	go test ./...
	cd tools && GOTOOLCHAIN=go1.26.9 go test ./...

vet:
	go vet ./...
	cd tools && GOTOOLCHAIN=go1.26.9 go vet ./...

race:
	go test -race ./...

build:
	go build ./cmd/tremelay

# Unsigned linux/amd64 candidate and evidence. Refuses a dirty tree.
# The helper is verified and compiled by tools/bootstrap-candidate.sh.
candidate:
	sh tools/bootstrap-candidate.sh

# Six-platform binaries, archives, SBOMs and checksums in dist/release.
# Dry run only: it does not sign or publish. See docs/adr/0027-release-artifacts.md.
release-dry:
	sh tools/release-dry.sh

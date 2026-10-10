.PHONY: test vet race build candidate

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

.PHONY: test vet race build

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race ./...

build:
	go build ./cmd/tremelay

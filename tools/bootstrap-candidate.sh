#!/bin/sh
# Compile and run the unsigned candidate helper.
# The committed tools module cache is verified before the helper is built or executed.
# Persisted Go settings, workspaces, flag overlays, and external build caches are disabled.
set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)

apply_bootstrap_env() {
	cache=$1
	export GOENV=off
	export GOWORK=off
	export GOEXPERIMENT=
	export GOCACHEPROG=
	export GOFIPS140=off
	export GOTOOLCHAIN=go1.26.9
	export GO111MODULE=on
	export GOFLAGS=-mod=readonly
	export GOCACHE=$cache
	export GOPROXY=https://proxy.golang.org,direct
	export GOSUMDB=sum.golang.org
	export GOTELEMETRY=off
}

if [ "${1:-}" = "print-env" ]; then
	apply_bootstrap_env "${TMPDIR:-/tmp}/tremelay-m11a-bootstrap-print"
	printf '%s\n' \
		"GOENV=$GOENV" \
		"GOWORK=$GOWORK" \
		"GOEXPERIMENT=$GOEXPERIMENT" \
		"GOCACHEPROG=$GOCACHEPROG" \
		"GOFIPS140=$GOFIPS140" \
		"GOTOOLCHAIN=$GOTOOLCHAIN" \
		"GO111MODULE=$GO111MODULE" \
		"GOFLAGS=$GOFLAGS" \
		"GOCACHE=$GOCACHE" \
		"GOPROXY=$GOPROXY" \
		"GOSUMDB=$GOSUMDB" \
		"GOTELEMETRY=$GOTELEMETRY"
	exit 0
fi

cache=$(mktemp -d "${TMPDIR:-/tmp}/tremelay-m11a-bootstrap.XXXXXX")
trap 'rm -rf "$cache"' EXIT
apply_bootstrap_env "$cache"

gopath=$(go env GOPATH)
if [ -z "$gopath" ]; then
	echo "candidate bootstrap: GOPATH is unset" >&2
	exit 1
fi
export GOPATH=$gopath
modcache=$(go env GOMODCACHE)
if [ -z "$modcache" ]; then
	echo "candidate bootstrap: GOMODCACHE is unset" >&2
	exit 1
fi
export GOMODCACHE=$modcache

cd "$here"
go mod download
verify=$(go mod verify)
if [ "$verify" != "all modules verified" ]; then
	echo "candidate bootstrap: tools module cache: $verify" >&2
	exit 1
fi
bin=$cache/candidate
go build -mod=readonly -o "$bin" ./cmd/candidate
verify=$(go mod verify)
if [ "$verify" != "all modules verified" ]; then
	echo "candidate bootstrap: tools module cache changed before exec: $verify" >&2
	exit 1
fi
final=$(mktemp "${TMPDIR:-/tmp}/tremelay-m11a-helper.XXXXXX")
cp "$bin" "$final"
chmod +x "$final"
rm -rf "$cache"
trap - EXIT
unset GOCACHE
exec "$final" --root "$root"

#!/bin/sh
# Compile and run the unsigned candidate helper.
# Build only archived inputs and bind the helper to their captured Git identity.
# The committed tools module cache is verified before the helper is built or executed.
# Persisted Go settings, workspaces, flag overlays, and external build caches are disabled.
set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)

apply_bootstrap_env() {
	cache=$1
	# Never compile the helper for an inherited cross-compilation target or CPU.
	unset GOOS GOARCH GOHOSTOS GOHOSTARCH GOROOT
	unset CC CXX FC PKG_CONFIG CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_FFLAGS CGO_LDFLAGS
	unset CGO_CFLAGS_ALLOW CGO_CFLAGS_DISALLOW CGO_CPPFLAGS_ALLOW CGO_CPPFLAGS_DISALLOW
	unset CGO_CXXFLAGS_ALLOW CGO_CXXFLAGS_DISALLOW CGO_LDFLAGS_ALLOW CGO_LDFLAGS_DISALLOW
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
	export GOPRIVATE= GONOPROXY= GONOSUMDB= GOINSECURE=
	export GOTELEMETRY=off
	export CGO_ENABLED=0 GO_EXTLINK_ENABLED=0
	export GOAMD64=v1 GO386=softfloat GOARM=5,softfloat GOARM64=v8.0
	export GOMIPS=softfloat GOMIPS64=softfloat GOPPC64=power8 GORISCV64=rva20u64 GOWASM=
	version=$(go env GOVERSION)
	if [ "$version" != go1.26.9 ]; then
		echo "candidate bootstrap: Go version $version, want go1.26.9" >&2
		exit 1
	fi
	host_os=$(go env GOHOSTOS)
	host_arch=$(go env GOHOSTARCH)
	if [ -z "$host_os" ] || [ -z "$host_arch" ]; then
		echo "candidate bootstrap: missing Go host identity" >&2
		exit 1
	fi
	export GOOS=$host_os GOARCH=$host_arch
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
		"GOPRIVATE=$GOPRIVATE" "GONOPROXY=$GONOPROXY" "GONOSUMDB=$GONOSUMDB" "GOINSECURE=$GOINSECURE" \
		"GOTELEMETRY=$GOTELEMETRY" \
		"GOOS=$GOOS" "GOARCH=$GOARCH" "CGO_ENABLED=$CGO_ENABLED" "GO_EXTLINK_ENABLED=$GO_EXTLINK_ENABLED" \
		"GOAMD64=$GOAMD64" "GO386=$GO386" "GOARM=$GOARM" "GOARM64=$GOARM64" \
		"GOMIPS=$GOMIPS" "GOMIPS64=$GOMIPS64" "GOPPC64=$GOPPC64" "GORISCV64=$GORISCV64" "GOWASM=$GOWASM"
	exit 0
fi

commit=$(git -C "$root" rev-parse --verify 'HEAD^{commit}')
tree=$(git -C "$root" rev-parse --verify "$commit^{tree}")
case "$commit$tree" in
	*[!0-9a-f]*) echo "candidate bootstrap: invalid Git identity" >&2; exit 1 ;;
esac
if [ "${#commit}" -ne 40 ] || [ "${#tree}" -ne 40 ]; then
	echo "candidate bootstrap: ambiguous Git identity" >&2
	exit 1
fi

assert_source() {
	if [ "$(git -C "$root" rev-parse --verify 'HEAD^{commit}')" != "$commit" ] ||
		[ "$(git -C "$root" rev-parse --verify 'HEAD^{tree}')" != "$tree" ]; then
		echo "candidate bootstrap: source identity changed" >&2
		exit 1
	fi
	status=$(git -C "$root" status --porcelain --untracked-files=all)
	if [ -n "$status" ]; then
		echo "candidate bootstrap: refusing modified source" >&2
		exit 1
	fi
}
assert_source

work=$(mktemp -d "${TMPDIR:-/tmp}/tremelay-m11a-bootstrap.XXXXXX")
trap 'cd "$root"; rm -rf "$work"' 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$work/source" "$work/cache"
git -C "$root" archive --format=tar --output="$work/source.tar" "$commit"
# A relative archive path also avoids tar interpreting a Windows drive as a host.
(cd "$work/source" && tar -xf ../source.tar)
assert_source
cd "$work/source/tools"
apply_bootstrap_env "$work/cache"

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

cp go.mod "$work/tools.go.mod"
cp go.sum "$work/tools.go.sum"
assert_modules() {
	if ! cmp -s go.mod "$work/tools.go.mod" || ! cmp -s go.sum "$work/tools.go.sum"; then
		echo "candidate bootstrap: tools go.mod/go.sum changed" >&2
		exit 1
	fi
}
go mod download
verify=$(go mod verify)
if [ "$verify" != "all modules verified" ]; then
	echo "candidate bootstrap: tools module cache: $verify" >&2
	exit 1
fi
assert_modules
bin=$work/candidate
go build -mod=readonly -trimpath -buildvcs=false -pgo=off \
	-ldflags "-X main.bootstrapCommit=$commit -X main.bootstrapTree=$tree" \
	-o "$bin" ./cmd/candidate
verify=$(go mod verify)
if [ "$verify" != "all modules verified" ]; then
	echo "candidate bootstrap: tools module cache changed before exec: $verify" >&2
	exit 1
fi
assert_modules
assert_source
unset GOCACHE
# Keep the shell alive so the helper and its inputs are removed on every exit.
"$bin" --root "$root"

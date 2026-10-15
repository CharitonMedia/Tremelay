#!/bin/sh
# Build the dry-run release artifacts into dist/release: six reproducible
# binaries in archives, one CycloneDX SBOM per binary, and SHA256SUMS.
# This never signs, tags, publishes or pushes anything. Publishing a release is
# V1 item 9 and owner-gated.
# Needs GNU tar, Info-ZIP zip, and sha256sum or shasum.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version=${TREMELAY_VERSION:-$(git -C "$root" describe --tags --always --dirty)}
# The version reaches the filesystem as part of every artifact name.
case $version in
	"" | *[!A-Za-z0-9._-]*)
		echo "release-dry: unusable version '$version'" >&2
		exit 1
		;;
esac
out=${TREMELAY_RELEASE_OUT:-$root/dist/release}
# The script cds twice and rm -rf's this tree, so a relative path would name
# a different directory at each step, starting with the caller's own.
case $out in
	/*) ;;
	*)
		echo "release-dry: TREMELAY_RELEASE_OUT must be an absolute path" >&2
		exit 1
		;;
esac
stage=$out/stage

# zip and tar read options from the environment, and an --exclude there would
# ship an archive with no binary in it that still matches its checksum.
unset ZIPOPT ZIP TAR_OPTIONS GZIP

export GOTOOLCHAIN=go1.26.9
export CGO_ENABLED=0
export GOFLAGS=-mod=readonly
# Keep the per-architecture baselines at their defaults so two builders agree.
export GOAMD64=v1 GOARM64=v8.0

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}

rm -rf "$out"
mkdir -p "$stage"
cd "$root"

# The commit is embedded only from a clean checkout, so a binary never names a
# commit it was not built from. The version always is: it is already in every
# artifact name.
revision=
if [ -z "$(git -C "$root" status --porcelain 2>/dev/null || echo x)" ]; then
	revision=$(git -C "$root" rev-parse HEAD)
fi
ldflags="-X main.versionOverride=$version -X main.vcsRevisionOverride=$revision"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
	os=${target%/*}
	arch=${target#*/}
	exe=
	case $os in windows) exe=.exe ;; esac
	name="tremelay_${version}_${os}_${arch}"
	bin="tremelay$exe"

	GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false -pgo=off -ldflags "$ldflags" -o "$stage/$bin" ./cmd/tremelay
	cp LICENSE "$stage/LICENSE"
	# bin mode reads the executable's build information; it does not run it.
	(cd tools && go tool cyclonedx-gomod bin -json -output-version 1.6 -std \
		-noserial -notimestamp -version "$version" \
		-output "$out/$name.cdx.json" "$stage/$bin")

	# Fixed names, owners, modes and timestamps keep the archives
	# byte-identical: zip stores the unix mode, which follows the umask.
	chmod 0755 "$stage/$bin"
	chmod 0644 "$stage/LICENSE"
	TZ=UTC touch -t 198001010000 "$stage/$bin" "$stage/LICENSE"
	case $os in
	windows)
		(cd "$stage" && TZ=UTC zip -qX9 "$out/$name.zip" "$bin" LICENSE)
		;;
	*)
		# Inside $out, so a failed run leaves nothing behind in TMPDIR and
		# the next run's rm -rf clears it.
		tar_tmp=$out/.tar.tmp
		tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@315532800 \
			-C "$stage" -cf "$tar_tmp" "$bin" LICENSE
		gzip -n9 -c "$tar_tmp" >"$out/$name.tar.gz"
		rm -f "$tar_tmp"
		;;
	esac
	rm -f "$stage/$bin" "$stage/LICENSE"
done

rmdir "$stage"
cd "$out"
sha256 *.tar.gz *.zip *.cdx.json >SHA256SUMS
echo "release-dry: $version -> $out (not signed, not published)"

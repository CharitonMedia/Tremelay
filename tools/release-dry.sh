#!/bin/sh
# Build the dry-run release artifacts into dist/release: six reproducible
# binaries in archives, six MCP Bundles (.mcpb), one CycloneDX SBOM per binary,
# registry server.json, and SHA256SUMS.
# This never signs, tags, publishes or pushes anything. Publishing a release is
# V1 item 9 and owner-gated.
# Needs GNU tar, Info-ZIP zip, and sha256sum or shasum.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version=${TREMELAY_VERSION:-$(git -C "$root" describe --tags --always --dirty)}
version_semver=$version
case $version_semver in v*) version_semver=${version_semver#v} ;; esac
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

sha256_file() {
	sha256 "$1" | awk '{print $1}'
}

# write_mcpb_manifest writes manifest.json for MCPB v0.3 (os is linux|darwin|windows).
write_mcpb_manifest() {
	_os=$1
	_arch=$2
	_out=$3
	case $_os in
	linux) _platform=linux ;;
	darwin) _platform=darwin ;;
	windows) _platform=win32 ;;
	*) echo "release-dry: unknown os $_os" >&2; exit 1 ;;
	esac
	_entry=server/tremelay
	_cmd='${__dirname}/server/tremelay'
	case $_os in
	windows)
		_entry=$_entry.exe
		_cmd='${__dirname}/server/tremelay.exe'
		_extra_user=',
    "daemon_instance": {
      "type": "string",
      "title": "Daemon instance label",
      "description": "Optional pipe instance label when the daemon was started with TREMELAY_DAEMON_INSTANCE. Leave empty for the default pipe.",
      "required": false,
      "default": ""
    }'
		_extra_env='"TREMELAY_DAEMON_INSTANCE": "${user_config.daemon_instance}"'
		;;
	*)
		_extra_user=',
    "daemon_socket": {
      "type": "string",
      "title": "Daemon Unix socket",
      "description": "Optional absolute socket path when the daemon uses TREMELAY_DAEMON_SOCKET. Leave empty for the default socket.",
      "required": false,
      "default": ""
    }'
		_extra_env='"TREMELAY_DAEMON_SOCKET": "${user_config.daemon_socket}"'
		;;
	esac
	cat >"$_out" <<EOF
{
  "manifest_version": "0.3",
  "name": "tremelay",
  "display_name": "Tremelay",
  "version": "$version_semver",
  "description": "Credential broker MCP server (stdio); talks to a local unlocked Tremelay daemon.",
  "author": {"name": "CharitonMedia"},
  "repository": {"url": "https://github.com/CharitonMedia/Tremelay", "type": "git"},
  "homepage": "https://github.com/CharitonMedia/Tremelay",
  "license": "Apache-2.0",
  "compatibility": {"platforms": ["$_platform"]},
  "user_config": {
    "token_file": {
      "type": "file",
      "title": "Agent token file",
      "description": "Path to the agent token file from tremelay agent create --token-file. Start the daemon first: tremelay daemon --vault PATH.",
      "required": true
    }${_extra_user}
  },
  "server": {
    "type": "binary",
    "entry_point": "$_entry",
    "mcp_config": {
      "command": "$_cmd",
      "args": ["mcp", "--daemon", "--token-file", "\${user_config.token_file}"],
      "env": { ${_extra_env} }
    }
  }
}
EOF
}

rm -rf "$out"
mkdir -p "$stage"
cd "$root"

# The commit is embedded only from a clean checkout, so a binary never names a
# commit it was not built from. The version always is: it is already in every
# artifact name. Git-ignored files are not seen here; CI builds a fresh checkout.
revision=
if [ -z "$(git -C "$root" status --porcelain --untracked-files=all 2>/dev/null || echo x)" ]; then
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

	mcp_name="tremelay-mcp_${version}_${os}_${arch}"
	mcp_stage=$stage/mcpb
	rm -rf "$mcp_stage"
	mkdir -p "$mcp_stage/server"
	cp "$stage/$bin" "$mcp_stage/server/$bin"
	cp LICENSE "$mcp_stage/LICENSE"
	write_mcpb_manifest "$os" "$arch" "$mcp_stage/manifest.json"
	chmod 0755 "$mcp_stage/server/$bin"
	chmod 0644 "$mcp_stage/LICENSE" "$mcp_stage/manifest.json"
	TZ=UTC touch -t 198001010000 "$mcp_stage/server/$bin" "$mcp_stage/LICENSE" "$mcp_stage/manifest.json"
	(cd "$mcp_stage" && TZ=UTC zip -qX9 "$out/$mcp_name.mcpb" manifest.json LICENSE "server/$bin")
	rm -rf "$mcp_stage"
	cp "$out/$name.cdx.json" "$out/$mcp_name.cdx.json"

	rm -f "$stage/$bin" "$stage/LICENSE"
done

rmdir "$stage"
cd "$out"

# Registry server.json: fill version and per-bundle SHA-256 from the files just built.
server_json=$out/server.json
sed \
	-e "s/__VERSION_SEMVER__/$version_semver/g" \
	-e "s/__VERSION_TAG__/$version/g" \
	-e "s/__SHA256_LINUX_AMD64__/$(sha256_file tremelay-mcp_${version}_linux_amd64.mcpb)/" \
	-e "s/__SHA256_LINUX_ARM64__/$(sha256_file tremelay-mcp_${version}_linux_arm64.mcpb)/" \
	-e "s/__SHA256_DARWIN_AMD64__/$(sha256_file tremelay-mcp_${version}_darwin_amd64.mcpb)/" \
	-e "s/__SHA256_DARWIN_ARM64__/$(sha256_file tremelay-mcp_${version}_darwin_arm64.mcpb)/" \
	-e "s/__SHA256_WINDOWS_AMD64__/$(sha256_file tremelay-mcp_${version}_windows_amd64.mcpb)/" \
	-e "s/__SHA256_WINDOWS_ARM64__/$(sha256_file tremelay-mcp_${version}_windows_arm64.mcpb)/" \
	"$root/server.json" >"$server_json"

sha256 *.tar.gz *.zip *.mcpb *.cdx.json >SHA256SUMS
echo "release-dry: $version -> $out (not signed, not published)"

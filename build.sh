#!/usr/bin/env bash
# Builds optimized, static rudp binaries into dist/.
#
#   ./build.sh                          # this machine's platform
#   ./build.sh linux/amd64 linux/arm64  # the given GOOS/GOARCH targets
#   ./build.sh all                      # every target in ALL_TARGETS
#
# Go environment variables pass through, e.g. GOAMD64=v3 ./build.sh linux/amd64
set -euo pipefail

cd "$(dirname "$0")"

NAME=rudp
PKG=./cmd/rudp
OUT=dist
ALL_TARGETS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)

if [[ $# -eq 0 ]]; then
	targets=("$(go env GOOS)/$(go env GOARCH)")
elif [[ $# -eq 1 && $1 == all ]]; then
	targets=("${ALL_TARGETS[@]}")
else
	targets=("$@")
fi

echo "==> Go binaries: $(go version | cut -d' ' -f3)"
mkdir -p "$OUT"

for target in "${targets[@]}"; do
	if [[ $target != */* ]]; then
		echo "invalid target '$target': want GOOS/GOARCH, e.g. linux/amd64" >&2
		exit 2
	fi
	goos=${target%/*}
	goarch=${target#*/}
	bin="$OUT/$NAME-$goos-$goarch"
	[[ $goos == windows ]] && bin+=.exe

	# CGO_ENABLED=0: static binary with no libc dependency.
	# -trimpath:     no local file system paths in the binary, for reproducible builds.
	# -s -w:         strip the symbol table and DWARF debug info.
	CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch \
		go build -trimpath -ldflags='-s -w' -o "$bin" "$PKG"

	echo "$bin ($(du -h "$bin" | cut -f1))"
done

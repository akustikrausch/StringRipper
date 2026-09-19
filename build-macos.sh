#!/usr/bin/env bash
# build-macos.sh - the portable StringRipper CLI for macOS (files/folders only;
# process memory is Windows-only). Builds an arm64 slice (min macOS 11.0), an
# x86_64 slice (min macOS 10.15, no Metal - it is a CLI), and a universal binary.
#
# You can build BOTH slices on Apple Silicon: -arch selects the compile target,
# it is not Rosetta (Rosetta only matters for RUNNING x86_64 code). The macOS SDK
# ships both slices. See docs/MACOS.md.
#
# Usage: ./build-macos.sh
set -euo pipefail
cd "$(dirname "$0")"

SRC=src/cli_main.cpp
OUT=dist/mac
mkdir -p "$OUT"
FLAGS="-std=c++20 -O2 -Isrc -DNDEBUG -Wall"

echo "arm64  (min macOS 11.0)"
clang++ $FLAGS -arch arm64  -mmacosx-version-min=11.0  "$SRC" -o "$OUT/stringripper-arm64"

echo "x86_64 (min macOS 10.15)"
clang++ $FLAGS -arch x86_64 -mmacosx-version-min=10.15 "$SRC" -o "$OUT/stringripper-x86_64"

echo "universal (lipo)"
lipo -create -output "$OUT/stringripper" "$OUT/stringripper-arm64" "$OUT/stringripper-x86_64"
lipo -info "$OUT/stringripper"

echo
echo "built:"
ls -la "$OUT"
echo
echo "Gatekeeper on an unsigned binary: clear quarantine after download with"
echo "  xattr -dr com.apple.quarantine $OUT/stringripper"

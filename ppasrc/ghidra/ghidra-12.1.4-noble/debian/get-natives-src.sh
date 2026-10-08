#!/bin/bash
# Recreate natives-src/ before building the source package (dpkg-buildpackage -S).
# natives-src/ holds the C and C++ sources of Ghidra's native programs (decompiler, Sleigh
# compiler, GNU demanglers, lzfse), which debian/rules compiles on arm64. It is copied unchanged
# from Ghidra's 12.1.4 source release, so git doesn't track it.
# Run from the package directory: debian/get-natives-src.sh
set -euo pipefail
tag=Ghidra_12.1.4_build
sha=2a858300c350f05ae2e729dff86b4f584d0b9a6b398879c55025574e67696cec
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/src.tar.gz" "https://github.com/NationalSecurityAgency/ghidra/archive/refs/tags/$tag.tar.gz"
# macOS has shasum but no sha256sum.
if command -v sha256sum >/dev/null; then sum=(sha256sum); else sum=(shasum -a 256); fi
echo "$sha  $tmp/src.tar.gz" | "${sum[@]}" -c -
tar -xzf "$tmp/src.tar.gz" -C "$tmp"
s=$tmp/ghidra-$tag
rm -rf natives-src && mkdir natives-src
cp -a "$s/Ghidra/Features/Decompiler/src/decompile/cpp" natives-src/decompiler
cp -a "$s/GPL/DemanglerGnu/src/demangler_gnu_v2_24" natives-src/demangler_gnu_v2_24
cp -a "$s/GPL/DemanglerGnu/src/demangler_gnu_v2_41" natives-src/demangler_gnu_v2_41
cp -a "$s/Ghidra/Features/FileFormats/src/lzfse/c" natives-src/lzfse
echo "natives-src/ recreated from $tag"

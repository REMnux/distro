#!/bin/bash
# Recreate natives-src/ before building the source package (dpkg-buildpackage -S).
# natives-src/ holds the C and C++ sources of Ghidra's native programs (decompiler, Sleigh
# compiler, GNU demanglers, lzfse), which debian/rules compiles on arm64. It is copied unchanged
# from Ghidra's 12.1.2 source release, so git doesn't track it.
# Run from the package directory: debian/get-natives-src.sh
set -euo pipefail
tag=Ghidra_12.1.2_build
sha=c30fe709ec5d5e68bf799a6c1f4dfc6853dacb189d10203eb882ecbb408db216
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/src.tar.gz" "https://github.com/NationalSecurityAgency/ghidra/archive/refs/tags/$tag.tar.gz"
echo "$sha  $tmp/src.tar.gz" | sha256sum -c -
tar -xzf "$tmp/src.tar.gz" -C "$tmp"
s=$tmp/ghidra-$tag
rm -rf natives-src && mkdir natives-src
cp -a "$s/Ghidra/Features/Decompiler/src/decompile/cpp" natives-src/decompiler
cp -a "$s/GPL/DemanglerGnu/src/demangler_gnu_v2_24" natives-src/demangler_gnu_v2_24
cp -a "$s/GPL/DemanglerGnu/src/demangler_gnu_v2_41" natives-src/demangler_gnu_v2_41
cp -a "$s/Ghidra/Features/FileFormats/src/lzfse/c" natives-src/lzfse
echo "natives-src/ recreated from $tag"

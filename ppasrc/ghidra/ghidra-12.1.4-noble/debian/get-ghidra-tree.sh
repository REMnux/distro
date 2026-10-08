#!/bin/bash
# Recreate ghidra/ before building. ghidra/ is upstream's Ghidra 12.1.4 release zip, extracted
# unchanged, so git doesn't track it. Run debian/get-natives-src.sh as well before building.
# Run from the package directory: debian/get-ghidra-tree.sh
set -euo pipefail
tag=Ghidra_12.1.4_build
zip=ghidra_12.1.4_PUBLIC_20260921.zip
# The SHA-256 published on https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build
sha=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$zip" "https://github.com/NationalSecurityAgency/ghidra/releases/download/$tag/$zip"
# macOS has shasum but no sha256sum.
if command -v sha256sum >/dev/null; then sum=(sha256sum); else sum=(shasum -a 256); fi
echo "$sha  $tmp/$zip" | "${sum[@]}" -c -
unzip -q "$tmp/$zip" -d "$tmp/x"
rm -rf ghidra && mv "$tmp/x/${zip%_*}" ghidra
echo "ghidra/ recreated from $zip"

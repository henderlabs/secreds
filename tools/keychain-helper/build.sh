#!/bin/bash
# Build and sign the Keychain helper. Usage: build.sh [IDENTITY-SHA-or-name]  (default: first "Apple Development" identity)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${SECREDS_HOME:-$HOME/.secreds}/seCreds-kc.app"
ID="${1:-$(security find-identity -v -p codesigning | awk '/Apple Development/ {print $2; exit}')}"
[ -n "$ID" ] || { echo "No Apple Development signing identity found."; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT/Contents/MacOS"
cp "$HERE/Info.plist" "$OUT/Contents/Info.plist"
swiftc -O -o "$OUT/Contents/MacOS/seCreds-kc" "$HERE/main.swift" \
  -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker "$HERE/Info.plist"
codesign --force --options runtime --sign "$ID" --identifier local.secreds.keychain "$OUT"
codesign --verify --strict "$OUT"
"$OUT/Contents/MacOS/seCreds-kc" ident
echo "built $OUT"

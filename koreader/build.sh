#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT/koreader/hitsz_connect.koplugin/bin"
mkdir -p "$OUT"

echo "Building Kindle ARM binary (GOARM=5; runs on armv6/armv7 Kindles)..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
  go build -trimpath -ldflags='-s -w' -o "$OUT/hitsz-connect-linux-arm" "$ROOT"

echo "Building Kindle aarch64 binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags='-s -w' -o "$OUT/hitsz-connect-linux-arm64" "$ROOT"

chmod 700 "$OUT/hitsz-connect-linux-arm" "$OUT/hitsz-connect-linux-arm64"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$OUT" && sha256sum hitsz-connect-linux-arm hitsz-connect-linux-arm64 > SHA256SUMS)
else
  (cd "$OUT" && shasum -a 256 hitsz-connect-linux-arm hitsz-connect-linux-arm64 > SHA256SUMS)
fi
echo "KOReader plugin ready: $ROOT/koreader/hitsz_connect.koplugin"

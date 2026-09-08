#!/usr/bin/env bash
# build-release.sh — tüm ikilileri hedef platformlar için çapraz derler.
# Çıktı: dist/<os>-<arch>/ altında c2, agent, watchdog, gencerts (+ .exe).
#
# Kullanım:
#   scripts/build-release.sh [VERSION]
# VERSION verilmezse git etiketinden ya da 'dev' kullanılır.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.agentVersion=${VERSION}"
OUT="dist"
rm -rf "$OUT"

# Hedefler: server yalnız sunucu OS'ları; agent+watchdog tüm uç OS'ları.
PLATFORMS=("windows/amd64" "linux/amd64")

echo "XEMS release derleme — sürüm ${VERSION}"
for p in "${PLATFORMS[@]}"; do
  GOOS="${p%/*}"; GOARCH="${p#*/}"
  ext=""; [ "$GOOS" = "windows" ] && ext=".exe"
  dir="${OUT}/${GOOS}-${GOARCH}"
  mkdir -p "$dir"
  echo "  → ${GOOS}/${GOARCH}"
  for t in "c2:./server/cmd/c2" "agent:./agent/cmd/agent" "watchdog:./agent/cmd/watchdog" "gencerts:./tools/gencerts"; do
    name="${t%%:*}"; pkg="${t#*:}"
    GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
      go build -trimpath -ldflags "$LDFLAGS" -o "${dir}/${name}${ext}" "$pkg"
  done
done

echo "Tamamlandı. Çıktı: ${OUT}/"
find "$OUT" -type f | sort

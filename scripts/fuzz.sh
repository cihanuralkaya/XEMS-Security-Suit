#!/usr/bin/env bash
# Kısa fuzz taraması: kritik ayrıştırıcıların (parser) rastgele/kötü niyetli
# girdide panik atmadığını doğrular. Her hedef FUZZTIME (varsayılan 15s) süre
# fuzz edilir. CI'da güvenlik-regresyon kalkanı; yerelde daha uzun süreyle
# (FUZZTIME=2m bash scripts/fuzz.sh) çalıştırılabilir.
set -euo pipefail

FUZZTIME="${FUZZTIME:-15s}"

# pkg:FuzzFn çiftleri (güven sınırını aşan ham girdi ayrıştıran saf fonksiyonlar).
TARGETS=(
  "./server/internal/logingest/:FuzzNormalizeJSON"
  "./server/internal/logingest/:FuzzNormalizeCEF"
  "./server/internal/logingest/:FuzzNormalizeLEEF"
  "./server/internal/logingest/:FuzzNormalizeSyslog"
  "./server/internal/logingest/:FuzzNormalizeWinEvent"
  "./server/internal/sigma/:FuzzConvertMulti"
  "./contentscan/:FuzzParseRules"
  "./offboard/:FuzzDecode"
  "./server/internal/notify/:FuzzParseWindows"
  "./agent/internal/dlp/:FuzzScan"
  "./agent/internal/dnsmon/:FuzzScoreDomain"
  "./server/internal/detect/:FuzzLoadRules"
  "./server/internal/auditexport/:FuzzVerify"
)

fail=0
for t in "${TARGETS[@]}"; do
  pkg="${t%%:*}"
  fn="${t##*:}"
  echo "── fuzz ${fn} (${pkg}) [${FUZZTIME}] ──"
  if ! go test "$pkg" -run='^$' -fuzz="^${fn}\$" -fuzztime="$FUZZTIME"; then
    echo "FUZZ BAŞARISIZ: ${fn}"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "FUZZ TARAMASI BAŞARISIZ — yeni corpus girdisi testdata/ altına yazıldı."
  exit 1
fi
echo "FUZZ TARAMASI GEÇTİ — panik bulunamadı."

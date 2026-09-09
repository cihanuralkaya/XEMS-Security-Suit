#!/usr/bin/env bash
# smoke-test.sh — uçtan uca kabul testi: gerçek c2 + gerçek agent'ı ayağa
# kaldırır, kayıt → heartbeat → olay → admin eylem → SSE zincirini iddialarla
# doğrular. Bellek-içi demo modu (harici bağımlılık yok). CI'da da çalışır.
#
# Çıkış kodu 0 = tüm iddialar geçti.
set -uo pipefail
cd "$(dirname "$0")/.."

EXT=""; [ "${OS:-}" = "Windows_NT" ] && EXT=".exe"
WORK="$(mktemp -d 2>/dev/null || echo "./_smoke")"; mkdir -p "$WORK"
AGENT_PORT=18443; ENROLL_PORT=18444; ADMIN_PORT=18445
B="https://127.0.0.1:${ADMIN_PORT}"
PIDS=()
FAILED=0

log(){ printf '  %s\n' "$*"; }
pass(){ printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail(){ printf '  \033[31m✗ %s\033[0m\n' "$*"; FAILED=1; }
cleanup(){
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

echo "[1/6] İkilileri derle"
go build -o "$WORK/c2$EXT" ./server/cmd/c2 || { echo "c2 derlenemedi"; exit 1; }
go build -o "$WORK/agent$EXT" ./agent/cmd/agent || { echo "agent derlenemedi"; exit 1; }
go build -o "$WORK/gencerts$EXT" ./tools/gencerts || { echo "gencerts derlenemedi"; exit 1; }
pass "c2, agent, gencerts derlendi"

# Depo modu: XEMS_DATABASE_URL verilirse PostgreSQL (şema yükle + admin tohumla),
# aksi halde bellek-içi demo. Diğer tüm adımlar/iddialar aynıdır.
MODE="bellek-içi"
if [ -n "${XEMS_DATABASE_URL:-}" ]; then
  MODE="PostgreSQL"
  command -v psql >/dev/null 2>&1 || { echo "psql gerekli (DB modu)"; exit 1; }
  echo "[2/6] PostgreSQL: şema yükle + admin tohumla"
  psql "$XEMS_DATABASE_URL" -v ON_ERROR_STOP=1 -q -f db/schema.sql \
    && pass "şema yüklendi (db/schema.sql)" || { fail "şema yüklenemedi"; exit 1; }
  go run ./tools/adminseed -email admin@local -password smoke1234 -role ADMIN -name Smoke \
    | tail -n +2 | psql "$XEMS_DATABASE_URL" -v ON_ERROR_STOP=1 -q \
    && pass "yönetici tohumlandı (Argon2id)" || fail "admin tohumlanamadı"
fi

echo "[2/6] PKI + sunucuyu başlat ($MODE)"
"$WORK/gencerts$EXT" -out "$WORK/pki" -name xems-c2 >/dev/null
MASTER_KEY="$(openssl rand -base64 32 2>/dev/null || head -c32 /dev/urandom | base64)"
COMMON_ENV=(
  "XEMS_MASTER_KEY=$MASTER_KEY"
  "XEMS_CA_CERT=$WORK/pki/ca.crt" "XEMS_CA_KEY=$WORK/pki/ca.key"
  "XEMS_SERVER_CERT=$WORK/pki/server.crt" "XEMS_SERVER_KEY=$WORK/pki/server.key"
  "XEMS_LISTEN_AGENT=:$AGENT_PORT" "XEMS_LISTEN_ENROLL=:$ENROLL_PORT" "XEMS_LISTEN_ADMIN=:$ADMIN_PORT"
  "XEMS_VULN_FILE=deploy/vuln-sample.json"
  "XEMS_INGEST_TOKEN=smoke-ingest-token"
)
if [ -n "${XEMS_DATABASE_URL:-}" ]; then
  # DB modunda yatay-ölçekleme fan-out'unu aç (#10): SSE iddiası gerçek Postgres
  # LISTEN/NOTIFY round-trip'ini doğrular (tek düğüm de NOTIFY'ı kendine geri alır).
  env "${COMMON_ENV[@]}" "XEMS_DATABASE_URL=$XEMS_DATABASE_URL" "XEMS_CLUSTER=1" "$WORK/c2$EXT" > "$WORK/c2.log" 2>&1 &
else
  env "${COMMON_ENV[@]}" "XEMS_DEMO=1" "XEMS_DEMO_ADMIN_PASSWORD=smoke1234" "$WORK/c2$EXT" > "$WORK/c2.log" 2>&1 &
fi
PIDS+=($!)

# Admin API hazır olana dek bekle (maks ~10 sn)
ready=0
for _ in $(seq 1 50); do
  if curl -sk "$B/" -o /dev/null 2>/dev/null; then ready=1; break; fi
  sleep 0.2
done
[ "$ready" = 1 ] && pass "C2 dinliyor (:$ADMIN_PORT)" || { fail "C2 başlamadı"; cat "$WORK/c2.log"; exit 1; }

echo "[3/6] Giriş + enrollment token"
TOK="$(curl -sk "$B/api/login" -X POST -H 'Content-Type: application/json' \
  -d '{"email":"admin@local","password":"smoke1234"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')"
[ -n "$TOK" ] && [ "$TOK" != "$(printf '{')" ] && pass "yönetici girişi başarılı" || fail "giriş başarısız"
ETOK="$(curl -sk "$B/api/enrollment-tokens" -X POST -H "Authorization: Bearer $TOK" -d '{}' \
  | sed -E 's/.*"enrollment_token":"([^"]+)".*/\1/')"
[ ${#ETOK} -ge 16 ] && pass "enrollment token üretildi" || fail "token üretilemedi"

echo "[4/6] Ajanı kaydet + olay akışını doğrula"
XEMS_ENROLL_ADDR="127.0.0.1:$ENROLL_PORT" XEMS_AGENT_ADDR="127.0.0.1:$AGENT_PORT" \
XEMS_SERVER_NAME="xems-c2" XEMS_CA_PEM="$WORK/pki/ca.crt" XEMS_ENROLL_TOKEN="$ETOK" \
XEMS_AGENT_DATA="$WORK/agent-data" XEMS_HEARTBEAT_INTERVAL="2s" XEMS_SAFE_MODE="1" \
  "$WORK/agent$EXT" > "$WORK/agent.log" 2>&1 &
PIDS+=($!)

# Cihaz görünene dek bekle
dev=0
for _ in $(seq 1 40); do
  n="$(curl -sk "$B/api/devices" -H "Authorization: Bearer $TOK" | grep -o '"id"' | wc -l)"
  if [ "$n" -ge 1 ]; then dev=1; break; fi
  sleep 0.25
done
[ "$dev" = 1 ] && pass "ajan kaydoldu (cihaz listede)" || fail "cihaz kaydı görünmedi"

# "kimlik hazır" log satırı, cihaz sunucuda göründükten SONRA yazılır (ajan
# ensureEnrolled → sunucuya kayıt → log). Tek-atışta yarışa girmemek için poll et.
idok=0
for _ in $(seq 1 40); do
  if grep -q "kimlik hazır" "$WORK/agent.log"; then idok=1; break; fi
  sleep 0.25
done
[ "$idok" = 1 ] && pass "ajan kimliği üretildi (CSR imzalandı)" || fail "ajan kimliği yok"

# Olaylar ilk heartbeat/toplama döngüsünden SONRA gelir (interval 2s). Tek-atış
# yerine yayılım için poll et (en çok ~15 sn).
evc=0
for _ in $(seq 1 60); do
  evc="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -o '"id"' | wc -l)"
  if [ "$evc" -ge 1 ]; then break; fi
  sleep 0.25
done
[ "$evc" -ge 1 ] && pass "olaylar alındı ($evc olay)" || fail "olay yok"
# Olay cihaz-atfı: her olay device_id taşımalı (filo-geneli triyaj/gruplama).
curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -q '"device_id"' \
  && pass "olaylar cihaz-atfı (device_id) taşıyor" || fail "olaylarda device_id yok"
# Uyum olayı: disk şifreleme + güvenlik duvarı durumu (poll — uyum kontrolü exec-ağır).
comp=""
for _ in $(seq 1 40); do
  comp="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -oE '"firewall":"[^"]+"' | head -1)"
  [ -n "$comp" ] && break
  sleep 0.25
done
[ -n "$comp" ] && pass "uyum olayı güvenlik duvarı durumu taşıyor ($comp)" || fail "uyum olayında firewall yok"
# Yazılım envanteri: ajan yüklü yazılım listesini raporlamalı (MDM varlık).
inv=""
for _ in $(seq 1 40); do
  inv="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -oE '"software_count":[0-9]+' | head -1)"
  [ -n "$inv" ] && break
  sleep 0.25
done
[ -n "$inv" ] && pass "yazılım envanteri raporlandı ($inv)" || fail "yazılım envanteri yok"
# Zafiyet eşleştirme: envanter × CVE veri kümesi (örnek set 7-Zip/Adobe içerir).
vln=""
for _ in $(seq 1 40); do
  vln="$(curl -sk "$B/api/vulnerabilities" -H "Authorization: Bearer $TOK" | grep -oE '"vulnerable_devices":[0-9]+' | head -1)"
  echo "$vln" | grep -qE ':[1-9]' && break
  sleep 0.25
done
echo "$vln" | grep -qE ':[1-9]' && pass "zafiyet eşleştirme çalıştı ($vln)" || fail "zafiyet eşleşmesi yok"
# Kaynak telemetrisi: ajan bellek/disk/uptime raporlamalı (uç-nokta sağlığı).
rsc=""
for _ in $(seq 1 40); do
  rsc="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -oE '"mem_used_pct":[0-9]+' | head -1)"
  [ -n "$rsc" ] && break
  sleep 0.25
done
[ -n "$rsc" ] && pass "kaynak telemetrisi raporlandı ($rsc)" || fail "kaynak telemetrisi yok"
# Filo yazılım araması: envanterdeki bir paketi ara, cihaz eşleşmeli.
pkg="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -oE '"software":\["[^"]+"' | head -1 | sed -E 's/.*\["([^"]+)".*/\1/' | cut -c1-6)"
if [ -n "$pkg" ]; then
  curl -sk "$B/api/software?q=$(printf %s "$pkg" | sed 's/ /%20/g')" -H "Authorization: Bearer $TOK" | grep -q '"device_count":[1-9]' \
    && pass "filo yazılım araması eşleşti ($pkg)" || fail "yazılım araması başarısız"
else
  fail "arama için paket adı bulunamadı"
fi

echo "[5/6] Admin eylemleri + okuma uçları"
DID="$(curl -sk "$B/api/devices" -H "Authorization: Bearer $TOK" | sed -E 's/.*"id":"([^"]+)".*/\1/')"
curl -sk "$B/api/devices/collect-diagnostics" -X POST -H "Authorization: Bearer $TOK" \
  -d "{\"device_id\":\"$DID\"}" -o /dev/null
sleep 0.3
curl -sk "$B/api/audit?limit=20" -H "Authorization: Bearer $TOK" | grep -q "COLLECT_DIAGNOSTICS" \
  && pass "tanılama komutu kuyruğa alındı + denetlendi" || fail "tanılama denetim izinde yok"
# Vaka yönetimi (#9): bir olaya sorumlu+not ata, listede geri oku (db SetEventCase/EventAcks).
EVID="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | sed -E 's/.*"id":"([^"]+)".*/\1/')"
curl -sk "$B/api/events/$EVID/case" -X POST -H "Authorization: Bearer $TOK" \
  -d '{"assignee":"soc@corp","note":"otomatik smoke vaka"}' -o /dev/null
curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -q '"ack_assignee":"soc@corp"' \
  && pass "olay vaka ataması (assignee) kalıcı + okundu" || fail "olay vaka ataması görünmedi"
curl -sk "$B/api/audit?limit=20" -H "Authorization: Bearer $TOK" | grep -q "EVENT_CASE" \
  && pass "vaka ataması denetim izine yazıldı" || fail "vaka denetim izinde yok"
# Kurcalama-kanıtlı denetim dışa aktarımı (#16): hash-zincirli JSONL üretilir.
exp="$(curl -sk "$B/api/audit/export" -H "Authorization: Bearer $TOK")"
echo "$exp" | grep -q '"hash"' \
  && pass "/api/audit/export hash-zinciri üretti" || fail "/api/audit/export başarısız"
curl -sk "$B/api/summary" -H "Authorization: Bearer $TOK" | grep -q "devices_total" \
  && pass "özet uç yanıt verdi" || fail "özet uç başarısız"
curl -sk "$B/api/policies" -H "Authorization: Bearer $TOK" | grep -q "policies" \
  && pass "politika listeleme uç yanıt verdi" || fail "politika uç başarısız"
# Tehdit etkinliği sayaçları (kimlik doğrulanmış) — yeni /api/activity ucu.
curl -sk "$B/api/activity" -H "Authorization: Bearer $TOK" | grep -q "detections" \
  && pass "/api/activity sayaçları döndü" || fail "/api/activity başarısız"
# Tespit kural kataloğu ucu.
curl -sk "$B/api/detections/rules" -H "Authorization: Bearer $TOK" | grep -q "XEMS-0001" \
  && pass "/api/detections/rules kataloğu döndü" || fail "/api/detections/rules başarısız"
# Tespit kuralı test aracı (dry-run): örnek olay → eşleşen kural.
curl -sk "$B/api/detections/test" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"category":"SECURITY","message":"ajan kurcalama girisimi"}' \
  | grep -q "XEMS-0001" \
  && pass "/api/detections/test kuralı eşleştirdi" || fail "/api/detections/test başarısız"
# Retro-hunt (#1): mevcut kuralları geçmiş olaylara uygula (QueryEvents + değerlendirme).
curl -sk "$B/api/hunt" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"mode":"rules","limit":500}' \
  | grep -q '"scanned"' \
  && pass "/api/hunt retro-hunt çalıştı (geçmiş olaylar tarandı)" || fail "/api/hunt başarısız"
# Olay korelasyonu (#2): incident listeleme ucu yanıt versin.
curl -sk "$B/api/incidents" -H "Authorization: Bearer $TOK" | grep -q '"incidents"' \
  && pass "/api/incidents korelasyon ucu döndü" || fail "/api/incidents başarısız"
# Zamanlanmış/dışa aktarılabilir rapor (#7): duruş raporu HTML üretimi.
curl -sk "$B/api/report" -H "Authorization: Bearer $TOK" | grep -q "XEMS Security Suite" \
  && pass "/api/report duruş raporu üretti" || fail "/api/report başarısız"
curl -sk "$B/api/coverage" -H "Authorization: Bearer $TOK" | grep -q "coverage_pct" \
  && pass "/api/coverage filo kapsamı döndü" || fail "/api/coverage başarısız"
curl -sk "$B/api/metrics/trends?days=7" -H "Authorization: Bearer $TOK" | grep -q "mttd_seconds" \
  && pass "/api/metrics/trends MTTD/MTTR trendi döndü" || fail "/api/metrics/trends başarısız"
curl -sk "$B/api/maintenance" -H "Authorization: Bearer $TOK" | grep -q "windows" \
  && pass "/api/maintenance bakım pencereleri ucu döndü" || fail "/api/maintenance başarısız"
# Harici log alımı (#21 SIEM): JSON log gönder, normalize edilip yazılmalı.
curl -sk "$B/api/ingest" -X POST -H "Authorization: Bearer smoke-ingest-token" \
  -H "Content-Type: application/json" \
  -d '[{"source":"fw-test","category":"NETWORK_CONN","severity":"high","message":"smoke ingest"}]' \
  | grep -q '"accepted":1' \
  && pass "/api/ingest harici log alımı çalıştı" || fail "/api/ingest başarısız"
# Zengin telemetri: cihaz OS sürümü (ilk heartbeat'ten sonra dolar) — poll et.
osv=""
for _ in $(seq 1 40); do
  osv="$(curl -sk "$B/api/devices" -H "Authorization: Bearer $TOK" | grep -oE '"os_version":"[^"]+"' | head -1)"
  [ -n "$osv" ] && break
  sleep 0.25
done
[ -n "$osv" ] && pass "cihaz OS sürümü raporlandı ($osv)" || fail "os_version boş kaldı"
# Sağlık uçları (kimlik doğrulama YOK) — /healthz sürüm + uptime içerir.
curl -sk "$B/healthz" | grep -q "uptime_seconds" \
  && pass "/healthz sürüm + uptime içeriyor" || fail "/healthz zenginleştirme yok"
[ "$(curl -sk -o /dev/null -w '%{http_code}' "$B/healthz")" = "200" ] \
  && pass "/healthz 200 (liveness)" || fail "/healthz başarısız"
[ "$(curl -sk -o /dev/null -w '%{http_code}' "$B/readyz")" = "200" ] \
  && pass "/readyz 200 (readiness)" || fail "/readyz başarısız"

echo "[6/6] SSE canlı akış"
SSE="$(curl -sk -N --max-time 5 "$B/api/stream" -H "Authorization: Bearer $TOK" 2>/dev/null)"
echo "$SSE" | grep -q '"type":"' && pass "SSE bildirim iletti" || fail "SSE bildirim gelmedi"

echo
if [ "$FAILED" = 0 ]; then
  echo -e "\033[32mSMOKE TEST GEÇTİ — uçtan uca zincir sağlıklı.\033[0m"; exit 0
else
  echo -e "\033[31mSMOKE TEST BAŞARISIZ.\033[0m"; echo "--- c2.log ---"; tail -20 "$WORK/c2.log"; exit 1
fi

# Durum Raporu — XEMS Security Suite
# Status Report — XEMS Security Suite

**Türkçe** · [English](#english)

Bu belge, kod tabanının mevcut durumunu, neyin nasıl doğrulandığını ve bilinçli
olarak kapsam dışı bırakılanları özetler. Devir/gözden geçirme için referanstır.

## Özet

Mimari dökümdeki **yazılım-tarafı yeteneklerin tamamına yakını** kodlandı ve test
edildi. Güvenlik-kritik akışlar gerçek mTLS gRPC ve gerçek kripto ile **uçtan uca
kanıtlandı** (`server/internal/e2e`). Kernel-seviye tamper koruması bilinçli
olarak kapsam dışıdır (bkz. aşağıda).

- Dil: **Go** (tek dil), iletişim **gRPC + mTLS**, TLS 1.3.
- ~25 600 satır üretim Go + kapsamlı test.
- **475 test fonksiyonu / 67 test paketi**, tümü geçiyor (`go test ./...`).
- Cross-compile doğrulandı: Windows (native), Linux, macOS.
- **Bellek-içi demo modu** canlı çalıştırıldı (`XEMS_DATABASE_URL` boş): gerçek
  enrollment, gerçek ağ keşfi, tüm admin/konsol akışları uçtan uca denendi.

## Uçtan uca kanıtlanan zincir (e2e)

`enroll (PKI) → mTLS → heartbeat (sunucu-saati) → politika dağıtımı (push) →
OTA imza + rollout kapısı → komut teslimi (karantina) → tek-kullanımlık token`
— hepsi tek entegrasyon testinde, gerçek TCP + mTLS gRPC + gerçek imza/hash ile.

**Smoke/kabul testi** (`scripts/smoke-test.sh`, `make smoke`): gerçek c2 + gerçek
agent süreçlerini izole portlarda ayağa kaldırır ve kayıt → CSR imza → heartbeat →
olay → admin eylem (tanılama) → denetim izi → özet/politika okuma → **SSE canlı
akış** zincirini ~28 iddiayla doğrular. **CI** (`.github/workflows/ci.yml`):
proto üret + `go vet` + `go test ./...` + smoke test + çapraz derleme (artifact).

## Yetenek matrisi

| Yetenek | Durum | Paket | Doğrulama |
|---|---|---|---|
| Enrollment / PKI bootstrap | ✅ | `server/internal/enroll` | e2e + birim |
| Kriptografi (HMAC blind index, AES-GCM, CA/CSR) | ✅ | `server/internal/security` | birim |
| mTLS gRPC (2 sunucu) | ✅ | `server/internal/grpc` | e2e |
| Heartbeat + sunucu-saati çıpası | ✅ | `grpc` + `agent/internal/agentclock` | e2e + birim |
| Politika motoru (mesai-dışı, gece-aşırı) | ✅ | `agent/internal/policy` | birim |
| Politika dağıtımı — anlık push | ✅ | `server/internal/policypush` | e2e + birim |
| Süreç enforcement (izle + sonlandır) | ✅ Win gerçek / Linux derlendi | `agent/internal/enforce` | birim + gerçek liste (Win) |
| Store-and-forward olay tamponu | ✅ | `agent/internal/collector` | birim |
| OTA imza doğrulama (Ed25519) | ✅ | `server/internal/ota`, `agent/internal/update`, `otawire` | e2e + birim |
| OTA indirme + staging | ✅ | `agent/internal/update` | birim (httptest) |
| Kademeli dağıtım (canary) | ✅ | `server/internal/rollout` | e2e + birim |
| Watchdog (gözetim + swap + rollback) | ✅ | `agent/internal/watchdog` | birim |
| Çift-süreç karşılıklı gözetim | ✅ | `agent/internal/liveness` | birim |
| Ağ keşfi (ARP/komşu) | ✅ Win gerçek / Linux derlendi | `agent/internal/discovery` | birim + gerçek tarama (Win) |
| Karantina (ağ izolasyonu) | ✅ mantık / OS derlendi | `agent/internal/quarantine` | birim (sahte izolatör) |
| Komut kuyruğu (karantina teslimi) | ✅ | `server/internal/db` + `grpc` | e2e |
| Admin servisi (RBAC + denetim izi) | ✅ | `server/internal/admin` | birim |
| Admin HTTP API + Argon2 + oturum | ✅ | `server/internal/adminapi` | birim (httptest) |
| Giriş kaba-kuvvet koruması (per-IP kilit) | ✅ | `adminapi/ratelimit.go` | birim + httptest |
| Yönetici yönetimi (oluştur/rol/pasifleştir) | ✅ | `admin/adminusers.go`, `db/admins.go` | birim + canlı demo |
| Enrollment token yönetimi (listele/iptal) | ✅ | `db/tokens.go`, `adminread` | birim + canlı demo |
| Politika listeleme (kural + cihaz sayımı) | ✅ | `adminread.ListPolicies`, `db/policy.go` | birim + canlı demo |
| Konsol: önem grafiği, cihaz arama, CSV dışa aktarma | ✅ | `adminapi/console.html` | canlı demo |
| Cihaz-detay olay akışı (device-scoped) | ✅ | `adminapi/console.html` + `adminread` | canlı demo |
| Tanılama topla komutu (COLLECT_DIAGNOSTICS) | ✅ | `admin.CollectDiagnostics` | birim + canlı demo |
| Canlı SSE push (olay/heartbeat → konsol) | ✅ | `eventbus`, `grpc.AdminNotifier`, `/api/stream` | birim + entegrasyon + canlı demo |
| KVKK veri sahibi hakları (erişim/dışa aktarma + silme) | ✅ | `admin.EraseDevice/AuthorizeExport`, `adminread.ExportDevice` | birim + canlı demo |
| Sağlık/hazırlık uçları (`/healthz`, `/readyz`) | ✅ | `adminapi` + `Store.Ping` | birim + smoke |
| Olay ayrıntısı (yapısal JSON) + sunucu-taraflı süzme | ✅ | `adminread`, `grpc` | birim + canlı demo |
| Cihaz OFFLINE otomasyonu (bayat heartbeat) | ✅ | `db/status.go`, `memstore` | birim |
| Web yönetim konsolu (SOC paneli, canlı yenileme) | ✅ | `adminapi/console.html` (embed) | httptest + canlı demo |
| Okuma API'si + görünürlük | ✅ | `server/internal/adminread` | birim |
| KVKK saklama otomasyonu | ✅ mantık / DB derlendi | `server/internal/retention` | birim |
| Davranışsal anomali tespiti + eğitilmiş model çıkarımı | ✅ Faz 1-3 | `agent/internal/anomaly` + `enforce` | birim |
| Kurcalama-kanıtı denetim izi (hash-zincir, SEC C-1) | ✅ | `security.AuditChainHash`, memstore+db | birim |
| Admin 2FA/MFA (TOTP, RFC 6238) + at-rest şifreli sır | ✅ | `security.totp`, `admin`, `db/mfa.go` | birim (RFC vektörleri) + httptest (uçtan uca) |
| Prometheus `/metrics` (token korumalı, bağımlılıksız) | ✅ | `server/internal/metrics`, `adminapi` | birim + httptest |
| SOC gerçek-zamanlı uyarı (HTTPS webhook, önem eşiği) | ✅ | `server/internal/notify`, `grpc` | birim (TLS httptest) |
| MITRE ATT&CK teknik eşlemesi + kapsama ucu | ✅ | `server/internal/mitre`, `grpc`, `adminapi` | birim + httptest |
| mTLS sunucu SPKI pinning (opsiyonel, rotasyonlu) | ✅ | `agent/internal/transport/pin.go` | birim + openssl çapraz-kontrol |
| Otomatik müdahale/SOAR (kritik olayda oto-karantina) | ✅ opsiyonel | `server/internal/response`, `grpc` | birim |
| Sunucu-taraflı tespit motoru (Sigma-benzeri kurallar) | ✅ | `server/internal/detect`, `grpc`, `adminapi` | birim + httptest |
| Cihaz etiketleme/gruplama (filo yönetimi + filtre) | ✅ | `admin`, `db`, `adminapi`, `console` | birim + httptest |
| Yapısal olay Details (ağ/enforce/anomali → structpb) | ✅ | `agent` (enforce, main) | birim |
| Tehdit istihbaratı (IoC) eşleştirme (IP/MAC/domain/hash) | ✅ opsiyonel | `server/internal/ioc`, `grpc` | birim |
| Süreç soyağacı zenginleştirme (ebeveyn zinciri) | ✅ Win/Linux | `agent/internal/enforce` | birim (zincir + stat ayrıştırma) |
| Zengin ajan telemetrisi (OS sürümü → cihaz envanteri) | ✅ Win/Linux | `agent/internal/osinfo`, proto, grpc, db | birim + e2e + smoke (gerçek sürüm) |
| Disk şifreleme uyum raporu (BitLocker/LUKS) | ✅ mantık/OS-derlendi | `agent/internal/compliance` | birim (ayrıştırıcılar) |
| Özel tespit kuralları (operatör-tanımlı, dosyadan) | ✅ opsiyonel | `detect.LoadRules`, `c2 main` | birim |
| Slack/Teams uyumlu uyarı biçimi | ✅ opsiyonel | `server/internal/notify` | birim (TLS httptest) |
| Genişletilmiş /metrics (tespit/uyarı/SOAR/IoC + runtime) | ✅ | `server/internal/metrics` | birim |
| Konsol: sol kenar çubuğu IA + bölüm derin-bağlama | ✅ | `adminapi/console.html` | canlı demo |
| Yapısal JSON loglama (server+agent, SIEM) | ✅ opsiyonel | `logx`, c2/agent main | birim |
| Config başlangıç öz-doğrulaması | ✅ | `server/internal/config` | birim |
| Denetim izi zincir doğrulama (konsol düğmesi) | ✅ | `adminapi`, console | canlı |
| Dağıtım koruma-duruşu görünürlüğü (/api/features) | ✅ | `adminapi`, c2 main, console | birim + canlı |
| Tehdit etkinlik sayaçları kartı (/api/activity) | ✅ | `adminapi`, `metrics`, console | birim + canlı |
| Tespit kuralı test aracı / dry-run (/api/detections/test) | ✅ | `adminapi`, `detect`, console | birim + smoke + canlı |
| MITRE ATT&CK kapsam boşluğu analizi + JSON dışa aktarım | ✅ | `adminapi/console.html` | canlı |
| Konsol: olay/denetim tıkla-süz chip'leri (klavye erişilebilir) | ✅ | `adminapi/console.html` | canlı |
| Olay cihaz-atfı (device_id) + en çok olay üreten cihazlar | ✅ | `adminread`, `db`, `memstore`, console | birim + smoke + canlı |
| Cihaz durumu hızlı-süzgeci (online/offline/karantina) | ✅ | `adminapi/console.html` | canlı |
| Uyum kontrolleri: disk şifreleme + güvenlik duvarı (agent) | ✅ | `agent/compliance` | birim + smoke + canlı |
| Filo uyum görünürlüğü: kart + cihaz-detay + "uyumsuz" KPI + CSV | ✅ | `adminread`, console | birim + canlı |
| Sunucu-taraflı uyum özeti (doğru filo KPI, /api/summary) | ✅ | `adminread`, `db`, `memstore` | birim + smoke |
| Sertleştirme: istek gövdesi 1 MiB sınırı (DoS) | ✅ | `adminapi` | birim |
| Sertleştirme: admin HTTP zaman aşımları (slowloris) | ✅ | c2 main | smoke (SSE korunur) |
| Şifreli PostgreSQL şeması | ✅ | `db/schema.sql` | — |
| Zengin süreç-çalıştırma telemetrisi (komut satırı + soyağacı) | ✅ Win/Linux | `agent/internal/enforce`, `monitor` | birim |
| Tespit motoru v2 (regex/alan/eşik kuralları) | ✅ | `server/internal/detect` | birim + smoke |
| Ağ bağlantı telemetrisi (dinleyen/kurulu) | ✅ Win/Linux | `agent/internal/netconn`, grpc, db | birim |
| İsteğe-bağlı dosya/artefakt toplama (adli/IR) | ✅ | `admin.CollectFile`, `grpc.UploadArtifact`, `artifacts` tablosu | birim + canlı |
| Envanterden zafiyet eşleştirme (CVE) | ✅ opsiyonel | `server/internal/vuln`, `adminread`, console | birim + smoke |
| MDM uzak eylemler: LOCK/RESTART (gerçek) + WIPE (gerçek kripto-silme, 3 katman) | ✅ Win/Linux | `admin`, `agent/internal/deviceaction`, proto | birim (ARM kapısı) + smoke |
| USB/çıkarılabilir medya kontrolü: denetle + gerçek engelleme (dismount/eject) | ✅ Win/Linux | `agent/internal/usbmon` | birim (safe-mode kapısı) |
| SIEM iletici (syslog + CEF/LEEF) | ✅ opsiyonel | `server/internal/notify/siem.go`, c2 main | birim |
| Vaka/olay yönetimi (sorumlu + not, denetimli) | ✅ | `admin.UpdateEventCase`, `adminread`, `db`, `memstore`, console | birim + smoke + canlı |
| Yatay ölçekleme / HA (çok-düğüm SSE fan-out) | ✅ opsiyonel | `server/internal/cluster` (Postgres LISTEN/NOTIFY), `eventbus`, `db` | birim + smoke (gerçek pg_notify) |
| IoC tehdit istihbaratı canlı hot-reload (yeniden başlatmasız) | ✅ opsiyonel | `grpc` (atomic.Pointer), `ioc`, c2 main | birim + canlı (gerçek sunucu) |
| Tespit kuralları canlı hot-reload (yeniden başlatmasız) | ✅ opsiyonel | `grpc`+`adminapi` (atomic.Pointer), `detect`, c2 main | birim + canlı (gerçek sunucu) |
| Artefakt saklama budaması (adli/IR dosya, sınırsız büyümeyi önler) | ✅ | `retention`, `db`, `memstore` | birim + smoke |
| Yerel CI-paritesi kapısı (make check/check-all) + CI -race | ✅ | Makefile, `.github/workflows/ci.yml` | CI (eşzamanlılık yarış dedektörü) |
| Çift-kontrol (dört-göz) WIPE onayı (opsiyonel) | ✅ | `admin`, `adminapi`, `db`, `memstore`, console | birim + HTTP + canlı |
| Gerçek yıkıcı MDM zorlama (WIPE kripto-silme + USB engelleme, 3-katman guard) | ✅ Win/Linux | `agent/internal/deviceaction`+`usbmon`, agent main | birim (guard kapıları) |
| Retro-hunt + SIEM olay araması (geçmiş olaylar) | ✅ | `adminread`+`adminapi` (QueryEvents), db, console | birim + HTTP + smoke |
| Alarm korelasyonu + otomatik incident gruplama | ✅ | `server/internal/correlate`, grpc, db, console | birim + smoke |
| Dosya bütünlüğü izleme (FIM) — ajan | ✅ | `agent/internal/fim` (SHA-256), agent main | birim |
| Ajan öz-tasdiki (takas/yama ikili tespiti) | ✅ | proto, `grpc`, `db`, `memstore`, agent | birim (kurcalama teşhisi) |
| Harici log alımı (JSON/CEF/LEEF/syslog/Windows olay) | ✅ opsiyonel | `server/internal/logingest`, `adminapi` (`/api/ingest`) | birim + fuzz |
| Sunucu-taraflı korelasyon analizörleri (beacon/yanal/DNS-tünel/kaba-kuvvet) | ✅ | `beacon`, `dnstunnel`, `bruteforce`, c2 arka plan işleri | birim (saf analizör) |

## V2 yetenekleri (2026-09 eklemeleri)

Aşağıdakiler ilk matristen sonra eklendi; hepsi test + smoke + CI yeşil.

- **Canonical Event Model v1.1 (§5):** `model.Event` kanonik kimlik/ilişki alanlarıyla
  genişletildi — `event_id` (içerik-adresli, dedup/replay temeli), `source`, `event_type`,
  `confidence`, `correlation_id`, `parent_event_id`, `tenant_id`. Migrasyonsuz (details
  JSONB round-trip); `/api/events` bunları ilk-sınıf yüzeye çıkarır; logingest 5 formatta
  damgalar. §17 korelasyon + §19 replay temeli.
- **Scope / ROE guardrail (§4):** yüksek-etkili operasyonlar (WIPE/QUARANTINE/LOCK/
  RESTART) enqueue'dan önce merkezi `server/internal/scope` motorundan geçer
  (fail-closed, excluded-wins, ROE action-gate; wildcard domain + IPv4/IPv6 CIDR +
  device/tenant/env/port seçiciler). `XEMS_SCOPE_*` ile yapılandırılır; enforce +
  denetim (would-deny) modları; `xems_scope_denied_total` metriği. Bkz.
  [V2-GAP-ANALYSIS.md](V2-GAP-ANALYSIS.md).
- **SOC istihbaratı:** çok-faktörlü **risk skorlama** (`/api/risk`), **saldırı hikâyesi**
  (kill-chain, `/api/devices/{id}/attack-story`), **varlık grafı** (`/graph`), **incident
  zaman çizelgesi**, **MTTD/MTTR** trendleri (`/api/metrics/trends`), **UEBA** (yönetici
  davranış analitiği, `/api/ueba/admins`), uyum çerçevesi eşleme (**CIS/NIST/ISO/KVKK**,
  `/api/compliance/frameworks`).
- **Tespit:** çok-sinyal **korelasyon** (yüksek-güven zincir), **yanal hareket** (netconn
  fan-out, T1046), **DNS tünelleme** (T1071.004), **kaba-kuvvet/parola-püskürtme** (Windows
  4625/4771 seri toplama, saldırgan IP + hedef hesap özniteliği, T1110), **başarılı
  kaba-kuvvet / hesap ele geçirme** (başarısız-seri ardından başarılı oturum → CRITICAL),
  geliştirilmiş **DGA** (ünsüz-dizisi), **Sigma içe aktarma**, **YARA-tarzı içerik tarama**,
  Detection-as-Code yaşam-döngüsü, **16 teknikli** MITRE kataloğu (Windows olay
  telemetrisi → ATT&CK: hizmet/görev kurulumu, hesap oluşturma, ayrıcalık, günlük
  temizleme, kod enjeksiyonu) + 14 yerleşik kural.
- **Korelasyon bütünlüğü:** sunucu-taraflı tespitler (beacon/yanal/DNS-tüneli/kaba-kuvvet)
  artık ajan tespitleri gibi **izlenen incident'lere** dönüşür (vaka yönetimi + filo-risk)
  VE **çok-sinyal saldırı zincirini** besler; filo-risk incident istismar-edilebilirliğini
  önem düzeyine göre tartar (aktif tehdit önceliği).
- **İmzalı içerik (kurcalamaya karşı):** TÜM yüklenebilir içerik (YARA, tespit kuralı,
  IoC, anomali modeli, OTA, offline offboard, denetim dışa aktarımı) Ed25519 imzalanabilir.
- **Alarm & teslim:** bildirim **yönlendirme + yükseltme**, **webhook HMAC imza**, sürekli
  **tehdit-avı** (kayıtlı aramalar), zamanlanmış **rapor webhook teslimi**, sunucu-taraflı
  tespitlerin SOC uyarı yoluna bağlanması.
- **Alım (SIEM):** JSON + **CEF** + **LEEF** (QRadar) + düz **syslog** (RFC5424/3164) +
  **Windows olay günlüğü** (winlogbeat/nxlog/EVTX; EventID+kanal sınıflaması, EventData
  zenginleştirme: hedef hesap/kaynak IP/oturum türü) giden log alımı, hız sınırlama.
  Beş biçimin tümü olayın gerçek zaman damgasını kullanır (zaman çizelgesi doğruluğu);
  tüm ağ-yüzeyli ayrıştırıcılar fuzz + özyineleme-derinliği koruması altında. Operatörler
  için çevrimdışı doğrulama CLI'si (`logcheck`) ve entegrasyon kılavuzu (`docs/INGEST.md`).
- **Ops/dayanıklılık:** **sertifika ömür-sonu izleme** (log + `/api/features` + metrik),
  **kaba-kuvvet kilidi sinyali**, genişletilmiş Prometheus metrikleri + hazır **alarm
  kuralları** (`deploy/prometheus-alerts.example.yml`), istek korelasyon kimliği + erişim logu.
- **Platform:** çok-kiracılı temel (kimlik + çıktı atıfı), kanonik olay şema sürümü.
- **Tedarik zinciri güvenliği (CI):** `govulncheck` + **fuzzing** + **SBOM** + gosec
  (4 gerçek CVE düzeltildi); dağıtım sertleştirme (`deploy/HARDENING.md`).

## İlk inceleme bulguları — karşılıklar

Bkz. `docs/threat-model.md`. Özet: kırık şema düzeltildi, şifreli-log yerine
at-rest + partitioning; düz-hash yerine **HMAC blind index**; yerel-saat yerine
**sunucu-saati çıpası**; hash-yerine **imza** OTA'da; enrollment/PKI eklendi;
RBAC + değişmez denetim izi.

**Agent güvenlik denetiminde yakalanan bulgular (düzeltildi):** Adversarial güvenlik incelemesi (siber güvenlik uzmanı agent) iki YÜKSEK bulgu buldu: **SEC-001** konsol XSS (`esc()` HTML kaçışı yapmıyordu → innerHTML'de saldırgan-kontrollü veri) ve **SEC-002** sertifika iptali bypass (`Renew` iptal kontrolü yapmıyordu → 60 sn cache penceresinde yeni cert). İkisi de düzeltildi + regresyon testi. Kalan orta/düşük öneriler (SPKI pinning; oturum iptali/MFA/denetim izi & anomali modeli imzalama uygulandı) yol haritasında.

**CI'da (Linux) yakalanan bulgu (düzeltildi):** `policy.matchesTarget`
`filepath.Base` kullanıyordu — Linux'ta `\` ayırıcıyı bölmez, bu yüzden
Windows-yolu süreçler (`D:\x\a.exe`) Linux'ta dosya adıyla eşleşmiyor ve
politika/enforce testleri yalnız CI'da FAIL veriyordu. OS-bağımsız `baseName`
(`/` ve `\`) ile düzeltildi; regresyon testi `TestMatchesTargetSeparatorAgnostic`.
Ürün hem Windows hem Linux hedeflediği için gerçek cross-platform düzeltmesi.

**Canlı demo sırasında yakalanan bulgu (düzeltildi):** bellek-içi
`LookupAdmin` `is_active` süzmüyordu → pasifleştirilen yönetici hâlâ giriş
yapabiliyordu. PostgreSQL yolu (`WHERE ... AND is_active`) zaten doğruydu;
memstore ona eşitlendi + regresyon testi (`TestLookupAdminExcludesDeactivated`).

## Bilinçli olarak kapsam dışı / canlı doğrulanmayan

- **Kernel-seviye tamper koruması** (MiniFilter sürücüsü + PPL/ELAM): C/C++, EV
  sertifikası, WHQL/attestation imzalama, BSOD riski — Go kod tabanının dışında,
  çok yüksek maliyetli **ayrı proje** (tasarım + Go-tarafı arayüz: `docs/KERNEL-TAMPER.md`).
  Userland savunma-derinliği (watchdog + çift-süreç canlılık + FIM + öz-tasdik + imzalı OTA)
  **ilk savunma** olarak sevk edilir; `agent/internal/tamperprotect` koruma DURUŞUNU
  (none/userland/kernel) değerlendirip başlangıçta SECURITY olayı olarak raporlar ve gelecek
  sürücüyü otomatik algılayan bir seam sağlar (sürücü kurulursa kod değişikliği gerekmez).
- **Canlı çalıştırılmayanlar** (mantık test edildi, ama bu ortamda çalıştırılmadı):
  - PostgreSQL'e karşı gerçek sorgular: bu makinede Postgres/Docker olmadığından
    yerelde çalıştırılmadı; **ancak CI'da `postgres:16` servisine karşı GEÇTİ**
    (`.github/workflows/ci.yml` → `db-test`, run #6 yeşil): şema yüklendi, admin
    tohumlandı, pgx yolu tüm zincirle (kayıt→olay→admin eylem→SSE) çalıştı. Yani
    DB katmanı artık **canlı doğrulanmış** durumda.
  - Gerçek firewall izolasyonu (`netsh`/`iptables`) — ağı keser, riskli.
  - Gerçek süreç **sonlandırma** — testte sahte controller (gerçek süreç öldürülmedi).
  - Linux `/proc`+SIGKILL ve OS izolatörleri — yalnız cross-compile.
  - `go test -race` — C derleyicisi (gcc) yok; eşzamanlılık mutex/atomic ile doğru-inşa.
- **Operasyonel uçlar:** veri sahibi başvuru akışı (KVKK erişim/silme) **YAPILDI**
  (aşağı bkz.). ONNX ML anomali hattı: **Faz 1-3 YAPILDI** — saf-Go istatistiksel +
  JSON-eğitilmiş-model (MLP/lojistik) çıkarımı, ajan-döngüsüne bağlı, SECURITY olayları
  üretir. **ONNX köprüsü YAPILDI (Seçenek D, DÜŞÜK risk):** `tools/onnx2json` çevrimdışı
  dönüştürücü, eğitilmiş bir ONNX'i (Gemm/MatMul + Relu/Sigmoid) taşınabilir JSON ağırlık
  formatına çevirir + Ed25519 imzalar (`-sign-key`); çalışan ikiliye/CGo/CI/go.mod'a
  ETKİSİ YOK (bkz. `docs/ONNX.md`). Gerçek onnxruntime CGo backend'i `//go:build onnx`
  arkasında **opt-in olarak belgelendi** (varsayılan derleme saf-Go kalır) — yalnız keyfi
  ONNX grafikleri gerekirse; CGO_ENABLED=0 cross-compile'ı bozacağından varsayılanda YOK.
  İmzalı script yürütme YAPILDI; süreç-AĞACI sonlandırma **YAPILDI** (enforce.descendants;
  denetim/audit modu XEMS_ENFORCE_AUDIT ile) — gerçek sandbox ileri faz.

## Çalıştırma

```bash
make proto && go mod tidy && go test ./...   # üret + test
make dev-certs                                # geliştirme sertifikaları + env önerisi
go run ./tools/otasign -genkey -out ./ota-keys
go run ./tools/adminseed -email a@x -password '...' -role ADMIN
# db/schema.sql yükle, XEMS_* env ayarla, bin/c2 ve bin/agent çalıştır
# yönetim konsolu: https://localhost:8445/
```

## Araçlar

- `tools/gencerts` — dev/prod CA + sunucu sertifikası.
- `tools/otasign` — OTA imza anahtarı üretimi + sürüm imzalama (+ SQL).
- `tools/adminseed` — yönetici parolası (Argon2id) + INSERT SQL.
- `tools/anomalytrain` — etiketli CSV'den lojistik anomali modeli eğitir ve
  `ModelScorer` JSON formatına yazar (eğit→JSON→ajan hattını tamamlar).
- `tools/mkclient` — TEK DOSYA istemci kurulum betiği üreteci (benzersiz/token
  gömülü veya paylaşımlı/kod girişli; ajan ikilisi base64 gömülü; Win/Linux).

## Dağıtım / paketleme (nihai teslimat) — ✅

- `scripts/build-release.sh` — c2/agent/watchdog/gencerts çapraz derleme
  (Windows+Linux amd64 → `dist/`), sürüm ldflags ile damgalı.
- **Sunucu kurulumu:** `deploy/server/install-linux.sh` (systemd),
  `install-windows.ps1` (zamanlanmış görev) — PKI + ana anahtar + config +
  servis otomasyonu. `c2.env.example` şablonu.
- **İstemci kurulumu:** `mkclient` ile üretilen tek-dosya installer; token gömülü
  (benzersiz) veya kod girişli (paylaşımlı); ajan+CA gömülü; servis kurar.
- Ayrıntı: `deploy/README.md`. **Canlı doğrulandı:** üretilen benzersiz Windows
  installer'ın gömülü yükü çalıştırıldığında cihaz başarıyla kaydoldu.

---

# English

This document summarizes the current state of the codebase, what was verified and
how, and what is deliberately out of scope. It is a handover/review reference.

## Summary

**Nearly all of the software-side capabilities** from the architecture doc are
implemented and tested. Security-critical flows are **proven end-to-end** with real
mTLS gRPC and real cryptography (`server/internal/e2e`). Kernel-level tamper
protection is deliberately out of scope (see below).

- Language: **Go** (single language), communication over **gRPC + mTLS**, TLS 1.3.
- ~15,000 lines of production Go + comprehensive tests.
- **277 test functions / 47 test packages**, all passing (`go test ./...`).
- Cross-compilation verified: Windows (native), Linux, macOS.
- **In-memory demo mode** run live (`XEMS_DATABASE_URL` empty): real enrollment, real
  network discovery, all admin/console flows exercised end-to-end.

## End-to-end proven chain (e2e)

`enroll (PKI) -> mTLS -> heartbeat (server-clock) -> policy distribution (push) ->
OTA signature + rollout gate -> command delivery (quarantine) -> single-use token`
- all in one integration test, with real TCP + mTLS gRPC + real signatures/hashes.

**Smoke/acceptance test** (`scripts/smoke-test.sh`, `make smoke`): brings up real c2
+ real agent processes on isolated ports and verifies the enroll -> CSR signing ->
heartbeat -> event -> admin action (diagnostics) -> audit log -> summary/policy read
-> **live SSE stream** chain with ~28 assertions. **CI** (`.github/workflows/ci.yml`):
proto generation + `go vet` + `go test ./...` + smoke test + cross-compilation.

## Capability matrix

| Capability | Status | Package | Verification |
|---|---|---|---|
| Enrollment / PKI bootstrap | done | `server/internal/enroll` | e2e + unit |
| Cryptography (HMAC blind index, AES-GCM, CA/CSR) | done | `server/internal/security` | unit |
| mTLS gRPC (2 servers) | done | `server/internal/grpc` | e2e |
| Heartbeat + server-clock anchor | done | `grpc` + `agent/internal/agentclock` | e2e + unit |
| Policy engine (after-hours, overnight) | done | `agent/internal/policy` | unit |
| Policy distribution - instant push | done | `server/internal/policypush` | e2e + unit |
| Process enforcement (watch + terminate) | Win real / Linux compiled | `agent/internal/enforce` | unit + real list (Win) |
| Store-and-forward event buffer | done | `agent/internal/collector` | unit |
| OTA signature verification (Ed25519) | done | `server/internal/ota`, `agent/internal/update`, `otawire` | e2e + unit |
| OTA download + staging | done | `agent/internal/update` | unit (httptest) |
| Staged rollout (canary) | done | `server/internal/rollout` | e2e + unit |
| Watchdog (supervision + swap + rollback) | done | `agent/internal/watchdog` | unit |
| Dual-process mutual supervision | done | `agent/internal/liveness` | unit |
| Network discovery (ARP/neighbor) | Win real / Linux compiled | `agent/internal/discovery` | unit + real scan (Win) |
| Quarantine (network isolation) | logic / OS compiled | `agent/internal/quarantine` | unit (fake isolator) |
| Command queue (quarantine delivery) | done | `server/internal/db` + `grpc` | e2e |
| Admin service (RBAC + audit log) | done | `server/internal/admin` | unit |
| Admin HTTP API + Argon2 + session | done | `server/internal/adminapi` | unit (httptest) |
| Login brute-force protection (per-IP lockout) | done | `adminapi/ratelimit.go` | unit + httptest |
| Admin management (create/role/deactivate) | done | `admin/adminusers.go`, `db/admins.go` | unit + live demo |
| Enrollment token management (list/revoke) | done | `db/tokens.go`, `adminread` | unit + live demo |
| Policy listing (rule + device counts) | done | `adminread.ListPolicies`, `db/policy.go` | unit + live demo |
| Console: severity chart, device search, CSV export | done | `adminapi/console.html` | live demo |
| Device-detail event stream (device-scoped) | done | `adminapi/console.html` + `adminread` | live demo |
| Collect-diagnostics command | done | `admin.CollectDiagnostics` | unit + live demo |
| Live SSE push (event/heartbeat -> console) | done | `eventbus`, `grpc.AdminNotifier`, `/api/stream` | unit + integration + live demo |
| Data-subject rights (access/export + erasure) | done | `admin.EraseDevice/AuthorizeExport`, `adminread.ExportDevice` | unit + live demo |
| Health/readiness endpoints (`/healthz`, `/readyz`) | done | `adminapi` + `Store.Ping` | unit + smoke |
| Event detail (structured JSON) + server-side filtering | done | `adminread`, `grpc` | unit + live demo |
| Device OFFLINE automation (stale heartbeat) | done | `db/status.go`, `memstore` | unit |
| Web admin console (SOC dashboard, live refresh) | done | `adminapi/console.html` (embed) | httptest + live demo |
| Read API + visibility | done | `server/internal/adminread` | unit |
| Retention automation | logic / DB compiled | `server/internal/retention` | unit |
| Behavioral anomaly detection + trained-model inference | Phase 1-3 | `agent/internal/anomaly` + `enforce` | unit |
| Tamper-evident audit log (hash-chain, SEC C-1) | done | `security.AuditChainHash`, memstore+db | unit |
| Admin 2FA/MFA (TOTP, RFC 6238) + at-rest encrypted secret | done | `security.totp`, `admin`, `db/mfa.go` | unit (RFC vectors) + httptest |
| Prometheus `/metrics` (token-gated, dependency-free) | done | `server/internal/metrics`, `adminapi` | unit + httptest |
| SOC real-time alerting (HTTPS webhook, severity threshold) | done | `server/internal/notify`, `grpc` | unit (TLS httptest) |
| MITRE ATT&CK technique mapping + coverage endpoint | done | `server/internal/mitre`, `grpc`, `adminapi` | unit + httptest |
| mTLS server SPKI pinning (optional, rotation) | done | `agent/internal/transport/pin.go` | unit + openssl cross-check |
| Auto-response/SOAR (auto-quarantine on critical event) | optional | `server/internal/response`, `grpc` | unit |
| Server-side detection engine (Sigma-like rules) | done | `server/internal/detect`, `grpc`, `adminapi` | unit + httptest |
| Device tagging/grouping (fleet management + filter) | done | `admin`, `db`, `adminapi`, `console` | unit + httptest |
| Structured event Details (network/enforce/anomaly -> structpb) | done | `agent` (enforce, main) | unit |
| Threat intelligence (IoC) matching (IP/MAC/domain/hash) | optional | `server/internal/ioc`, `grpc` | unit |
| Process lineage enrichment (parent chain) | Win/Linux | `agent/internal/enforce` | unit (chain + stat parsing) |
| Disk-encryption compliance report (BitLocker/LUKS) | logic/OS-compiled | `agent/internal/compliance` | unit (parsers) |
| Detection rule tester / dry-run (/api/detections/test) | done | `adminapi`, `detect`, console | unit + smoke + live |
| MITRE ATT&CK coverage-gap analysis + JSON export | done | `adminapi/console.html` | live |
| Console click-to-filter chips for events/audit (keyboard-accessible) | done | `adminapi/console.html` | live |
| Event device attribution (device_id) + top devices by alert volume | done | `adminread`, `db`, `memstore`, console | unit + smoke + live |
| Device status quick-filter (online/offline/quarantine) | done | `adminapi/console.html` | live |
| Compliance checks: disk encryption + firewall (agent) | done | `agent/compliance` | unit + smoke + live |
| Fleet compliance visibility: card + device-detail + non-compliant KPI + CSV | done | `adminread`, console | unit + live |
| Server-side compliance summary (accurate fleet KPI, /api/summary) | done | `adminread`, `db`, `memstore` | unit + smoke |
| Hardening: 1 MiB request-body limit (DoS) | done | `adminapi` | unit |
| Hardening: admin HTTP timeouts (slowloris) | done | c2 main | smoke (SSE preserved) |
| Encrypted PostgreSQL schema | done | `db/schema.sql` | - |
| Rich process-execution telemetry (command line + lineage) | done Win/Linux | `agent/internal/enforce`, `monitor` | unit |
| Detection engine v2 (regex/field/threshold rules) | done | `server/internal/detect` | unit + smoke |
| Network connection telemetry (listening/established) | done Win/Linux | `agent/internal/netconn`, grpc, db | unit |
| On-demand file/artifact collection (forensics/IR) | done | `admin.CollectFile`, `grpc.UploadArtifact`, `artifacts` table | unit + live |
| Vulnerability mapping from inventory (CVE) | done optional | `server/internal/vuln`, `adminread`, console | unit + smoke |
| MDM remote actions: LOCK/RESTART (real) + WIPE (real crypto-erase, 3-layer guard) | done Win/Linux | `admin`, `agent/internal/deviceaction`, proto | unit (arm gate) + smoke |
| USB/removable-media control: audit + real block (dismount/eject) | done Win/Linux | `agent/internal/usbmon` | unit (safe-mode gate) |
| SIEM forwarder (syslog + CEF/LEEF) | done optional | `server/internal/notify/siem.go`, c2 main | unit |
| Case/incident management (assignee + note, audited) | done | `admin.UpdateEventCase`, `adminread`, `db`, `memstore`, console | unit + smoke + live |
| Horizontal scale / HA (multi-node SSE fan-out) | done optional | `server/internal/cluster` (Postgres LISTEN/NOTIFY), `eventbus`, `db` | unit + smoke (real pg_notify) |
| IoC threat-intel live hot-reload (no restart) | done optional | `grpc` (atomic.Pointer), `ioc`, c2 main | unit + live (real server) |
| Detection-rule live hot-reload (no restart) | done optional | `grpc`+`adminapi` (atomic.Pointer), `detect`, c2 main | unit + live (real server) |
| Artifact retention pruning (forensic files, prevents unbounded growth) | done | `retention`, `db`, `memstore` | unit + smoke |
| Local CI-parity gate (make check/check-all) + CI -race | done | Makefile, `.github/workflows/ci.yml` | CI (concurrency race detector) |
| Dual-control (four-eyes) WIPE approval (optional) | done | `admin`, `adminapi`, `db`, `memstore`, console | unit + HTTP + live |
| Real destructive MDM enforcement (WIPE crypto-erase + USB block, 3-layer guard) | done Win/Linux | `agent/internal/deviceaction`+`usbmon`, agent main | unit (guard gates) |
| Retro-hunt + SIEM historical event search | done | `adminread`+`adminapi` (QueryEvents), db, console | unit + HTTP + smoke |
| Alert correlation + auto-incident grouping | done | `server/internal/correlate`, grpc, db, console | unit + smoke |
| File Integrity Monitoring (FIM) — agent | done | `agent/internal/fim` (SHA-256), agent main | unit |
| Agent self-attestation (swapped/patched binary detection) | done | proto, `grpc`, `db`, `memstore`, agent | unit (tamper detection) |

## V2 capabilities (2026-09 additions)

Added after the initial matrix; all tests + smoke + CI green.

- **SOC intelligence:** multi-factor **risk scoring** (`/api/risk`), **attack story**
  (kill-chain, `/api/devices/{id}/attack-story`), **entity graph** (`/graph`), **incident
  timeline**, **MTTD/MTTR** trends (`/api/metrics/trends`), **UEBA** (admin behavior
  analytics, `/api/ueba/admins`), compliance-framework mapping (**CIS/NIST/ISO/KVKK**,
  `/api/compliance/frameworks`).
- **Detection:** multi-signal **correlation** (high-confidence chain), **lateral movement**
  (netconn fan-out, T1046), **DNS tunneling** (T1071.004), improved **DGA** (consonant-run),
  **Sigma import**, **YARA-style content scanning**, Detection-as-Code lifecycle, expanded
  MITRE catalog + 14 built-in rules.
- **Signed content (tamper-resistant):** ALL loadable content (YARA, detection rules, IoC,
  anomaly model, OTA, offline offboard, audit export) is Ed25519-signable.
- **Alerting & delivery:** notification **routing + escalation**, **webhook HMAC signing**,
  continuous **threat hunting** (saved searches), scheduled **report webhook delivery**,
  server-side detections wired into the SOC alert path.
- **Ingest (SIEM):** JSON + **CEF** + **LEEF** (QRadar) inbound; rate limiting.
- **Ops/resilience:** **certificate-expiry monitoring** (log + `/api/features` + metric),
  **brute-force lockout signal**, expanded Prometheus metrics + ready-made **alert rules**
  (`deploy/prometheus-alerts.example.yml`), request correlation IDs + access logs.
- **Platform:** multi-tenancy foundation (identity + output attribution), canonical event
  schema version.
- **Supply-chain security (CI):** `govulncheck` + **fuzzing** + **SBOM** + gosec (fixed 4
  real CVEs); deployment hardening (`deploy/HARDENING.md`).

## Initial review findings - responses

See `docs/threat-model.md`. Summary: broken schema fixed, at-rest + partitioning
instead of encrypted-log; **HMAC blind index** instead of plain hash; **server-clock
anchor** instead of local time; **signature** instead of hash for OTA; enrollment/PKI
added; RBAC + immutable audit log.

**Findings caught in the agent security audit (fixed):** An adversarial security
review found two HIGH issues: **SEC-001** console XSS (`esc()` did not HTML-escape)
and **SEC-002** certificate-revocation bypass (`Renew` did not check revocation).
Both fixed + regression tests. Remaining medium/low recommendations (SPKI pinning;
session revocation/MFA/audit-log & anomaly-model signing) are now implemented.

**Finding caught in CI (Linux) (fixed):** `policy.matchesTarget` used
`filepath.Base` - on Linux the `\` separator is not split, so Windows-path processes
did not match by filename on Linux and tests failed only in CI. Fixed with an
OS-independent `baseName`; regression test `TestMatchesTargetSeparatorAgnostic`.

**Finding caught during the live demo (fixed):** the in-memory `LookupAdmin` did not
filter by `is_active` -> a deactivated admin could still log in. Memstore was aligned
to the (already-correct) PostgreSQL path + regression test.

## Deliberately out of scope / not live-verified

- **Kernel-level tamper protection** (MiniFilter driver + PPL/ELAM): C/C++, EV
  certificate, WHQL/attestation signing, BSOD risk - a very high-cost **separate
  project**. Watchdog + liveness are only a **first line of defense**.
- **Not run live** (logic tested, not executed in this environment):
  - Real firewall isolation (`netsh`/`iptables`) - cuts the network, risky.
  - Real process **termination** - fake controller in tests.
  - Linux `/proc`+SIGKILL and OS isolators - cross-compile only.
  - `go test -race` - no C compiler (gcc); concurrency correct-by-construction.
  - Note: the PostgreSQL path IS live-verified in CI against the `postgres:16` service.
- **ML anomaly pipeline:** Phase 1-3 DONE (pure-Go statistical + JSON-trained-model
  inference). Real `.onnx` loading (onnxruntime CGo) is interface-ready but does not
  compile here (a C dependency would break the pure-Go CI).

## Running

```bash
make proto && go mod tidy && go test ./...   # generate + test
make dev-certs                                # dev certificates + env suggestion
go run ./tools/otasign -genkey -out ./ota-keys
go run ./tools/adminseed -email a@x -password '...' -role ADMIN
# load db/schema.sql, set XEMS_* env, run bin/c2 and bin/agent
# admin console: https://localhost:8445/
```

## Tools

- `tools/gencerts` - dev/prod CA + server certificate.
- `tools/otasign` - OTA signing key generation + release signing (+ SQL).
- `tools/adminseed` - admin password (Argon2id) + INSERT SQL.
- `tools/anomalytrain` - trains a logistic anomaly model from a labeled CSV.
- `tools/mkclient` - SINGLE-FILE client installer generator (Win/Linux).
- `tools/logcheck` - offline external-log ingest validation CLI.
- `tools/onnx2json` - offline ONNX -> anomaly-model JSON converter (pure Go).
- `tools/mkicon` - pure-Go app-icon generator (.ico + embedded `*_windows_amd64.syso`
  PE resource) from `assets/xems-logo.png`; see `docs/BRANDING.md`.

## Deployment / packaging - done

- `scripts/build-release.sh` - cross-compilation of c2/agent/watchdog/gencerts.
- **GitHub Releases:** `.github/workflows/release.yml` - on a `v*` tag, cross-compiles,
  packages (zip/tar.gz), emits `SHA256SUMS` (+ optional GPG `SHA256SUMS.asc`), and
  publishes the release. Verification steps in README ("Release verification").
- **Server install:** `deploy/server/install-linux.sh` (systemd),
  `install-windows.ps1` (scheduled task) - PKI + master key + config + service.
- **Client install:** the single-file installer produced by `mkclient`.
- Details: `deploy/README.md`.

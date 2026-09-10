# XEMS Security Suite — Kurumsal Uç Nokta Güvenliği ve Ajan Yönetim Sistemi
# XEMS Security Suite — Corporate Endpoint Security & Agent Management System

[![CI](https://github.com/cihanuralkaya/XEMS-Security-Suit/actions/workflows/ci.yml/badge.svg)](https://github.com/cihanuralkaya/XEMS-Security-Suit/actions/workflows/ci.yml)

**Türkçe** · [English](#english)

> **🇬🇧 EN —** Endpoint security & management platform (EDR/XDR + MDM) for authorized
> corporate environments. Single language **Go**; agent ↔ C2 over **gRPC + mTLS**
> (TLS 1.3). Feature-complete, CI green, deployment-ready. **Full English docs
> below → [English](#english).**
>
> **🇹🇷 TR —** Yetkili kurumsal ortamlar için uç nokta güvenlik ve yönetim platformu
> (EDR/XDR + MDM). Tek dil **Go**; ajan ↔ C2 **gRPC + mTLS** (TLS 1.3). Özellik-tam,
> CI yeşil, dağıtıma hazır.

---

Yetkili kurumsal ortam için (şirkete ait cihazlar, bildirilmiş kullanım
politikası, IT yönetimi) tasarlanmış uç nokta güvenlik ve yönetim platformu.
Tek dil: **Go**. Ajan ↔ C2 iletişimi **gRPC + mTLS** (TLS 1.3).

> **Durum: özellik-tam, CI yeşil, dağıtıma hazır.** Ayrıntılı yetenek matrisi ve
> ne-nasıl-doğrulandı için **[docs/STATUS.md](docs/STATUS.md)**.
>
> - **189 test / 36 paket** geçiyor; **CI** (`.github/workflows/ci.yml`) her push'ta
>   `go vet` + test + **uçtan uca smoke** + **gerçek PostgreSQL'e karşı DB testi** +
>   çapraz derleme çalıştırır — hepsi yeşil.
> - Uçtan uca kanıtlı zincir: enroll (PKI) → mTLS heartbeat (sunucu-saati) → olay →
>   politika push → OTA imza + rollout → komut teslimi → tek-kullanımlık token
>   (`server/internal/e2e`, `make e2e`).
> - **Güvenlik:** HMAC blind index, AES-256-GCM alan şifreleme, Argon2id parola,
>   Ed25519 OTA/script imzası, RBAC + değişmez (hash-zincirli) denetim izi, giriş
>   kaba-kuvvet koruması, admin 2FA (TOTP), mTLS sunucu SPKI pinning, sıkılaştırılmış
>   güvenlik başlıkları (HSTS/CSP nonce).
> - **Tespit & müdahale:** MITRE ATT&CK eşleme, sunucu-taraflı tespit kuralları
>   (Sigma-benzeri) + **Detection-as-Code** yaşam-döngüsü + **Sigma içe aktarma**,
>   saf-Go **YARA-tarzı içerik tarama** (imzalı kurallar), IoC tehdit istihbaratı
>   (güven/kaynak), davranışsal anomali, C2 beacon tespiti, SOAR otomatik-karantina,
>   SOC webhook uyarı (**yönlendirme + yükseltme + HMAC imza**), SIEM (CEF/LEEF),
>   Prometheus `/metrics`.
> - **SOC istihbaratı:** çok-sinyal **korelasyon** (yüksek-güven saldırı zinciri),
>   çok-faktörlü **risk skorlama**, **saldırı hikâyesi** (kill-chain), **varlık grafı**,
>   **incident zaman çizelgesi**, **MTTD/MTTR** trendleri, **UEBA** (ayrıcalıklı-kullanıcı
>   davranış analitiği), uyum çerçevesi eşleme (**CIS/NIST/ISO 27001/KVKK**), bakım/
>   bastırma pencereleri.
> - **Tedarik zinciri güvenliği (CI):** `govulncheck` (bağımlılık CVE), **fuzzing**
>   (kritik ayrıştırıcılar), **SBOM** (CycloneDX), gosec; hız sınırlama, kurcalama-
>   kanıtlı imzalı denetim dışa aktarımı, imzalı çevrimdışı offboard, çok-kiracılı
>   çıktı atıfı.
> - **KVKK:** at-rest şifreleme + partition-bazlı saklama; **veri sahibi hakları**
>   (erişim/dışa aktarma + silme, denetim korunur).
> - **Konsol:** gömülü tek-sayfa SOC paneli — cihazlar/olaylar/politikalar/yöneticiler,
>   cihaz etiketleme, **canlı SSE push**, önem grafiği, arama, CSV dışa aktarma,
>   sağlık uçları (`/healthz`, `/readyz`).
> - **Dağıtım:** çapraz derleme + tek-dosya istemci installer üreteci (token gömülü
>   veya kod girişli, Win/Linux) + sunucu kurulum betikleri — bkz.
>   **[deploy/README.md](deploy/README.md)**.
> - Üçüncü taraf lisanslar (telif uyumu): **[docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md)**
>   (hepsi izin verici; copyleft yok).

## Bileşenler

| Bileşen | Dizin | Rol |
|---|---|---|
| C2 sunucusu | `server/` | Log toplama, politika dağıtımı, OTA, enrollment/PKI |
| Uç nokta ajanı | `agent/` | Politika uygulama, olay toplama, ağ keşfi |
| Watchdog | `agent/cmd/watchdog` + `internal/watchdog` | Ajanı canlı tutar + OTA swap/rollback (ilk savunma) |
| Proto sözleşmeleri | `proto/xems/v1` | gRPC servis + mesaj tanımları |
| Veritabanı | `db/` | Düzeltilmiş PostgreSQL şeması + migration'lar |
| Dokümantasyon | `docs/` | Mimari, tehdit modeli, KVKK notları |

## Gereksinimler (geliştirme)

- Go 1.23+
- [buf](https://buf.build) (proto üretimi) veya protoc + eklentiler
- PostgreSQL 14+ (`uuid-ossp`, `pgcrypto` eklentileri)

## Hızlı başlangıç

```bash
# 1) Proto kodunu üret
make proto

# 2) Bağımlılıkları düzenle
make tidy

# 3) İkilileri derle
make build        # bin/c2, bin/agent, bin/watchdog

# 4) Veritabanı şemasını kur
psql -U postgres -d xems -f db/schema.sql
```

## Kurulum ve dağıtım ✅

Tam akış: **[deploy/README.md](deploy/README.md)**.

- **Release:** `scripts/build-release.sh 1.0.0` — c2/agent/watchdog/gencerts
  Windows+Linux için çapraz derlenir (`dist/`).
- **Sunucu (C2):** `deploy/server/install-linux.sh` (systemd) /
  `install-windows.ps1` (zamanlanmış görev) — PKI + ana anahtar + config + servis
  otomatik.
- **İstemci (agent):** `tools/mkclient` her cihaz için **tek-dosya** kurulum betiği
  üretir — **benzersiz** (enrollment token gömülü, otomatik kaydolur) veya
  **paylaşımlı** (kod girişli); ajan ikilisi base64 gömülü, servisi kurar.
  Windows (`.ps1`) + Linux (`.sh`).

## Yapılandırma (ortam değişkenleri)

Tüm ayarlar ortam değişkenleriyle yapılır. Tam liste + açıklama:
**[deploy/server/c2.env.example](deploy/server/c2.env.example)** (sunucu) ve
**[deploy/agent.env.example](deploy/agent.env.example)** (ajan).

- **Zorunlu (sunucu):** `XEMS_MASTER_KEY` (32 bayt base64), TLS yolları
  (`XEMS_CA_CERT`/`XEMS_CA_KEY`/`XEMS_SERVER_CERT`/`XEMS_SERVER_KEY`); üretim için
  `XEMS_DATABASE_URL` (boşsa `XEMS_DEMO=1` ile bellek-içi demo).
- **Opsiyonel korumalar (sunucu):** `XEMS_ALERT_WEBHOOK_URL`/`XEMS_ALERT_FORMAT`
  (SOC uyarı, Slack/Teams), `XEMS_AUTO_RESPONSE` (SOAR oto-karantina), `XEMS_IOC_FILE`
  (tehdit istihbaratı), `XEMS_DETECT_RULES_FILE` (özel tespit kuralları),
  `XEMS_METRICS_TOKEN` (Prometheus), `XEMS_LOG_FORMAT=json` (SIEM).
- **Ajan:** bağlantı (`XEMS_ENROLL_ADDR`/`XEMS_AGENT_ADDR`/`XEMS_SERVER_NAME`/`XEMS_CA_PEM`),
  `XEMS_SERVER_SPKI_PIN` (pinning), `XEMS_UPDATE_PUBKEY`/`XEMS_SCRIPT_PUBKEY` (imza),
  `XEMS_ANOMALY_*`, `XEMS_SAFE_MODE`, `XEMS_LOG_FORMAT`.

Etkin korumaları konsoldan (Yönetim → **Koruma Katmanları**) veya `GET /api/features`
ile görebilirsiniz.

## Yol haritası

Bkz. [docs/architecture.md](docs/architecture.md) — fazlara bölünmüş plan.
İnceleme bulguları ve karşılığında alınan kararlar [docs/threat-model.md](docs/threat-model.md)
içinde.

---

# English

Endpoint security and management platform designed for authorized corporate
environments (company-owned devices, a notified usage policy, IT management).
Single language: **Go**. Agent ↔ C2 communication over **gRPC + mTLS** (TLS 1.3).

> **Status: feature-complete, CI green, deployment-ready.** For the detailed
> capability matrix and what-was-verified-how, see **[docs/STATUS.md](docs/STATUS.md)**.
>
> - **189 tests / 36 packages** pass; **CI** (`.github/workflows/ci.yml`) runs
>   `go vet` + tests + **end-to-end smoke** + **DB test against a real PostgreSQL** +
>   cross-compilation on every push — all green.
> - End-to-end proven chain: enroll (PKI) → mTLS heartbeat (server-clock) → event →
>   policy push → OTA signature + rollout → command delivery → single-use token
>   (`server/internal/e2e`, `make e2e`).
> - **Security:** HMAC blind index, AES-256-GCM field encryption, Argon2id passwords,
>   Ed25519 OTA/script signing, RBAC + immutable (hash-chained) audit log, login
>   brute-force protection, admin 2FA (TOTP), mTLS server SPKI pinning, hardened
>   security headers (HSTS/CSP nonce).
> - **Detection & response:** MITRE ATT&CK mapping, server-side detection rules
>   (Sigma-like) + **Detection-as-Code** lifecycle + **Sigma import**, pure-Go
>   **YARA-style content scanning** (signed rules), IoC threat intelligence
>   (confidence/source), behavioral anomaly detection, C2 beacon detection, SOAR
>   auto-quarantine, SOC webhook alerting (**routing + escalation + HMAC signing**),
>   SIEM (CEF/LEEF), Prometheus `/metrics`.
> - **SOC intelligence:** multi-signal **correlation** (high-confidence attack chains),
>   multi-factor **risk scoring**, **attack story** (kill-chain), **entity graph**,
>   **incident timeline**, **MTTD/MTTR** trends, **UEBA** (privileged-user behavior
>   analytics), compliance-framework mapping (**CIS/NIST/ISO 27001/KVKK**), maintenance/
>   suppression windows.
> - **Supply-chain security (CI):** `govulncheck` (dependency CVEs), **fuzzing**
>   (critical parsers), **SBOM** (CycloneDX), gosec; rate limiting, tamper-evident
>   signed audit export, signed offline offboarding, multi-tenant output attribution.
> - **Data protection (KVKK/GDPR-style):** at-rest encryption + partition-based
>   retention; **data-subject rights** (access/export + erasure, audit preserved).
> - **Console:** embedded single-page SOC dashboard — devices/events/policies/admins,
>   device tagging, **live SSE push**, severity chart, search, CSV export, health
>   endpoints (`/healthz`, `/readyz`).
> - **Deployment:** cross-compilation + single-file client installer generator (token
>   embedded or code-entry, Win/Linux) + server install scripts — see
>   **[deploy/README.md](deploy/README.md)**.
> - Third-party licenses (copyright compliance): **[docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md)**
>   (all permissive; no copyleft).

## Components

| Component | Directory | Role |
|---|---|---|
| C2 server | `server/` | Log collection, policy distribution, OTA, enrollment/PKI |
| Endpoint agent | `agent/` | Policy enforcement, event collection, network discovery |
| Watchdog | `agent/cmd/watchdog` + `internal/watchdog` | Keeps the agent alive + OTA swap/rollback (first line of defense) |
| Proto contracts | `proto/xems/v1` | gRPC service + message definitions |
| Database | `db/` | Corrected PostgreSQL schema + migrations |
| Documentation | `docs/` | Architecture, threat model, data-protection notes |

## Requirements (development)

- Go 1.23+
- [buf](https://buf.build) (proto generation) or protoc + plugins
- PostgreSQL 14+ (`uuid-ossp`, `pgcrypto` extensions)

## Quick start

```bash
# 1) Generate proto code
make proto

# 2) Tidy dependencies
make tidy

# 3) Build the binaries
make build        # bin/c2, bin/agent, bin/watchdog

# 4) Install the database schema
psql -U postgres -d xems -f db/schema.sql
```

## Installation & deployment ✅

Full flow: **[deploy/README.md](deploy/README.md)**.

- **Release:** `scripts/build-release.sh 1.0.0` — c2/agent/watchdog/gencerts
  cross-compiled for Windows+Linux (`dist/`).
- **Server (C2):** `deploy/server/install-linux.sh` (systemd) /
  `install-windows.ps1` (scheduled task) — PKI + master key + config + service
  set up automatically.
- **Client (agent):** `tools/mkclient` produces a **single-file** installer per
  device — **unique** (enrollment token embedded, auto-enrolls) or **shared**
  (code-entry); the agent binary is base64-embedded and installs the service.
  Windows (`.ps1`) + Linux (`.sh`).

## Configuration (environment variables)

All settings are via environment variables. Full list + descriptions:
**[deploy/server/c2.env.example](deploy/server/c2.env.example)** (server) and
**[deploy/agent.env.example](deploy/agent.env.example)** (agent).

- **Required (server):** `XEMS_MASTER_KEY` (32-byte base64), TLS paths
  (`XEMS_CA_CERT`/`XEMS_CA_KEY`/`XEMS_SERVER_CERT`/`XEMS_SERVER_KEY`); for production
  `XEMS_DATABASE_URL` (if empty, in-memory demo with `XEMS_DEMO=1`).
- **Optional protections (server):** `XEMS_ALERT_WEBHOOK_URL`/`XEMS_ALERT_FORMAT`
  (SOC alerting, Slack/Teams), `XEMS_AUTO_RESPONSE` (SOAR auto-quarantine),
  `XEMS_IOC_FILE` (threat intel), `XEMS_DETECT_RULES_FILE` (custom detection rules),
  `XEMS_METRICS_TOKEN` (Prometheus), `XEMS_LOG_FORMAT=json` (SIEM).
- **Agent:** connection (`XEMS_ENROLL_ADDR`/`XEMS_AGENT_ADDR`/`XEMS_SERVER_NAME`/`XEMS_CA_PEM`),
  `XEMS_SERVER_SPKI_PIN` (pinning), `XEMS_UPDATE_PUBKEY`/`XEMS_SCRIPT_PUBKEY` (signing),
  `XEMS_ANOMALY_*`, `XEMS_SAFE_MODE`, `XEMS_LOG_FORMAT`.

You can see which protections are enabled from the console (Management → **Protection
Layers**) or via `GET /api/features`.

## Roadmap

See [docs/architecture.md](docs/architecture.md) — a phased plan. Review findings
and the decisions taken in response are in [docs/threat-model.md](docs/threat-model.md).

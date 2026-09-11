# XEMS V2 Roadmap — Uygulanabilirlik ve Boşluk Analizi (Gap Analysis)

> Kaynak: `SOC.txt` (V2 Development Roadmap). Bu belge, roadmap'teki her başlığı
> **mevcut kod tabanıyla** karşılaştırır ve uygulanabilirliğini değerlendirir.
> Analiz tarihi: 2026-09-11. Değerlendirme kanıta dayalıdır (paket/uç referanslı).

## Durum lejantı

| Simge | Anlam |
|-------|-------|
| ✅ **VAR** | Roadmap'in istediği yetenek uygulanmış (üretim düzeyinde). |
| 🟡 **KISMİ** | Temel mevcut ama roadmap derinliğinin altında; artırımlı genişletilmeli. |
| ⬜ **YOK** | Net-yeni; kod tabanında yok. |

**Uygulanabilirlik**: roadmap'in temel ilkesi (mevcut Go + gRPC + mTLS + PostgreSQL
mimarisini koru, artırımlı ekle) sayesinde başlıkların **neredeyse tamamı saf-Go ve
mevcut mimariye uyumludur**. Risk taşıyanlar ayrıca işaretlenmiştir (dış bağımlılık,
altyapı, kod-imzalama/sertifika, güvenlik yüzeyi).

---

## Özet tablo (skor)

| Öncelik | ✅ VAR | 🟡 KISMİ | ⬜ YOK | Toplam |
|---------|:-----:|:-------:|:-----:|:------:|
| P0 (§4–14)  | 6 | 5 | 0 | 11 |
| P1 (§15–26) | 11 | 1 | 0 | 12 |
| P2 (§27–34) | 1 | 4 | 3 | 8 |
| P3 (§35–45) | 3 | 4 | 4 | 11 |
| **Toplam**  | **21** | **14** | **7** | **42** |

**Sonuç:** XEMS, roadmap'in **~%50'sini tam (21/42)**, **~%33'ünü kısmi (14/42)**
karşılıyor; gerçek net-yeni iş **~%17 (7/42)**.

> **Güncelleme (2026-09-11):** Bu oturumda üç başlık uygulandı: **§4 Merkezi Scope/ROE
> Guardrail** (`server/internal/scope` + admin servis kapısı), **§5 Canonical Event
> Model v1.1** (`event_id`/`source`/`event_type`/`correlation_id`/`parent_event_id`,
> migrasyonsuz) ve **§19 Event Replay** (`POST /api/detections/replay` — aday kuralı
> geçmişe uygula). P0'da açık boşluk kalmadı; P1 tamamlandı (11/12 VAR). Sıradaki:
> **§6 pipeline sağlamlığı** (DLQ/retry/duplicate/ordering).

---

## P0 — Kritik (production güvenliği + mimari temel)

| § | Başlık | Durum | Kanıt / mevcut | Boşluk & uygulanabilirlik |
|---|--------|:-----:|----------------|---------------------------|
| 4 | Central Scope / ROE / Guardrails | ✅ VAR | `server/internal/scope` (Engine.Authorize, fail-closed, excluded-wins, ROE action-gate, wildcard/CIDR selector) + admin servis kapısı (WIPE/QUARANTINE/LOCK/RESTART) + `XEMS_SCOPE_*` config + metrikler | **Bu oturumda uygulandı.** Yüksek-etkili her op enqueue'dan önce `guardScope`'tan geçer; enforce/denetim modları. Geriye uyumlu (motor bağlı değilse no-op). |
| 5 | Canonical Security Event Model | ✅ VAR | `model.Event` v1.1: `event_id` (içerik-adresli, EnsureID), `source`, `event_type`, `confidence`, `correlation_id`, `parent_event_id`, `tenant_id` + JSON şeması; `EventDTO` bunları details'ten yükseltir; logingest 5 formatta damgalar | **Bu oturumda uygulandı** (§4'ten sonra). Migrasyonsuz (details JSONB round-trip). Kalan minör: tipli `process/network/file/auth` alt-nesneleri hâlâ serbest details içinde. |
| 6 | Event Pipeline | 🟡 KISMİ | `eventbus` (sınırlı kanal + yavaş-abone atlama); collector→normalize→enrich→correlate→detect→store zinciri mevcut | Eksik: dead-letter (DLQ), retry, event-ordering garantisi, duplicate-detection, **replay**, schema-versioned pipeline. Saf-Go. |
| 7 | Concurrency & Performance | ✅ VAR | Go native goroutine/channel/context; job worker desenleri | Roadmap zaten "Go korunsun" diyor. Karşılanıyor. |
| 8 | Rate Limiting + Adaptive Backpressure | 🟡 KISMİ | `ratelimit.Limiter` (token-bucket, rate+burst) | Eksik: katmanlı limit (Global/Tenant/Agent/Target/API/TI) + adaptive 429/503→backoff→concurrency-azalt. Saf-Go. |
| 9 | PKI & Certificate Lifecycle | ✅ VAR | `enroll` + agent `certrenew` + `revocation` (CRL); enrollment→renewal→rotation→revocation | İyi durumda. Emergency-revocation/intermediate-CA envanteri 🟡 doğrulanmalı. |
| 10 | Agent Hardening | 🟡 KISMİ | `tamperprotect` (userland + çekirdek seam), `watchdog`, `standdown`, `enforce`, `quarantine` | Eksik: seccomp/AppArmor/SELinux, WDAC, EV code-signing (bkz. `docs/KERNEL-TAMPER.md` — sertifika kullanıcı aksiyonu). |
| 11 | OTA & Supply Chain | ✅ VAR | `ota` + `tools/otasign` (Ed25519) + CI SBOM + release SHA-256/GPG (`release.yml`) | İyi durumda. Anti-rollback / minimum-sürüm / staged-rollout (`rollout` paketi var) 🟡 genişletilebilir. |
| 12 | Security Regression & Fuzzing | ✅ VAR | Parser'larda `Fuzz*` testleri + CI "Güvenlik" işi (govulncheck + fuzz + SBOM) | Karşılanıyor. gosec/semgrep/CodeQL eklenebilir (§43). |
| 13 | Secrets & Config Security | 🟡 KISMİ | `config` (env/`XEMS_`), master-key base64 | Eksik: KMS/Vault/secret-manager entegrasyonu, imzalama/CA anahtarları için key-rotation. Arayüz saf-Go; sağlayıcı dış bağımlılık (opsiyonel). |
| 14 | Observability | 🟡 KISMİ | `metrics` (Prometheus `/metrics`), yapısal JSON log | Eksik: **distributed tracing** (OpenTelemetry) uçtan-uca (Agent→C2→pipeline→detection→SOAR). OTel dış bağımlılık — opt-in katman. |

---

## P1 — Yüksek (SOC/EDR/XDR operasyonel)

| § | Başlık | Durum | Kanıt / mevcut | Boşluk |
|---|--------|:-----:|----------------|--------|
| 15 | Attack Story | ✅ VAR | `adminread/attackstory.go` + kill-chain aşamalandırma; `/api/devices/{id}/attack-story` | Karşılanıyor. |
| 16 | Process / Entity Graph | ✅ VAR | `/api/devices/{id}/graph` varlık grafiği | Karşılanıyor. |
| 17 | Advanced Correlation Engine | ✅ VAR | `correlate` (Correlator + ChainDetector): temporal/entity/IOC/MITRE/risk | Karşılanıyor. |
| 18 | Threat Hunting | ✅ VAR | `adminapi.handleHunt` + `db/read` + `memstore`; `/api/hunt` alan-filtre + zaman aralığı | Saved-queries/aggregation/cross-device 🟡 genişletilebilir. |
| 19 | Event Replay | ✅ VAR | `adminread.ReplayDetections` + `POST /api/detections/replay`: aday kuralı zaman-pencereli geçmiş olaylara uygular, `by_rule` etki raporu döner (draft aday aktive edilir) | **Bu oturumda uygulandı** (§5 event_id üzerine). Salt-okuma; tarama 50k ile sınırlı. |
| 20 | Detection-as-Code | ✅ VAR | `sigma` + `/api/detections/rules`+`/test` + `detectsign` (imzalı kural) + lifecycle | Karşılanıyor (Sigma tabanlı, imzalı). |
| 21 | Risk Engine | ✅ VAR | `risk` (severity×exploitability×… incident/fleet risk) | Karşılanıyor; skorlama configurable 🟡. |
| 22 | Incident Timeline | ✅ VAR | Incident olayları + attack-story; `/api/incidents` | Karşılanıyor. |
| 23 | Evidence & Chain of Custody | 🟡 KISMİ | Artifact toplama (`/api/devices/*/artifacts`, `collect-file`) + hash-zincirli audit (`/api/audit/verify`) | Eksik: evidence başına collector/acquisition-method/access-audit metadata; SHA-256+immutability formalize. |
| 24 | SIEM / External Integration | ✅ VAR | `logingest` (CEF/LEEF/syslog/JSON in) + `auditexport` (out) + `notify` (webhook/Slack/Teams, HMAC) | Genel connector-abstraction 🟡 (bkz. §45). |
| 25 | Threat Intelligence Enrichment | ✅ VAR | `ioc` + IOC lifecycle | ASN/reputation/domain-enrichment 🟡. |
| 26 | Vulnerability Management | ✅ VAR | `vuln` + `/api/vulnerabilities` + `/api/software` (CVE/CVSS) | Karşılanıyor. |

---

## P2 — Stratejik (farklılaştırıcı)

| § | Başlık | Durum | Kanıt / mevcut | Boşluk & risk |
|---|--------|:-----:|----------------|---------------|
| 27 | AI SOC Assistant | ⬜ YOK | LLM entegrasyonu yok | **RISK:** dış LLM bağımlılığı + güvenlik. Sağlayıcı-bağımsız arayüz + zorunlu human-in-the-loop (AI yüksek-etkili aksiyon YAPMAZ). Öneri/özet katmanı olarak uygulanabilir. |
| 28 | UEBA | 🟡 KISMİ | `ueba` + `/api/ueba/admins` (baseline anomali) | Varlık kümesini (login/device/location/time/privilege) genişlet. Saf-Go. |
| 29 | XDR Connector Architecture | ⬜ YOK | `logingest` sadece inbound-normalize | Jenerik XDR connector çerçevesi (kaynak→Canonical Event) yok. Saf-Go, §45'e bağlı. |
| 30 | Cloud Security (AWS/Azure/GCP/M365) | ⬜ YOK | — | **RISK:** dış SDK + kimlik-bilgisi (secret-mgmt §13'e bağlı). Opt-in connector. |
| 31 | Advanced MDM / UEM | 🟡 KISMİ | `inventory`, `usbmon`, `dlp`, `deviceaction`, `compliance`, `quarantine` | Patch-status/config/encryption/app-control envanterini genişlet. |
| 32 | Compliance Engine | ✅ VAR | `complianceframework` + `/api/compliance/frameworks` (CIS/NIST/ISO/KVKK) | Karşılanıyor. |
| 33 | Advanced Reporting | 🟡 KISMİ | `report` (HTML/CSV/JSON) | Eksik: PDF, executive/technical/incident varyantları. |
| 34 | Dashboard / SOC UX | 🟡 KISMİ | Konsol + SSE canlı akış (`/api/stream`) | Nav genişletme (attack-graph/MITRE-coverage görünümleri) 🟡. |

---

## P3 — Enterprise (kurumsal / SaaS-MSP)

| § | Başlık | Durum | Kanıt / mevcut | Boşluk & risk |
|---|--------|:-----:|----------------|---------------|
| 35 | Enterprise Identity (OIDC/SAML/SSO/SCIM/ABAC) | 🟡 KISMİ | RBAC + MFA (`/api/mfa/*`) | Eksik: OIDC/SAML/SCIM/ABAC. **RISK:** dış IdP kütüphaneleri (dep). MFA/RBAC hazır temel. |
| 36 | Multi-Tenancy | ✅ VAR | `tenant` + `tenant_id` izolasyonu (app-level) | DB satır-düzeyi izolasyon denetimi 🟡 doğrulanmalı. |
| 37 | MSP Mode | ⬜ YOK | — | Tenant üstüne delegated-admin/global-SOC/per-tenant-billing. Saf-Go. |
| 38 | High Availability & Scalability | 🟡 KISMİ | `cluster/broker.go` | Eksik: leader-election/failover + benchmark (10k agent hedefi). |
| 39 | Event Storage Strategy | 🟡 KISMİ | PostgreSQL + `retention/plan` + `db/retention` | Eksik: hot/warm/cold + opsiyonel ClickHouse/OpenSearch. **Altyapı.** |
| 40 | Data Retention | ✅ VAR | `retention` + KVKK | Legal-hold / irreversible-delete-verification 🟡. |
| 41 | Chaos Testing | ⬜ YOK | — | Kontrollü failure harness (kill-C2/DB-drop/burst). Saf-Go test. |
| 42 | Developer Experience | ✅ VAR | Makefile (build/test/e2e/smoke/release/icons), dev-certs | `make docker` / tek-komut dev-env 🟡. |
| 43 | CI/CD Security Pipeline | 🟡 KISMİ | gofmt/vet/test/fuzz/govulncheck/SBOM/release-sign | Eksik gate'ler: gosec, semgrep, CodeQL, Trivy, secret-scan. |
| 44 | Detection Registry / Marketplace | ⬜ YOK | `sigmaimport` (kısmi adım) | Versiyonlu kural registry'si. Saf-Go. |
| 45 | Plugin / Connector Architecture | ⬜ YOK | — | Jenerik connector interface (core'u değiştirmeden). §24/§29 için temel. Saf-Go. |

---

## Uygulama sırası önerisi (mevcut duruma göre)

Roadmap'in kendi P0→P3 sırası geçerli; ancak **mevcut kod tabanı P1'in çoğunu zaten
karşıladığı için** en yüksek marjinal değer şu net-yeni işlerdedir:

1. ~~**§4 Scope/ROE Guardrail motoru**~~ — ✅ **TAMAMLANDI** (bu oturum): `server/internal/scope` + admin servis kapısı.
2. ~~**§5 Canonical Event alanları**~~ — ✅ **TAMAMLANDI** (bu oturum): `event_id`/`correlation_id`/`parent_event_id`/`source`/`event_type` (v1.1).
3. ~~**§19 Event Replay**~~ — ✅ **TAMAMLANDI** (bu oturum): `POST /api/detections/replay`.
4. **§6 Pipeline sağlamlığı** — DLQ/retry/duplicate-detection/ordering. **(Sıradaki artırım.)**
5. **§8 Katmanlı rate-limit + adaptive backpressure.**
6. **§14 OpenTelemetry tracing** (opt-in).
7. **§45 Plugin/connector interface** → §29/§30 XDR/Cloud'un önkoşulu.

**Risk taşıyan / dış-bağımlılık gerektiren** (izole, opt-in tutulmalı): §27 AI,
§30 Cloud, §35 OIDC/SAML, §39 ClickHouse/OpenSearch, §10 EV code-signing/WDAC.

---

## Kritik tasarım ilkeleri — mevcut uyum

Roadmap §53'teki 10 ilke zaten kod tabanının omurgasında: security-by-default,
least-privilege (agent audit modu, enforce), zero-trust (mTLS + agent verisi doğrulama),
defense-in-depth, human-in-the-loop (wipe-approve), immutable audit (hash-zincir),
backward-compat (proto + `EventSchemaVersion`), observability-first (metrics),
incremental-architecture, data-minimization (KVKK retention). Yeni işler bu
ilkelere bağlı kalmalıdır.

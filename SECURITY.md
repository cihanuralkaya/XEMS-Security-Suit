# Güvenlik Politikası / Security Policy

**Türkçe** · [English](#english)

XEMS Security Suite bir güvenlik ürünüdür; kendisi kritik bir saldırı yüzeyidir.
Güvenlik açıklarını sorumlu biçimde bildirmenizi önemsiyoruz.

## Desteklenen sürümler

`master` dalı aktif geliştirilir ve güvenlik düzeltmelerini alır. Etiketlenmiş
sürümler için en son minör sürüm desteklenir.

## Bir güvenlik açığını bildirme

- Lütfen açığı **herkese açık bir issue olarak AÇMAYIN.**
- Depo sahibine özel olarak ulaşın (GitHub üzerinden özel danışma / e-posta).
- Şunları ekleyin: etkilenen bileşen (c2/agent/watchdog), etki, yeniden üretme
  adımları ve varsa bir kavram-kanıtı.
- Makul bir açıklama takvimi (ör. düzeltme yayımlanana kadar) için koordinasyon
  yapılır.

## Kapsam ve mevcut sertleştirme

- Ajan ↔ C2 **mTLS (TLS 1.3)**; kısa-ömürlü istemci sertifikaları + oto-yenileme;
  sunucu **SPKI pinning** (opsiyonel).
- At-rest **AES-256-GCM alan şifreleme** + **HMAC blind index**; **Argon2id** parola.
- **Ed25519** imzalı OTA, script, offline-offboard, denetim dışa aktarımı.
- **RBAC** + **değişmez (hash-zincirli) denetim izi**; admin **2FA (TOTP)**;
  giriş kaba-kuvvet koruması + kilit sinyali.
- CI **tedarik zinciri güvenliği**: `govulncheck` (bağımlılık CVE), **fuzzing**,
  **SBOM** (CycloneDX), gosec.
- Dağıtım sertleştirme: [`deploy/HARDENING.md`](deploy/HARDENING.md)
  (systemd sandbox, Windows kod-imzalama/WDAC, sır yönetimi).

Bu depo yalnız **yetkili kurumsal savunma** kullanımı içindir (şirkete ait
cihazlar, bildirilmiş politika, IT yönetimi).

---

# English

XEMS Security Suite is a security product and is itself a critical attack surface.
We value responsible disclosure of vulnerabilities.

## Supported versions

The `master` branch is actively developed and receives security fixes. For tagged
releases, the latest minor version is supported.

## Reporting a vulnerability

- Please **do NOT open a public issue** for a vulnerability.
- Contact the repository owner privately (GitHub private advisory / email).
- Include: affected component (c2/agent/watchdog), impact, reproduction steps, and
  a proof-of-concept if available.
- We coordinate on a reasonable disclosure timeline (e.g., until a fix is released).

## Scope and existing hardening

- Agent ↔ C2 over **mTLS (TLS 1.3)**; short-lived client certs + auto-renewal;
  optional server **SPKI pinning**.
- At-rest **AES-256-GCM field encryption** + **HMAC blind index**; **Argon2id**
  passwords.
- **Ed25519**-signed OTA, scripts, offline offboarding, audit export.
- **RBAC** + **immutable (hash-chained) audit log**; admin **2FA (TOTP)**;
  login brute-force protection + lockout signal.
- CI **supply-chain security**: `govulncheck` (dependency CVEs), **fuzzing**,
  **SBOM** (CycloneDX), gosec.
- Deployment hardening: [`deploy/HARDENING.md`](deploy/HARDENING.md) (systemd
  sandbox, Windows code-signing/WDAC, secrets management).

This repository is intended for **authorized corporate defensive** use only
(company-owned devices, a notified policy, IT management).

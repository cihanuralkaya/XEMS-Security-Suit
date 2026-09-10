# Çekirdek-Seviye Kurcalama Koruması — Tasarım ve Durum

# Kernel-Level Tamper Protection — Design & Status

**Türkçe** · [English](#english)

Bu belge, XEMS ajanının kurcalamaya (tamper) karşı korunmasını iki katmanda tanımlar:
(1) BUGÜN sevk edilen **userland savunma-derinliği** ve (2) gerçek çekirdek-seviye
korumanın neden **ayrı bir C/C++ projesi** olduğu ile Go ajanının o sürücüyle arayüzü.

## Neden çekirdek sürücüsü ayrı bir projedir

Windows'ta gerçek kurcalama-koruması bir **MiniFilter dosya-sistemi filtre sürücüsü**
(süreç/dosya/registry korumasını çekirdekte uygular) ve/veya **PPL (Protected Process
Light) + ELAM (Early Launch Anti-Malware)** gerektirir. Bunlar:

- **C/C++ + WDK** ile yazılır (Go değil); çekirdek modunda çalışır.
- **EV kod-imzalama sertifikası** + Microsoft **WHQL/attestation imzalaması** ister
  (PPL/ELAM için ek Microsoft onayı).
- Hatalı sürücü **BSOD** (mavi ekran) riski taşır → ayrı QA/imzalama boru hattı.

Bu yüzden çekirdek sürücüsü, Go mono-deposunun **bilinçli olarak dışındadır** — ayrı,
yüksek-maliyetli bir alt-proje olarak ele alınır. Go ajanı onun yerini alamaz; yalnız
**tamamlayıcı** userland savunması ve sürücüyle bir arayüz sağlar.

## Bugün sevk edilen: userland savunma-derinliği

Ajan, çekirdek sürücüsü olmadan da "ilk savunma" katmanını uygular (hepsi test edilmiş):

| Savunma | Paket | Ne yapar |
|---|---|---|
| **Watchdog** | `agent/internal/watchdog` | Ayrı süreçle gözetim + ikili takas/rollback |
| **Çift-süreç canlılık** | `agent/internal/liveness` | Ajan ↔ watchdog karşılıklı beacon; biri ölürse diğeri yeniden başlatır |
| **Dosya bütünlüğü (FIM)** | `agent/internal/fim` | İzlenen dosyaların SHA-256 değişimini tespit eder |
| **Öz-tasdik** | ajan ikili SHA-256 (heartbeat) | Ajan ikilisinin takas/yama edilmesini sunucuda tespit |
| **İmzalı OTA** | `agent/internal/update` | Ed25519 imzalı güncelleme; sahte/bozuk güncelleme reddi (fail-closed) |

**Durum raporlama:** `agent/internal/tamperprotect` bu savunmaların hangilerinin aktif
olduğunu ve çekirdek sürücüsünün mevcut olup olmadığını değerlendirir (`Assess`) ve ajan
başlangıçta bir SECURITY olayı yayınlar: koruma seviyesi **none / userland / kernel**.
Böylece SOC, her uç noktanın gerçek koruma duruşunu görür.

## Çekirdek sürücüsü arayüzü (seam)

`tamperprotect.KernelDriverProbe()` (platforma özgü), gelecekteki XEMS MiniFilter
sürücüsünün (`xemsflt.sys`) varlığını yoklar. Bu depo sürücü **sevk etmez** → yoklama
`false` döner ve seviye `userland` olur. Sürücü ayrıca kurulursa (ayrı proje), yoklama
`true` döner ve duruş otomatik `kernel` seviyesine yükselir — Go tarafında kod değişikliği
gerekmez. Sürücünün ajana sağlayacağı korumalar (tasarım):

- Ajan sürecinin (ve watchdog'un) **sonlandırılmasını/askıya alınmasını engelleme** (PPL).
- Ajan ikilisi, yapılandırması ve registry anahtarlarının **yazma korumasını** çekirdekte.
- Kurcalama girişimlerini ajana **olay olarak** iletme (ETW/port).

## Yol haritası

Gerçek sürücü, EV sertifikası + WHQL boru hattı + adanmış BSOD-QA gerektirdiğinden bir
ürün/altyapı kararıdır. Userland katmanı, o karara kadar birincil savunmadır ve sürücü
geldiğinde onu **tamamlar** (yerine geçmez).

---

<a name="english"></a>

# Kernel-Level Tamper Protection — Design & Status (English)

This document describes XEMS agent tamper protection in two layers: (1) the **userland
defense-in-depth** shipped today, and (2) why real kernel-level protection is a **separate
C/C++ project**, plus the Go agent's interface to that driver.

## Why the kernel driver is a separate project

Real tamper protection on Windows requires a **MiniFilter file-system filter driver**
(enforcing process/file/registry protection in the kernel) and/or **PPL + ELAM**. These are
written in **C/C++ with the WDK** (not Go), run in kernel mode, require an **EV code-signing
certificate** plus Microsoft **WHQL/attestation signing** (and extra Microsoft approval for
PPL/ELAM), and carry **BSOD** risk from a faulty driver — demanding a separate QA/signing
pipeline. So the kernel driver is **deliberately out of** the Go monorepo, treated as a
separate high-cost sub-project. The Go agent cannot replace it — it provides complementary
userland defense and an interface to the driver.

## Shipped today: userland defense-in-depth

Even without the kernel driver, the agent implements a "first defense" layer (all tested):
watchdog (`agent/internal/watchdog`, supervision + binary swap/rollback), dual-process
liveness (`agent/internal/liveness`, agent ↔ watchdog mutual beacons with restart), file
integrity (`agent/internal/fim`, SHA-256), self-attestation (agent binary SHA-256 in the
heartbeat, so swap/patch is detected server-side), and signed OTA
(`agent/internal/update`, fail-closed Ed25519). `agent/internal/tamperprotect` assesses
which of these are active plus whether the kernel driver is present, and the agent emits a
startup SECURITY event reporting the protection level — **none / userland / kernel** — so
the SOC sees each endpoint's real posture.

## Kernel driver interface (seam)

`tamperprotect.KernelDriverProbe()` (platform-specific) probes for the future XEMS
MiniFilter driver (`xemsflt.sys`). This repo ships **no** driver → the probe returns
`false` and the level is `userland`. If the driver is later installed (separate project),
the probe returns `true` and the posture automatically escalates to `kernel` with **no Go
code change**. The driver's intended protections: block termination/suspension of the agent
and watchdog (PPL); kernel-enforced write protection of the agent binary, config, and
registry keys; and delivery of tamper attempts to the agent as events (ETW/port).

## Roadmap

The real driver requires an EV certificate + WHQL pipeline + dedicated BSOD-QA, so it is a
product/infrastructure decision. The userland layer is the primary defense until then and
**complements** (does not replace) the driver when it arrives.

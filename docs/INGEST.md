# Harici Log Alımı — Entegrasyon Kılavuzu

# External Log Ingest — Integration Guide

**Türkçe** · [English](#english)

XEMS, uç-nokta ajan telemetrisinin yanı sıra HARİCİ kaynaklardan (güvenlik duvarı,
bulut, kimlik sağlayıcı, başka SIEM, Windows olay günlüğü) log alabilir ve bunları
tek bir korelasyon/tespit/hunt yüzeyinde toplar. Bu belge alım uç noktasını, desteklenen
biçimleri ve yaygın log-shipper yapılandırmalarını özetler.

## Uç nokta

```
POST /api/ingest
Authorization: Bearer <XEMS_INGEST_TOKEN>
```

- Uç, yalnız `XEMS_INGEST_TOKEN` ayarlıysa AÇIKtır; aksi halde `404`. Token sabit-zaman
  karşılaştırılır. Güçlü, rastgele bir token kullanın.
- Hız sınırı: istemci IP başına token-bucket (`XEMS_INGEST_RATE_PER_SEC`, varsayılan 50,
  tavan 2×). Aşılırsa `429`.
- Gövde üst sınırı 4 MiB. Yanıt: `{"accepted": <n>, "sources": <m>}`.
- Her kaynak adı KARARLI bir cihaz kimliğine (UUIDv5) eşlenir — aynı kaynak her zaman
  aynı "cihaz" altında toplanır.

## Biçim yönlendirme

| İçerik | Yönlendirme | Kaynak | Önem |
|---|---|---|---|
| `Content-Type: application/json` (XEMS şeması) | `source`+`message` alanlı JSON dizi/nesne | `source` | `severity` alanı |
| `Content-Type: application/json` + `?format=winlog` **veya** gövdede `winlog`/`event_id` | Windows olay günlüğü | bilgisayar adı | EventID+kanal |
| satır `CEF:` içeriyor | CEF (ArcSight) | Vendor/Product | CEF 0-10 |
| satır `LEEF:` içeriyor | LEEF (QRadar) | Vendor/Product | `sev` özniteliği |
| satır `<` ile başlıyor | düz syslog (RFC5424/3164) | HOSTNAME/APP | `<PRI>` |
| diğer satırlar | CEF varsayılır | — | — |

Metin gövdeleri satır-başına ayrıştırılır; tanınmayan satırlar atlanır.

## Olay zamanı

Beş biçimin tümü olayın GERÇEK zaman damgasını kullanır (alım zamanını değil), böylece
saldırı hikâyesi ve zaman çizelgesi doğru sıralanır:

- JSON: `occurred_at` (RFC3339)
- Windows: `@timestamp` / `event.created` / TimeCreated `@SystemTime`
- syslog: RFC5424 TIMESTAMP alanı (RFC3164 yıl taşımaz → alım zamanı)
- CEF: `rt` uzantısı (epoch ms/sn ya da tarih)
- LEEF: `devTime` özniteliği

Zaman damgası yoksa/çözülemezse alım zamanına düşülür.

## Örnekler

### JSON (XEMS yerel şeması)

```bash
curl -sS -X POST https://c2.example.corp/api/ingest \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '[{"source":"fw-dc-1","category":"NETWORK_CONN","severity":"high",
        "message":"engellenen bağlantı","occurred_at":"2026-09-10T12:00:00Z",
        "details":{"src":"10.0.0.5","dst":"8.8.8.8"}}]'
```

`source` ve `message` zorunlu; geçersiz kategori/önem güvenli varsayılana (SYSTEM/INFO)
düşer.

### CEF (ArcSight) / LEEF (QRadar) / syslog

```
CEF:0|Palo Alto|PAN-OS|10.0|threat|Malware Blocked|9|src=10.0.0.5 rt=1767322845000
LEEF:2.0|Palo Alto|PAN-OS|10.2|threat|x09|sev=8	src=1.2.3.4	msg=malware	devTime=2026-09-10T12:00:00Z
<134>1 2026-09-10T12:00:00Z fw01 kernel 1234 ID47 - port scan detected
```

Metin gövdesini `Content-Type: text/plain` ile gönderin (satır-başına bir kayıt).

### Windows olay günlüğü

Windows güvenlik olayları EventID + kanala göre sınıflandırılır (ör. 4625 başarısız
oturum → MEDIUM, 1102 denetim günlüğü temizlendi → CRITICAL, 7045 hizmet kurulumu →
HIGH, Sysmon 8 CreateRemoteThread → HIGH). EventData'dan hedef hesap, kaynak IP ve oturum
türü çıkarılıp Details'e taşınır. Üç JSON şekli desteklenir: winlogbeat (iç içe `winlog`),
nxlog (düz) ve render-XML (`Event.System`).

## Log-shipper yapılandırmaları

**winlogbeat** (Windows olayları → XEMS):

```yaml
output.http:  # (community/http output)
  url: "https://c2.example.corp/api/ingest?format=winlog"
  headers:
    Authorization: "Bearer ${XEMS_INGEST_TOKEN}"
```

**nxlog** (`om_http`), **rsyslog** (`omhttp`), **fluent-bit** (`http` output) syslog/JSON
iletebilir. rsyslog örneği:

```
module(load="omhttp")
action(type="omhttp" server="c2.example.corp" restpath="api/ingest"
       httpheaderkey="Authorization" httpheadervalue="Bearer TOKEN")
```

## Alım verisinden beslenen tespitler

Alınan olaylar tüm sunucu-taraflı analizörleri besler: **kaba-kuvvet/parola-püskürtme**
(Windows 4625/4771 seri toplama → T1110), **başarılı kaba-kuvvet** (başarısız-seri ardından
başarılı oturum → hesap ele geçirme, CRITICAL), **beacon/yanal hareket/DNS-tüneli**, ve
**MITRE ATT&CK** kapsama matrisi + saldırı hikâyesi. Ayarlanabilir eşikler için
`deploy/server/c2.env.example` bakınız.

---

<a name="english"></a>

# External Log Ingest — Integration Guide (English)

Beyond endpoint agent telemetry, XEMS ingests logs from EXTERNAL sources (firewall,
cloud, identity provider, another SIEM, Windows Event Log) onto one correlation/detection/
hunt surface. This document summarizes the ingest endpoint, supported formats, and common
log-shipper configs.

## Endpoint

```
POST /api/ingest
Authorization: Bearer <XEMS_INGEST_TOKEN>
```

- Open only when `XEMS_INGEST_TOKEN` is set (else `404`); constant-time token compare.
- Per-client-IP token-bucket rate limit (`XEMS_INGEST_RATE_PER_SEC`, default 50, cap 2×);
  `429` when exceeded. Body cap 4 MiB. Response `{"accepted": n, "sources": m}`.
- Each source name maps to a STABLE device id (UUIDv5).

## Format routing

| Content | Routed as | Source | Severity |
|---|---|---|---|
| `application/json` (XEMS schema) | JSON array/object with `source`+`message` | `source` | `severity` |
| `application/json` + `?format=winlog` **or** body has `winlog`/`event_id` | Windows Event Log | computer name | EventID+channel |
| line contains `CEF:` | CEF (ArcSight) | Vendor/Product | CEF 0-10 |
| line contains `LEEF:` | LEEF (QRadar) | Vendor/Product | `sev` attr |
| line starts with `<` | plain syslog (RFC5424/3164) | HOSTNAME/APP | `<PRI>` |
| other lines | assumed CEF | — | — |

Text bodies are parsed per line; unrecognized lines are skipped.

## Event time

All five formats use the event's REAL timestamp (not ingest time) so the attack story and
timeline order correctly: JSON `occurred_at`; Windows `@timestamp`/`event.created`/
TimeCreated `@SystemTime`; syslog RFC5424 TIMESTAMP (RFC3164 has no year → ingest time);
CEF `rt`; LEEF `devTime`. Falls back to ingest time when absent/unparseable.

## Windows Event Log

Windows security events are classified by EventID + channel (e.g. 4625 failed logon →
MEDIUM, 1102 audit log cleared → CRITICAL, 7045 service install → HIGH, Sysmon 8
CreateRemoteThread → HIGH). Target account, source IP and logon type are lifted from
EventData into Details. Three JSON shapes are supported: winlogbeat (nested `winlog`),
nxlog (flat), and rendered-XML (`Event.System`). Point winlogbeat's HTTP output at
`/api/ingest?format=winlog`.

## Detections fed by ingested data

Ingested events feed all server-side analyzers: **brute force / password spraying**
(Windows 4625/4771 burst aggregation → T1110), **successful brute force** (success after a
failed-logon burst → account compromise, CRITICAL), **beacon / lateral movement / DNS
tunneling**, and the **MITRE ATT&CK** coverage matrix + attack story. See
`deploy/server/c2.env.example` for tunable thresholds.

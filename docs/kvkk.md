# KVKK / Gizlilik Notları
# Data Protection / Privacy Notes (KVKK / GDPR)

**Türkçe** · [English](#english)

Bu sistem ağ trafiği ve süreç verisi işler; kurumsal bağlamda meşru olsa da
KVKK (ve muadili GDPR) gereklilikleri tasarıma baştan girer.

## İlkeler

- **Şeffaflık / bilgilendirme:** Çalışanlara izleme kapsamı açıkça bildirilir;
  gizli/örtük izleme yapılmaz.
- **Veri minimizasyonu:** Yalnız güvenlik amacı için gerekli veri toplanır.
  İçerik (ör. dosya/klavye içeriği) değil, meta-veri (süreç adı, bağlantı
  meta-verisi) hedeflenir.
- **Amaçla sınırlılık:** Toplanan veri güvenlik/politika uygulaması dışında
  kullanılmaz.
- **Saklama süresi:** `event_logs` zaman-bazlı partition'lıdır; saklama süresi
  dolan partition'lar DROP edilir (varsayılan öneri: 90 gün — kurumun
  politikasına göre ayarlanır).
- **Erişim kontrolü + denetim:** Yönetici erişimi RBAC ile sınırlı; hassas
  aksiyonlar (kaldırma OTP'si, karantina) `audit_log`'a değişmez yazılır.
- **Şifreleme:** Hassas alanlar at-rest şifreli; iletişim mTLS ile şifreli.

## Yapılacaklar

- [ ] Çalışan bilgilendirme metni / aydınlatma metni şablonu.
- [x] Saklama süresini otomatik uygulayan partition DROP görevi —
      `server/internal/retention` (C2'de günlük çalışır; `XEMS_RETENTION_DAYS`,
      varsayılan 90 gün). Dolan `event_logs` aylık partition'ları düşürülür,
      gelecek aylar önceden oluşturulur.
- [ ] Veri sahibi başvuru (erişim/silme) süreçlerinin operasyonel karşılığı.

---

# English

This system processes network traffic and process data; even though it is legitimate
in a corporate context, data-protection requirements (Turkey's KVKK and its GDPR
counterpart) are built into the design from the start.

## Principles

- **Transparency / notice:** the scope of monitoring is clearly communicated to
  employees; no covert/implicit monitoring.
- **Data minimization:** only data necessary for the security purpose is collected.
  Metadata (process name, connection metadata) is targeted, not content (e.g. file or
  keystroke content).
- **Purpose limitation:** collected data is not used outside security/policy
  enforcement.
- **Retention period:** `event_logs` is time-based partitioned; partitions whose
  retention period has elapsed are DROPped (default suggestion: 90 days - configured
  per the organization's policy).
- **Access control + audit:** admin access is limited by RBAC; sensitive actions
  (uninstall OTP, quarantine) are written immutably to `audit_log`.
- **Encryption:** sensitive fields are at-rest encrypted; communication is encrypted
  with mTLS.

## To do

- [ ] Employee notice / privacy-notice text template.
- [x] Partition-DROP job that automatically enforces the retention period -
      `server/internal/retention` (runs daily in C2; `XEMS_RETENTION_DAYS`, default 90
      days). Elapsed monthly `event_logs` partitions are dropped and future months are
      pre-created.
- [ ] Operational counterpart of data-subject request (access/erasure) processes.

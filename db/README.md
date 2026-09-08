# Veritabanı
# Database

**Türkçe** · [English](#english)

`schema.sql` — düzeltilmiş PostgreSQL şeması (PostgreSQL 14+).

## Kurulum

```bash
createdb xems
psql -U postgres -d xems -f schema.sql
```

## Notlar

- **Blind index (HMAC):** `*_bidx` sütunları uygulama katmanında
  `HMAC-SHA256(sunucu_gizli_anahtarı, normalize_değer)` ile üretilir. Düz hash
  kullanmayın (MAC adres uzayı brute-force'a açıktır).
- **At-rest şifreleme:** `event_logs` sorgulanabilir kalması için alan-bazlı
  şifrelenmez; gizliliği şifreli tablespace / disk (TDE) düzeyinde sağlanır.
  Serbest-metin kimlik alanları (`*_encrypted`) `pgcrypto` ile şifrelidir.
- **Partition yönetimi:** `event_logs` RANGE partition'lıdır. Üretimde
  `pg_partman` veya bir cron görevi ile gelecek partition'lar önceden
  oluşturulmalı ve saklama süresi dolanlar DROP edilmelidir (bkz. `docs/kvkk.md`).
- **Migration'lar:** İleride `migrations/` altına sıralı `.sql` dosyaları
  (ör. golang-migrate) eklenecek; `schema.sql` başlangıç anlık görüntüsüdür.

---

# English

`schema.sql` - the corrected PostgreSQL schema (PostgreSQL 14+).

## Setup

```bash
createdb xems
psql -U postgres -d xems -f schema.sql
```

## Notes

- **Blind index (HMAC):** the `*_bidx` columns are produced at the application layer
  as `HMAC-SHA256(server_secret_key, normalized_value)`. Do not use a plain hash (the
  MAC address space is open to brute force).
- **At-rest encryption:** `event_logs` is not field-level encrypted so it stays
  queryable; its confidentiality is provided at the encrypted-tablespace / disk (TDE)
  level. Free-text identity fields (`*_encrypted`) are encrypted with `pgcrypto`.
- **Partition management:** `event_logs` is RANGE-partitioned. In production, future
  partitions must be pre-created and elapsed ones DROPped via `pg_partman` or a cron
  job (see `docs/kvkk.md`).
- **Migrations:** sequential `.sql` files (e.g. golang-migrate) will be added under
  `migrations/` later; `schema.sql` is the initial snapshot.

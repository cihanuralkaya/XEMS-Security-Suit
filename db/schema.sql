-- =============================================================================
-- XEMS Security Suite — PostgreSQL Şeması (düzeltilmiş)
-- =============================================================================
-- İnceleme bulgularına göre orijinal taslaktan farklar:
--   #1  Eksik `policies` tablosu eklendi; kırık FK düzeltildi.
--   #1  event_logs artık ZAMAN-BAZLI PARTITIONING kullanır ve sorgulanabilir
--       kalması için mesaj/detay alanları düz metin/JSONB'dir. Gizlilik
--       AT-REST şifreleme (TDE / şifreli disk / pgcrypto ile SEÇİLİ alanlar)
--       ile sağlanır — her logu BYTEA'ya şifreleyip aranamaz hale getirmek yerine.
--   #2  Blind index'ler düz SHA-256 değil, HMAC (keyed) üretilmelidir.
--       Uygulama katmanı, sunucudaki gizli anahtarla HMAC-SHA256 hesaplar.
--   #6  enrollment_tokens, agent_certificates tabloları (PKI bootstrap).
--   #4  ota_releases: imza alanı (yalnız hash değil).
--   #10 admins (RBAC) + audit_log (yönetici aksiyon denetim izi).
--   common: device_status'a PENDING_ENROLLMENT eklendi.
--
-- NOT (gizlilik): Bu şema, gerçekten hassas serbest-metin alanlarını (hostname,
-- mac, os_info) pgcrypto ile ŞİFRELİ (BYTEA) saklar ve arama için AYRI bir HMAC
-- blind-index sütunu tutar. Yüksek hacimli event_logs ise sorgulanabilirlik için
-- şifrelenmez; onun gizliliği disk/tablespace düzeyi at-rest şifreleme ile korunur.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- ENUM TİPLERİ
-- ---------------------------------------------------------------------------
CREATE TYPE device_status AS ENUM (
    'PENDING_ENROLLMENT', 'ACTIVE', 'OFFLINE', 'QUARANTINED', 'UNINSTALLED'
);

CREATE TYPE event_category AS ENUM (
    'SYSTEM', 'SECURITY', 'NETWORK_DISCOVERY', 'POLICY_VIOLATION', 'AGENT_UPDATE', 'PROCESS', 'NETWORK_CONN'
);

CREATE TYPE severity AS ENUM (
    'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
);

CREATE TYPE admin_role AS ENUM ('VIEWER', 'OPERATOR', 'ADMIN');

CREATE TYPE command_type AS ENUM (
    'QUARANTINE', 'UNQUARANTINE', 'RUN_SIGNED_SCRIPT', 'UNINSTALL', 'COLLECT_DIAGNOSTICS', 'COLLECT_FILE',
    'LOCK', 'RESTART', 'WIPE'
);

-- ---------------------------------------------------------------------------
-- CİHAZLAR
--   * Hassas serbest-metin alanları pgcrypto ile şifreli (BYTEA).
--   * *_bidx sütunları HMAC(keyed) blind index'tir — düz SHA-256 DEĞİL (#2).
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
    id                     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname_encrypted     BYTEA NOT NULL,
    mac_address_encrypted  BYTEA NOT NULL,
    os_info_encrypted      BYTEA,
    -- HMAC-SHA256(sunucu_gizli_anahtarı, normalize_edilmiş_mac). MAC uzayı ~48 bit
    -- olduğundan DÜZ hash offline brute-force'a açıktır; keyed HMAC şarttır.
    mac_address_bidx       BYTEA NOT NULL UNIQUE,
    agent_version          VARCHAR(50),
    os_platform            VARCHAR(20),               -- "windows" | "linux"
    os_version             VARCHAR(120),              -- okunabilir OS sürümü (filo envanteri)
    status                 device_status NOT NULL DEFAULT 'PENDING_ENROLLMENT',
    current_policy_version VARCHAR(64),
    tags                   TEXT[] NOT NULL DEFAULT '{}',   -- filo gruplama/etiketleme
    last_seen              TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_status    ON devices (status);
CREATE INDEX idx_devices_last_seen ON devices (last_seen);

-- ---------------------------------------------------------------------------
-- PKI / ENROLLMENT (#6 bootstrap)
-- ---------------------------------------------------------------------------
-- Tek kullanımlık, süreli kayıt token'ları. token_hash = HMAC(token) saklanır,
-- ham token asla DB'de tutulmaz.
CREATE TABLE enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash  BYTEA NOT NULL UNIQUE,
    created_by  UUID,                       -- admins.id (aşağıda FK)
    device_id   UUID REFERENCES devices(id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,                -- NULL => henüz kullanılmadı
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_enroll_tokens_expiry ON enrollment_tokens (expires_at)
    WHERE used_at IS NULL;

-- İmzalanmış istemci sertifikaları ve iptal durumu (mTLS + revocation).
CREATE TABLE agent_certificates (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    serial_number NUMERIC NOT NULL UNIQUE,   -- X.509 seri no
    fingerprint   BYTEA NOT NULL UNIQUE,     -- SHA-256(DER)
    not_before    TIMESTAMPTZ NOT NULL,
    not_after     TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,               -- NULL => geçerli
    revoke_reason VARCHAR(100),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_certs_device ON agent_certificates (device_id);
CREATE INDEX idx_agent_certs_active ON agent_certificates (device_id)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- POLİTİKALAR (#1 — eksik tablo eklendi)
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(150) NOT NULL,
    description TEXT,
    version     VARCHAR(64) NOT NULL,        -- ajana itilen sürüm etiketi
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policy_rules (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id    UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    type         VARCHAR(50) NOT NULL,       -- APP_TIME_BLOCK | APP_BLOCK_ALWAYS | NETWORK_RULE
    target_value VARCHAR(255) NOT NULL,
    start_time   TIME,                       -- APP_TIME_BLOCK için gerekli
    end_time     TIME,
    active_days  INT[] NOT NULL DEFAULT '{1,2,3,4,5,6,0}',  -- 0=Pazar
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_policy_rules_policy ON policy_rules (policy_id);

-- Hangi cihaz(lar)a hangi politika atanmış (grup yerine önce doğrudan atama).
CREATE TABLE device_policies (
    device_id  UUID NOT NULL REFERENCES devices(id)  ON DELETE CASCADE,
    policy_id  UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, policy_id)
);

-- ---------------------------------------------------------------------------
-- OTA SÜRÜMLERİ (#4 — imza, yalnız hash değil)
-- ---------------------------------------------------------------------------
CREATE TABLE ota_releases (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version         VARCHAR(50) NOT NULL UNIQUE,
    os_platform     VARCHAR(20) NOT NULL,     -- "windows" | "linux"
    download_url    TEXT NOT NULL,
    sha256_hex      VARCHAR(64) NOT NULL,     -- bütünlük
    signature       BYTEA NOT NULL,           -- Ed25519/Authenticode imzası (kimlik)
    mandatory       BOOLEAN NOT NULL DEFAULT FALSE,
    rollout_percent INT NOT NULL DEFAULT 100 CHECK (rollout_percent BETWEEN 0 AND 100),
    published_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- OLAY LOGLARI (#1 — partitioned, sorgulanabilir)
--   Gizlilik at-rest şifreleme ile; içerik JSONB olarak sorgulanabilir kalır.
--   PostgreSQL 12+ native RANGE partitioning (created_at üzerinde).
-- ---------------------------------------------------------------------------
CREATE TABLE event_logs (
    id          UUID NOT NULL DEFAULT uuid_generate_v4(),
    device_id   UUID NOT NULL,               -- FK partition'lı tabloda pratik
                                             -- nedenlerle uygulama katmanında doğrulanır
    category    event_category NOT NULL,
    severity    severity NOT NULL DEFAULT 'INFO',
    message     TEXT NOT NULL,
    details     JSONB,
    occurred_at TIMESTAMPTZ NOT NULL,        -- ajanın gözlemlediği an
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),  -- sunucuya ulaşma anı
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Sorgu erişim desenleri için indeksler (partition'lara miras kalır).
CREATE INDEX idx_event_logs_device   ON event_logs (device_id, created_at DESC);
CREATE INDEX idx_event_logs_category ON event_logs (category, created_at DESC);
CREATE INDEX idx_event_logs_severity ON event_logs (severity, created_at DESC)
    WHERE severity IN ('HIGH', 'CRITICAL');
CREATE INDEX idx_event_logs_details  ON event_logs USING GIN (details);

-- Örnek başlangıç partition'ları. Üretimde pg_partman veya cron ile otomatik
-- oluşturulmalı ve saklama süresi (KVKK #11) ile eski partition'lar DROP edilmeli.
CREATE TABLE event_logs_2026_08 PARTITION OF event_logs
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE event_logs_2026_09 PARTITION OF event_logs
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

-- Olay triyaj durumu (alarm yaşam-döngüsü): yüksek-önem olayları SOC analisti
-- ACKNOWLEDGED (inceleniyor) veya RESOLVED (kapatıldı) olarak işaretler. event_id
-- olayın kimliğidir (partition'lı event_logs'a FK pratik değil — bkz. device_id
-- notu). Olay başına tek durum (upsert). Denetim izi ayrıca WriteAudit ile tutulur.
-- Not: admin_id'de FK yok (admins tablosu bu noktadan sonra tanımlı; ayrıca
-- device_id gibi uygulama katmanında doğrulanır). Kim işaretledi bilgisi
-- denetim iziyle (WriteAudit) sağlam tutulur; buradaki admin_id yalnız görüntü.
-- status nullable: bir olay yalnız atanabilir/notlanabilir (henüz ack'lenmeden) —
-- vaka yönetimi (#9). assignee: sorumlu analist; note: serbest triyaj notu.
CREATE TABLE event_ack (
    event_id   TEXT PRIMARY KEY,
    status     TEXT CHECK (status IS NULL OR status IN ('ACKNOWLEDGED', 'RESOLVED')),
    assignee   TEXT,
    note       TEXT,
    admin_id   UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- AĞ KEŞFİ (Network Discovery)
-- ---------------------------------------------------------------------------
CREATE TABLE discovered_hosts (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reporter_device  UUID REFERENCES devices(id) ON DELETE SET NULL,
    mac_bidx         BYTEA NOT NULL,          -- HMAC blind index (#2)
    mac_encrypted    BYTEA NOT NULL,
    ip_encrypted     BYTEA,
    vendor           VARCHAR(120),            -- OUI'den türetilmiş üretici (hassas değil)
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_authorized    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX idx_discovered_mac ON discovered_hosts (mac_bidx);

-- ---------------------------------------------------------------------------
-- CİHAZ KOMUT KUYRUĞU
--   Admin'in ürettiği anlık komutlar (karantina vb.) burada bekler; heartbeat
--   ile ajana teslim edilir ve delivered_at işaretlenir (en-fazla-bir-kez).
-- ---------------------------------------------------------------------------
CREATE TABLE device_commands (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    type         command_type NOT NULL,
    params       JSONB,
    issued_by    UUID,                       -- admins.id (FK aşağıda bağlanır)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ                 -- NULL => bekliyor
);
CREATE INDEX idx_device_commands_pending ON device_commands (device_id, created_at)
    WHERE delivered_at IS NULL;

-- Adli/IR dosya toplama artefaktları: COLLECT_FILE komutuyla ajandan yüklenen
-- dosya içeriği (boyut-sınırlı, uygulama katmanında). content ham baytlar;
-- hassas olabileceğinden erişim RBAC + denetim iziyle korunur.
CREATE TABLE artifacts (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command_id   UUID,
    path         TEXT NOT NULL,
    sha256       CHAR(64) NOT NULL,
    size_bytes   INTEGER NOT NULL,
    content      BYTEA NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_artifacts_device ON artifacts (device_id, collected_at DESC);
-- Saklama budaması (retention.PurgeArtifactsOlderThan): WHERE collected_at < cutoff.
-- Cihaz-index'in başı device_id olduğundan bu taramaya hizmet edemez; ayrı index.
CREATE INDEX idx_artifacts_collected ON artifacts (collected_at);

-- ---------------------------------------------------------------------------
-- YÖNETİCİLER (RBAC) + DENETİM İZİ (#10)
-- ---------------------------------------------------------------------------
CREATE TABLE admins (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email         VARCHAR(255) NOT NULL UNIQUE,
    display_name  VARCHAR(150),
    role          admin_role NOT NULL DEFAULT 'VIEWER',
    password_hash TEXT,                       -- Argon2id (uygulama katmanı)
    mfa_secret    BYTEA,                       -- AES-256-GCM ile şifreli TOTP sırrı (2FA)
    mfa_enrolled  BOOLEAN NOT NULL DEFAULT FALSE,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- FK'ları burada bağla (admins tablosu artık mevcut).
ALTER TABLE enrollment_tokens
    ADD CONSTRAINT fk_enroll_token_admin
    FOREIGN KEY (created_by) REFERENCES admins(id) ON DELETE SET NULL;

ALTER TABLE device_commands
    ADD CONSTRAINT fk_device_command_admin
    FOREIGN KEY (issued_by) REFERENCES admins(id) ON DELETE SET NULL;

-- Kim, neyi, ne zaman yaptı — özellikle uninstall OTP üretimi gibi hassas
-- aksiyonların değiştirilemez kaydı.
CREATE TABLE audit_log (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    admin_id    UUID REFERENCES admins(id) ON DELETE SET NULL,
    action      VARCHAR(100) NOT NULL,       -- "ISSUE_UNINSTALL_OTP", "QUARANTINE", ...
    target_type VARCHAR(50),                 -- "device" | "policy" | ...
    target_id   UUID,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Kurcalama-kanıtı hash zinciri (SEC C-1): entry_hash =
    -- SHA-256(prev_hash || kanonik(alanlar)). Bir kaydın değiştirilmesi/silinmesi
    -- sonraki hash'leri geçersiz kılar. VerifyAuditChain ile doğrulanır.
    prev_hash   BYTEA,
    entry_hash  BYTEA
);
CREATE INDEX idx_audit_admin  ON audit_log (admin_id, created_at DESC);
CREATE INDEX idx_audit_target ON audit_log (target_type, target_id);

-- ---------------------------------------------------------------------------
-- ÇİFT-KONTROL (DÖRT-GÖZ) BEKLEYEN WIPE TALEPLERİ
-- ---------------------------------------------------------------------------
-- WIPE geri döndürülemez olduğundan, XEMS_WIPE_DUAL_CONTROL=1 iken bir ADMIN talep
-- eder ve FARKLI bir ADMIN onaylayana dek komut kuyruğa GİRMEZ. Tek ele geçirilmiş/
-- kötü-niyetli ADMIN filoyu silemez.
CREATE TABLE pending_wipes (
    device_id    UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    requested_by UUID NOT NULL REFERENCES admins(id),
    reason       TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

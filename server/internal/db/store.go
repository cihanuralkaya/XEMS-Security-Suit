// Package db, PostgreSQL erişim katmanıdır (pgx). enroll.Store gibi domain
// arayüzlerini somut sorgularla karşılar.
//
// NOT: Bu paket harici bağımlılık (github.com/jackc/pgx/v5) kullanır; derlenmesi
// için `go get` / `go mod tidy` gerekir. Çekirdek security/enroll paketleri buna
// bağımlı DEĞİLDİR ve tek başlarına test edilebilir.
package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/structpb"

	xemsv1 "xems.corp/suite/gen/xems/v1"
	"xems.corp/suite/server/internal/enroll"
	"xems.corp/suite/server/internal/model"
	"xems.corp/suite/server/internal/security"
)

// Store, pgx havuzu üzerinden domain depolama arayüzlerini uygular.
type Store struct {
	pool   *pgxpool.Pool
	cipher *security.FieldCipher // MFA sırrı gibi hassas sütunları at-rest şifreler
}

// SetFieldCipher, hassas sütunların (ör. TOTP sırrı) at-rest şifrelenmesi için
// alan şifreleyiciyi bağlar. MFA kayıt akışı bu ayarlanmadan çalışmaz (fail-closed).
func (s *Store) SetFieldCipher(c *security.FieldCipher) { s.cipher = c }

// New, DSN'den bir bağlantı havuzu açar.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("db: havuz açılamadı: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("db: ping başarısız: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Ping, veritabanı bağlantısının sağlığını kontrol eder (readiness).
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// NotifyChannel, bir Postgres LISTEN/NOTIFY kanalına yük gönderir (#10 küme
// fan-out). Kanal adı tanımlayıcı olduğundan bağlanamaz; ancak pg_notify(text,
// text) fonksiyonu her iki argümanı da parametre olarak alarak enjeksiyona karşı
// güvenlidir. Yük 8000 bayttan küçük olmalıdır (Postgres NOTIFY sınırı).
func (s *Store) NotifyChannel(ctx context.Context, channel, payload string) error {
	if _, err := s.pool.Exec(ctx, "SELECT pg_notify($1, $2)", channel, payload); err != nil {
		return fmt.Errorf("db: pg_notify: %w", err)
	}
	return nil
}

// ListenChannel, adanmış bir bağlantıda LISTEN yaparak gelen her bildirimin
// yükünü onPayload'a iletir. ctx iptal edilene ya da bağlantı düşene dek BLOKLAR
// (çağıran genelde ayrı bir goroutine'de çalıştırıp hata dönüşünde yeniden bağlanır).
// Kanal adı tanımlayıcı olduğundan pgx.Identifier.Sanitize ile güvenli-alıntılanır.
func (s *Store) ListenChannel(ctx context.Context, channel string, onPayload func(string)) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("db: dinleyici bağlantısı: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return fmt.Errorf("db: LISTEN %s: %w", channel, err)
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return fmt.Errorf("db: bildirim bekleme: %w", err)
		}
		onPayload(n.Payload)
	}
}

// Close, havuzu kapatır.
func (s *Store) Close() { s.pool.Close() }

// Derleme-zamanı arayüz kontrolü.
var _ enroll.Store = (*Store)(nil)

// ConsumeEnrollmentToken, token'ı ATOMİK olarak doğrular ve kullanılmış işaretler.
// Tek bir UPDATE ... RETURNING ile yarış koşulu olmadan tek-kullanım garanti edilir.
func (s *Store) ConsumeEnrollmentToken(ctx context.Context, tokenIndex []byte, _ time.Time) (string, error) {
	// Zaman çıpası olarak DB'nin now()'ı kullanılır (tek otorite); domain
	// arayüzündeki time.Time parametresi burada gerekmez.
	const q = `
		UPDATE enrollment_tokens
		   SET used_at = now()
		 WHERE token_hash = $1
		   AND used_at IS NULL
		   AND expires_at > now()
	 RETURNING COALESCE(device_id::text, '')`
	var boundDeviceID string
	err := s.pool.QueryRow(ctx, q, tokenIndex).Scan(&boundDeviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", enroll.ErrInvalidToken
	}
	if err != nil {
		return "", fmt.Errorf("db: token tüketme: %w", err)
	}
	return boundDeviceID, nil
}

// UpsertEnrollingDevice, cihazı oluşturur/günceller ve device_id döner.
func (s *Store) UpsertEnrollingDevice(ctx context.Context, in enroll.DeviceEnrollment) (string, error) {
	if in.PreferredDeviceID != "" {
		const upd = `
			UPDATE devices
			   SET hostname_encrypted = $2,
			       mac_address_encrypted = $3,
			       os_info_encrypted = $4,
			       mac_address_bidx = $5,
			       os_platform = $6,
			       agent_version = $7,
			       status = 'ACTIVE'
			 WHERE id = $1
		 RETURNING id::text`
		var id string
		err := s.pool.QueryRow(ctx, upd, in.PreferredDeviceID, in.HostnameEnc, in.MACEnc,
			in.OSInfoEnc, in.MACBlindIndex, in.OSPlatform, in.AgentVersion).Scan(&id)
		if err != nil {
			return "", fmt.Errorf("db: cihaz güncelleme: %w", err)
		}
		return id, nil
	}

	const ins = `
		INSERT INTO devices
			(hostname_encrypted, mac_address_encrypted, os_info_encrypted,
			 mac_address_bidx, os_platform, agent_version, status)
		VALUES ($1,$2,$3,$4,$5,$6,'ACTIVE')
		ON CONFLICT (mac_address_bidx) DO UPDATE SET
			hostname_encrypted = EXCLUDED.hostname_encrypted,
			mac_address_encrypted = EXCLUDED.mac_address_encrypted,
			os_info_encrypted = EXCLUDED.os_info_encrypted,
			os_platform = EXCLUDED.os_platform,
			agent_version = EXCLUDED.agent_version,
			status = 'ACTIVE'
	 RETURNING id::text`
	var id string
	err := s.pool.QueryRow(ctx, ins, in.HostnameEnc, in.MACEnc, in.OSInfoEnc,
		in.MACBlindIndex, in.OSPlatform, in.AgentVersion).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("db: cihaz ekleme: %w", err)
	}
	return id, nil
}

// SaveCertificate, imzalanan istemci sertifikasını kaydeder.
func (s *Store) SaveCertificate(ctx context.Context, c enroll.CertRecord) error {
	const q = `
		INSERT INTO agent_certificates
			(device_id, serial_number, fingerprint, not_before, not_after)
		VALUES ($1, $2::numeric, $3, $4, $5)`
	_, err := s.pool.Exec(ctx, q, c.DeviceID, c.Serial, c.Fingerprint, c.NotBefore, c.NotAfter)
	if err != nil {
		return fmt.Errorf("db: sertifika kaydı: %w", err)
	}
	return nil
}

// DeviceHasActiveCert, cihazın iptal edilmemiş (revoked_at IS NULL) en az bir
// sertifikası var mı. Yenileme iptal-bypass korumasında (SEC-002) kullanılır —
// revocation cache yerine KESİN DB kontrolü.
func (s *Store) DeviceHasActiveCert(ctx context.Context, deviceID string) (bool, error) {
	const q = `SELECT EXISTS(SELECT 1 FROM agent_certificates WHERE device_id = $1::uuid AND revoked_at IS NULL)`
	var ok bool
	if err := s.pool.QueryRow(ctx, q, deviceID).Scan(&ok); err != nil {
		return false, fmt.Errorf("db: aktif sertifika kontrolü: %w", err)
	}
	return ok, nil
}

// --- AgentService (heartbeat/olay) depolaması ---

// TouchHeartbeat, last_seen ve agent_version günceller; cihazın sunucudaki
// geçerli politika sürümünü döner.
func (s *Store) TouchHeartbeat(ctx context.Context, deviceID, agentVersion, osVersion string, at time.Time) (string, error) {
	const q = `
		UPDATE devices
		   SET last_seen = $2,
		       agent_version = COALESCE(NULLIF($3, ''), agent_version),
		       os_version = COALESCE(NULLIF($4, ''), os_version),
		       status = CASE WHEN status = 'OFFLINE' THEN 'ACTIVE' ELSE status END
		 WHERE id = $1
	 RETURNING COALESCE(current_policy_version, '')`
	var v string
	err := s.pool.QueryRow(ctx, q, deviceID, at, agentVersion, osVersion).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("db: bilinmeyen cihaz: %s", deviceID)
	}
	if err != nil {
		return "", fmt.Errorf("db: heartbeat güncelleme: %w", err)
	}
	return v, nil
}

// PendingCommands, cihaz için bekleyen komutları döner ve teslim edildi olarak
// işaretler (en-fazla-bir-kez teslim). Tek UPDATE...RETURNING ile atomiktir.
func (s *Store) PendingCommands(ctx context.Context, deviceID string) ([]*xemsv1.Command, error) {
	const q = `
		UPDATE device_commands
		   SET delivered_at = now()
		 WHERE id IN (
		       SELECT id FROM device_commands
		        WHERE device_id = $1 AND delivered_at IS NULL
		        ORDER BY created_at
		        LIMIT 100)
	 RETURNING id::text, type, COALESCE(params::text, '')`
	rows, err := s.pool.Query(ctx, q, deviceID)
	if err != nil {
		return nil, fmt.Errorf("db: komut sorgusu: %w", err)
	}
	defer rows.Close()

	var cmds []*xemsv1.Command
	for rows.Next() {
		var id, typ, paramsJSON string
		if err := rows.Scan(&id, &typ, &paramsJSON); err != nil {
			return nil, fmt.Errorf("db: komut okuma: %w", err)
		}
		cmd := &xemsv1.Command{CommandId: id, Type: commandTypeToProto(typ)}
		if paramsJSON != "" {
			var m map[string]any
			if json.Unmarshal([]byte(paramsJSON), &m) == nil {
				cmd.Params, _ = structpb.NewStruct(m)
			}
		}
		cmds = append(cmds, cmd)
	}
	return cmds, rows.Err()
}

// EnqueueCommand, cihaz için bir komut kuyruğa ekler (admin aksiyonu).
func (s *Store) EnqueueCommand(ctx context.Context, deviceID, cmdType, issuedBy string) error {
	return s.EnqueueCommandParams(ctx, deviceID, cmdType, issuedBy, nil)
}

// EnqueueCommandParams, parametreli komut kuyruğa ekler (params JSONB olarak
// saklanır ve teslimde google.protobuf.Struct'a dönüşür).
func (s *Store) EnqueueCommandParams(ctx context.Context, deviceID, cmdType, issuedBy string, params map[string]string) error {
	var pj []byte
	if len(params) > 0 {
		pj, _ = json.Marshal(params)
	}
	const q = `
		INSERT INTO device_commands (device_id, type, issued_by, params)
		VALUES ($1, $2::command_type, NULLIF($3,'')::uuid, $4)`
	_, err := s.pool.Exec(ctx, q, deviceID, cmdType, issuedBy, pj)
	if err != nil {
		return fmt.Errorf("db: komut kuyruğa eklenemedi: %w", err)
	}
	return nil
}

func commandTypeToProto(t string) xemsv1.Command_CommandType {
	switch t {
	case "QUARANTINE":
		return xemsv1.Command_COMMAND_TYPE_QUARANTINE
	case "UNQUARANTINE":
		return xemsv1.Command_COMMAND_TYPE_UNQUARANTINE
	case "RUN_SIGNED_SCRIPT":
		return xemsv1.Command_COMMAND_TYPE_RUN_SIGNED_SCRIPT
	case "UNINSTALL":
		return xemsv1.Command_COMMAND_TYPE_UNINSTALL
	case "COLLECT_DIAGNOSTICS":
		return xemsv1.Command_COMMAND_TYPE_COLLECT_DIAGNOSTICS
	case "COLLECT_FILE":
		return xemsv1.Command_COMMAND_TYPE_COLLECT_FILE
	case "LOCK":
		return xemsv1.Command_COMMAND_TYPE_LOCK
	case "RESTART":
		return xemsv1.Command_COMMAND_TYPE_RESTART
	case "WIPE":
		return xemsv1.Command_COMMAND_TYPE_WIPE
	default:
		return xemsv1.Command_COMMAND_TYPE_UNSPECIFIED
	}
}

// SaveEvents, gelen olayları event_logs'a yazar ve kabul edilen son sırayı döner.
//
// Batch AÇIK bir transaction içinde çalışır (hepsi-ya-hiç): tek bir ifade
// başarısız olursa hiçbiri yazılmaz, fonksiyon 0 döner, ajan tüm partiyi yeniden
// gönderir ve KISMEN yazılmış olaylardan kaynaklı DUPLİKASYON oluşmaz.
// (Ack kaybında tüm parti yeniden gelebilir; teslim en-az-bir-kez'dir.)
func (s *Store) SaveEvents(ctx context.Context, deviceID string, evs []model.Event) (uint64, error) {
	if len(evs) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("db: olay transaction başlatma: %w", err)
	}
	defer tx.Rollback(ctx) // commit sonrası no-op

	const q = `
		INSERT INTO event_logs (device_id, category, severity, message, occurred_at, details)
		VALUES ($1, $2::event_category, $3::severity, $4, $5, NULLIF($6, '')::jsonb)`
	batch := &pgx.Batch{}
	var last uint64
	for _, e := range evs {
		batch.Queue(q, deviceID, e.Category, e.Severity, e.Message, e.OccurredAt, e.Details)
		if e.Sequence > last {
			last = e.Sequence
		}
	}
	br := tx.SendBatch(ctx, batch)
	for range evs {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return 0, fmt.Errorf("db: olay yazma: %w", err)
		}
	}
	if err := br.Close(); err != nil {
		return 0, fmt.Errorf("db: olay batch kapatma: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("db: olay commit: %w", err)
	}
	return last, nil
}

package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"xdr.corp/suite/server/internal/admin"
	"xdr.corp/suite/server/internal/adminapi"
	"xdr.corp/suite/server/internal/security"
)

// Derleme-zamanı arayüz kontrolleri.
var (
	_ admin.Store        = (*Store)(nil)
	_ adminapi.AuthStore = (*Store)(nil)
)

// LookupAdmin, e-postadan yönetici id'si ve parola hash'ini çözer (adminapi auth).
func (s *Store) LookupAdmin(ctx context.Context, email string) (string, string, error) {
	const q = `SELECT id::text, COALESCE(password_hash, '') FROM admins WHERE email = $1 AND is_active`
	var id, hash string
	err := s.pool.QueryRow(ctx, q, email).Scan(&id, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("db: admin arama: %w", err)
	}
	return id, hash, nil
}

// AdminRole, yöneticinin rolünü döner. Bilinmeyen/pasif admin için boş rol
// (yetkisiz) döner.
func (s *Store) AdminRole(ctx context.Context, adminID string) (admin.Role, error) {
	const q = `SELECT role FROM admins WHERE id = $1 AND is_active`
	var r string
	err := s.pool.QueryRow(ctx, q, adminID).Scan(&r)
	if errors.Is(err, pgx.ErrNoRows) {
		return admin.Role(""), nil
	}
	if err != nil {
		return "", fmt.Errorf("db: admin rolü: %w", err)
	}
	return admin.Role(r), nil
}

// SaveEnrollmentToken, admin tarafından üretilen token'ın HMAC indeksini saklar.
func (s *Store) SaveEnrollmentToken(ctx context.Context, tokenIndex []byte, createdBy string, expiresAt time.Time) error {
	const q = `
		INSERT INTO enrollment_tokens (token_hash, created_by, expires_at)
		VALUES ($1, NULLIF($2,'')::uuid, $3)`
	_, err := s.pool.Exec(ctx, q, tokenIndex, createdBy, expiresAt)
	if err != nil {
		return fmt.Errorf("db: enrollment token kaydı: %w", err)
	}
	return nil
}

// WriteAudit, değişmez denetim izine bir satır yazar (#10).
// SaveArtifact, toplanan bir dosya artefaktını saklar ve id'sini döner
// (grpc.ArtifactSink; adli/IR). command_id boşsa NULL yazılır.
func (s *Store) SaveArtifact(ctx context.Context, deviceID, commandID, path, sha256 string, content []byte) (string, error) {
	const q = `
		INSERT INTO artifacts (device_id, command_id, path, sha256, size_bytes, content)
		VALUES ($1::uuid, NULLIF($2,'')::uuid, $3, $4, $5, $6)
		RETURNING id::text`
	var id string
	if err := s.pool.QueryRow(ctx, q, deviceID, commandID, path, sha256, len(content), content).Scan(&id); err != nil {
		return "", fmt.Errorf("db: artefakt kaydı: %w", err)
	}
	return id, nil
}

// SetEventAck, bir olayın triyaj durumunu ayarlar (olay başına upsert). Alarm
// yaşam-döngüsü (ACKNOWLEDGED/RESOLVED).
func (s *Store) SetEventAck(ctx context.Context, eventID, adminID, status string) error {
	const q = `
		INSERT INTO event_ack (event_id, status, admin_id, updated_at)
		VALUES ($1, $2, NULLIF($3,'')::uuid, now())
		ON CONFLICT (event_id) DO UPDATE
		   SET status = EXCLUDED.status, admin_id = EXCLUDED.admin_id, updated_at = now()`
	if _, err := s.pool.Exec(ctx, q, eventID, status, adminID); err != nil {
		return fmt.Errorf("db: olay triyaj durumu: %w", err)
	}
	return nil
}

// SetEventCase, olayın sorumlu+not alanlarını ayarlar (durumu korur; upsert).
func (s *Store) SetEventCase(ctx context.Context, eventID, adminID, assignee, note string) error {
	const q = `
		INSERT INTO event_ack (event_id, assignee, note, admin_id, updated_at)
		VALUES ($1, NULLIF($2,''), NULLIF($3,''), NULLIF($4,'')::uuid, now())
		ON CONFLICT (event_id) DO UPDATE
		   SET assignee = NULLIF($2,''), note = NULLIF($3,''), admin_id = EXCLUDED.admin_id, updated_at = now()`
	if _, err := s.pool.Exec(ctx, q, eventID, assignee, note, adminID); err != nil {
		return fmt.Errorf("db: olay vaka güncelleme: %w", err)
	}
	return nil
}

// SavePendingWipe, ikinci-onay bekleyen WIPE talebini saklar (çift-kontrol; upsert).
func (s *Store) SavePendingWipe(ctx context.Context, deviceID, requestedBy, reason string) error {
	const q = `
		INSERT INTO pending_wipes (device_id, requested_by, reason, requested_at)
		VALUES ($1::uuid, $2::uuid, NULLIF($3,''), now())
		ON CONFLICT (device_id) DO UPDATE
		   SET requested_by = EXCLUDED.requested_by, reason = EXCLUDED.reason, requested_at = now()`
	if _, err := s.pool.Exec(ctx, q, deviceID, requestedBy, reason); err != nil {
		return fmt.Errorf("db: bekleyen wipe kaydı: %w", err)
	}
	return nil
}

// GetPendingWipe, cihaz için bekleyen WIPE talebini (talep eden admin id'si) döner.
func (s *Store) GetPendingWipe(ctx context.Context, deviceID string) (string, bool, error) {
	var rb string
	err := s.pool.QueryRow(ctx, `SELECT requested_by::text FROM pending_wipes WHERE device_id = $1::uuid`, deviceID).Scan(&rb)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("db: bekleyen wipe okuma: %w", err)
	}
	return rb, true, nil
}

// DeletePendingWipe, bekleyen WIPE talebini siler (onay/iptal sonrası; yoksa no-op).
func (s *Store) DeletePendingWipe(ctx context.Context, deviceID string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM pending_wipes WHERE device_id = $1::uuid`, deviceID); err != nil {
		return fmt.Errorf("db: bekleyen wipe silme: %w", err)
	}
	return nil
}

func (s *Store) WriteAudit(ctx context.Context, adminID, action, targetType, targetID string) error {
	// Kurcalama-kanıtı hash zinciri (SEC C-1): önceki entry_hash okunur, yeni hash
	// hesaplanır ve prev_hash+entry_hash+created_at ile eklenir — hepsi tek
	// transaction'da (araya kayıt sıkışması/yarış olmadan sıralı zincir).
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: denetim tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var prev []byte
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("db: son denetim hash: %w", err)
	}
	now := time.Now().Truncate(time.Microsecond)
	hash := security.AuditChainHash(prev, adminID, action, targetType, targetID, now.UnixNano())

	const q = `
		INSERT INTO audit_log (admin_id, action, target_type, target_id, created_at, prev_hash, entry_hash)
		VALUES (NULLIF($1,'')::uuid, $2, NULLIF($3,''), NULLIF($4,'')::uuid, $5, $6, $7)`
	if _, err := tx.Exec(ctx, q, adminID, action, targetType, targetID, now, prev, hash); err != nil {
		return fmt.Errorf("db: denetim izi: %w", err)
	}
	return tx.Commit(ctx)
}

// VerifyAuditChain, audit_log hash zincirinin bütünlüğünü doğrular (SEC C-1).
// Kayıtları id sırasıyla okur ve her entry_hash'i yeniden hesaplayıp karşılaştırır.
func (s *Store) VerifyAuditChain(ctx context.Context) error {
	rows, err := s.pool.Query(ctx,
		`SELECT id, COALESCE(admin_id::text,''), action, COALESCE(target_type,''),
		        COALESCE(target_id::text,''), created_at, entry_hash
		   FROM audit_log ORDER BY id`)
	if err != nil {
		return fmt.Errorf("db: denetim zinciri okuma: %w", err)
	}
	defer rows.Close()

	var prev []byte
	for rows.Next() {
		var id int64
		var adminID, action, targetType, targetID string
		var createdAt time.Time
		var stored []byte
		if err := rows.Scan(&id, &adminID, &action, &targetType, &targetID, &createdAt, &stored); err != nil {
			return fmt.Errorf("db: denetim satırı: %w", err)
		}
		want := security.AuditChainHash(prev, adminID, action, targetType, targetID, createdAt.UnixNano())
		if !bytes.Equal(want, stored) {
			return fmt.Errorf("db: denetim izi zinciri kırık: kayıt id=%d", id)
		}
		prev = stored
	}
	return rows.Err()
}

// CreatePolicy, yeni bir politika oluşturur ve id'sini döner.
func (s *Store) CreatePolicy(ctx context.Context, name, version string) (string, error) {
	const q = `INSERT INTO policies (name, version) VALUES ($1, $2) RETURNING id::text`
	var id string
	if err := s.pool.QueryRow(ctx, q, name, version).Scan(&id); err != nil {
		return "", fmt.Errorf("db: politika oluşturma: %w", err)
	}
	return id, nil
}

// AssignPolicy, bir politikayı cihaza atar (idempotent).
func (s *Store) AssignPolicy(ctx context.Context, deviceID, policyID string) error {
	const q = `
		INSERT INTO device_policies (device_id, policy_id)
		VALUES ($1, $2)
		ON CONFLICT (device_id, policy_id) DO NOTHING`
	_, err := s.pool.Exec(ctx, q, deviceID, policyID)
	if err != nil {
		return fmt.Errorf("db: politika atama: %w", err)
	}
	return nil
}

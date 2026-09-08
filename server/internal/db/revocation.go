package db

import (
	"context"
	"fmt"

	"xems.corp/suite/server/internal/revocation"
)

// Derleme-zamanı arayüz kontrolü.
var _ revocation.Source = (*Store)(nil)

// RevokedFingerprints, iptal edilmiş (revoked_at dolu) sertifikaların
// SHA-256(DER) parmak izlerini döner.
func (s *Store) RevokedFingerprints(ctx context.Context) ([][]byte, error) {
	const q = `SELECT fingerprint FROM agent_certificates WHERE revoked_at IS NOT NULL`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: iptal listesi: %w", err)
	}
	defer rows.Close()

	var out [][]byte
	for rows.Next() {
		var fp []byte
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

// RevokeDeviceCerts, bir cihazın geçerli tüm sertifikalarını iptal işaretler
// (admin aksiyonu). İptal, tazeleme turunda mTLS reddine yansır.
func (s *Store) RevokeDeviceCerts(ctx context.Context, deviceID, reason string) error {
	const q = `
		UPDATE agent_certificates
		   SET revoked_at = now(), revoke_reason = NULLIF($2,'')
		 WHERE device_id = $1 AND revoked_at IS NULL`
	if _, err := s.pool.Exec(ctx, q, deviceID, reason); err != nil {
		return fmt.Errorf("db: sertifika iptali: %w", err)
	}
	return nil
}

// EraseDeviceData, KVKK veri silme: olay logları + komut geçmişini siler ve
// sertifikaları iptal eder — tek transaction'da (atomik). Denetim izi korunur.
// event_logs partition'lı ve devices'a FK'siz olduğundan elle silinir; certs
// iptal (revoked_at) edilir, satır silinmez (revocation tombstone kalıcı olur).
func (s *Store) EraseDeviceData(ctx context.Context, deviceID string) (int, int, int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("db: silme tx: %w", err)
	}
	defer tx.Rollback(ctx)

	evTag, err := tx.Exec(ctx, `DELETE FROM event_logs WHERE device_id = $1::uuid`, deviceID)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("db: olay silme: %w", err)
	}
	cmdTag, err := tx.Exec(ctx, `DELETE FROM device_commands WHERE device_id = $1::uuid`, deviceID)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("db: komut silme: %w", err)
	}
	certTag, err := tx.Exec(ctx,
		`UPDATE agent_certificates SET revoked_at = now(), revoke_reason = 'KVKK erasure'
		   WHERE device_id = $1::uuid AND revoked_at IS NULL`, deviceID)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("db: sertifika iptali: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, 0, fmt.Errorf("db: silme commit: %w", err)
	}
	return int(evTag.RowsAffected()), int(cmdTag.RowsAffected()), int(certTag.RowsAffected()), nil
}

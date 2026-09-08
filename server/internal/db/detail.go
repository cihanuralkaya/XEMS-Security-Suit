package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"xems.corp/suite/server/internal/adminread"
)

// DeviceByID, tek bir cihazı (şifreli alanlar dahil) döner. Cihaz yoksa
// ok=false döner.
func (s *Store) DeviceByID(ctx context.Context, id string) (adminread.DeviceRow, bool, error) {
	const q = `
		SELECT id::text, status::text, COALESCE(agent_version,''),
		       COALESCE(os_platform,''), COALESCE(os_version,''), COALESCE(last_seen, 'epoch'::timestamptz),
		       hostname_encrypted, mac_address_encrypted, COALESCE(tags, '{}')
		  FROM devices
		 WHERE id = $1`
	var d adminread.DeviceRow
	var lastSeen time.Time
	err := s.pool.QueryRow(ctx, q, id).Scan(&d.ID, &d.Status, &d.AgentVersion,
		&d.OSPlatform, &d.OSVersion, &lastSeen, &d.HostnameEnc, &d.MACEnc, &d.Tags)
	if errors.Is(err, pgx.ErrNoRows) {
		return adminread.DeviceRow{}, false, nil
	}
	if err != nil {
		return adminread.DeviceRow{}, false, fmt.Errorf("db: cihaz okuma: %w", err)
	}
	d.LastSeen = lastSeen
	return d, true, nil
}

// CertsByDevice, bir cihazın sertifikalarını döner (fingerprint hex-kodlu).
func (s *Store) CertsByDevice(ctx context.Context, id string) ([]adminread.CertRow, error) {
	const q = `
		SELECT serial_number::text, encode(fingerprint,'hex'),
		       not_before, not_after, revoked_at IS NOT NULL
		  FROM agent_certificates
		 WHERE device_id = $1
		 ORDER BY not_before DESC`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("db: sertifika listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.CertRow
	for rows.Next() {
		var c adminread.CertRow
		if err := rows.Scan(&c.Serial, &c.Fingerprint, &c.NotBefore, &c.NotAfter, &c.Revoked); err != nil {
			return nil, fmt.Errorf("db: sertifika okuma: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CommandHistory, bir cihazın komut geçmişini en yeniden eskiye döner.
func (s *Store) CommandHistory(ctx context.Context, id string) ([]adminread.CmdRow, error) {
	const q = `
		SELECT type::text, COALESCE(issued_by::text,''), created_at, delivered_at
		  FROM device_commands
		 WHERE device_id = $1
		 ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("db: komut geçmişi: %w", err)
	}
	defer rows.Close()

	var out []adminread.CmdRow
	for rows.Next() {
		var c adminread.CmdRow
		if err := rows.Scan(&c.Type, &c.IssuedBy, &c.CreatedAt, &c.DeliveredAt); err != nil {
			return nil, fmt.Errorf("db: komut okuma: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AssignedPolicy, cihaza atanmış politikanın id ve sürümünü döner. Atama yoksa
// boş değerler döner.
func (s *Store) AssignedPolicy(ctx context.Context, id string) (string, string, error) {
	const q = `
		SELECT p.id::text, p.version
		  FROM device_policies dp
		  JOIN policies p ON p.id = dp.policy_id
		 WHERE dp.device_id = $1
		 LIMIT 1`
	var policyID, version string
	err := s.pool.QueryRow(ctx, q, id).Scan(&policyID, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("db: atanmış politika: %w", err)
	}
	return policyID, version, nil
}

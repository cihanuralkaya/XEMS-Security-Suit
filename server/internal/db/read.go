package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"xems.corp/suite/server/internal/adminread"
)

// Derleme-zamanı arayüz kontrolü.
var _ adminread.Store = (*Store)(nil)

// ListDevices, cihazları son görülmeye göre listeler (okuma API'si).
func (s *Store) ListDevices(ctx context.Context, limit int) ([]adminread.DeviceRow, error) {
	const q = `
		SELECT id::text, status::text, COALESCE(agent_version,''),
		       COALESCE(os_platform,''), COALESCE(os_version,''), COALESCE(last_seen, 'epoch'::timestamptz),
		       hostname_encrypted, mac_address_encrypted, COALESCE(tags, '{}')
		  FROM devices
		 ORDER BY last_seen DESC NULLS LAST
		 LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("db: cihaz listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.DeviceRow
	for rows.Next() {
		var d adminread.DeviceRow
		var lastSeen time.Time
		if err := rows.Scan(&d.ID, &d.Status, &d.AgentVersion, &d.OSPlatform, &d.OSVersion,
			&lastSeen, &d.HostnameEnc, &d.MACEnc, &d.Tags); err != nil {
			return nil, fmt.Errorf("db: cihaz okuma: %w", err)
		}
		d.LastSeen = lastSeen
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListEvents, olay loglarını (deviceID boşsa tümünü) en yeniden eskiye listeler.
// severity ve category boş ("") değilse ilgili ENUM sütununa göre sunucu-tarafında
// filtre uygulanır. details, ham JSON metni olarak okunur (yoksa nil).
func (s *Store) ListEvents(ctx context.Context, deviceID, severity, category string, limit int) ([]adminread.EventRow, error) {
	const q = `
		SELECT id::text, device_id::text, category::text, severity::text, message, occurred_at, created_at,
		       COALESCE(details::text, '')
		  FROM event_logs
		 WHERE ($1 = '' OR device_id = NULLIF($1,'')::uuid)
		   AND ($2 = '' OR severity = $2::severity)
		   AND ($3 = '' OR category = $3::event_category)
		 ORDER BY created_at DESC
		 LIMIT $4`
	rows, err := s.pool.Query(ctx, q, deviceID, severity, category, limit)
	if err != nil {
		return nil, fmt.Errorf("db: olay listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.EventRow
	for rows.Next() {
		var e adminread.EventRow
		var details string
		if err := rows.Scan(&e.ID, &e.DeviceID, &e.Category, &e.Severity, &e.Message, &e.OccurredAt, &e.CreatedAt, &details); err != nil {
			return nil, fmt.Errorf("db: olay okuma: %w", err)
		}
		if details != "" {
			e.Details = []byte(details)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAudit, denetim izini (audit_log) admin e-postasıyla birlikte en yeniden
// eskiye listeler. Admin silinmiş/eşleşmemişse e-posta boş döner (LEFT JOIN).
// ListArtifacts, bir cihazın artefakt meta verisini (içerik hariç) en yeniden
// eskiye döner.
func (s *Store) ListArtifacts(ctx context.Context, deviceID string) ([]adminread.ArtifactRow, error) {
	const q = `
		SELECT id::text, device_id::text, path, sha256, size_bytes, collected_at
		  FROM artifacts WHERE device_id = $1::uuid ORDER BY collected_at DESC`
	rows, err := s.pool.Query(ctx, q, deviceID)
	if err != nil {
		return nil, fmt.Errorf("db: artefakt listesi: %w", err)
	}
	defer rows.Close()
	var out []adminread.ArtifactRow
	for rows.Next() {
		var a adminread.ArtifactRow
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.Path, &a.SHA256, &a.Size, &a.CollectedAt); err != nil {
			return nil, fmt.Errorf("db: artefakt okuma: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetArtifact, tek bir artefaktın içeriğini (indirme için) döner.
func (s *Store) GetArtifact(ctx context.Context, id string) (adminread.ArtifactContent, bool, error) {
	const q = `SELECT path, content FROM artifacts WHERE id = $1::uuid`
	var c adminread.ArtifactContent
	err := s.pool.QueryRow(ctx, q, id).Scan(&c.Path, &c.Content)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return adminread.ArtifactContent{}, false, nil
		}
		return adminread.ArtifactContent{}, false, fmt.Errorf("db: artefakt içerik: %w", err)
	}
	return c, true, nil
}

// EventAcks, triyaj işaretli tüm olayların durumunu döner (olay kimliği →
// durum + işaretleyen e-posta + zaman). Alarm yaşam-döngüsü.
func (s *Store) EventAcks(ctx context.Context) (map[string]adminread.EventAck, error) {
	const q = `
		SELECT e.event_id, COALESCE(e.status,''), COALESCE(e.assignee,''), COALESCE(e.note,''), COALESCE(ad.email,''), e.updated_at
		  FROM event_ack e
		  LEFT JOIN admins ad ON ad.id = e.admin_id`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: olay triyaj listesi: %w", err)
	}
	defer rows.Close()

	out := map[string]adminread.EventAck{}
	for rows.Next() {
		var id string
		var a adminread.EventAck
		if err := rows.Scan(&id, &a.Status, &a.Assignee, &a.Note, &a.AdminEmail, &a.At); err != nil {
			return nil, fmt.Errorf("db: olay triyaj okuma: %w", err)
		}
		out[id] = a
	}
	return out, rows.Err()
}

// ListPendingWipes, ikinci-onay bekleyen tüm WIPE taleplerini (talep eden admin
// e-postasıyla) en yeniden eskiye döner (çift-kontrol görünürlüğü).
func (s *Store) ListPendingWipes(ctx context.Context) ([]adminread.PendingWipeRow, error) {
	const q = `
		SELECT p.device_id::text, COALESCE(ad.email, p.requested_by::text), COALESCE(p.reason,''), p.requested_at
		  FROM pending_wipes p
		  LEFT JOIN admins ad ON ad.id = p.requested_by
		  ORDER BY p.requested_at DESC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: bekleyen wipe listesi: %w", err)
	}
	defer rows.Close()
	var out []adminread.PendingWipeRow
	for rows.Next() {
		var r adminread.PendingWipeRow
		if err := rows.Scan(&r.DeviceID, &r.RequestedBy, &r.Reason, &r.RequestedAt); err != nil {
			return nil, fmt.Errorf("db: bekleyen wipe okuma: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]adminread.AuditRow, error) {
	const q = `
		SELECT a.id, COALESCE(ad.email,''), a.action::text,
		       COALESCE(a.target_type,''), COALESCE(a.target_id::text,''), a.created_at
		  FROM audit_log a
		  LEFT JOIN admins ad ON ad.id = a.admin_id
		 ORDER BY a.created_at DESC
		 LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("db: denetim izi listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.AuditRow
	for rows.Next() {
		var a adminread.AuditRow
		if err := rows.Scan(&a.ID, &a.AdminEmail, &a.Action, &a.TargetType, &a.TargetID, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: denetim izi okuma: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

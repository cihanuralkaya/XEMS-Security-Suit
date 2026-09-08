package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xems.corp/suite/server/internal/adminread"
)

// DeviceStatusCounts, cihazları durumuna göre gruplayıp (status -> adet) döner.
func (s *Store) DeviceStatusCounts(ctx context.Context) (map[string]int, error) {
	const q = `SELECT status::text, count(*) FROM devices GROUP BY status`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: cihaz durum sayımı: %w", err)
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, fmt.Errorf("db: cihaz durum okuma: %w", err)
		}
		out[status] = n
	}
	return out, rows.Err()
}

// EventSeverityCounts, since'ten bu yana olayları önem seviyesine göre sayar.
func (s *Store) EventSeverityCounts(ctx context.Context, since time.Time) (map[string]int, error) {
	const q = `SELECT severity::text, count(*) FROM event_logs WHERE created_at >= $1 GROUP BY severity`
	return s.eventCounts(ctx, q, since, "olay önem sayımı")
}

// EventCategoryCounts, since'ten bu yana olayları kategoriye göre sayar.
func (s *Store) EventCategoryCounts(ctx context.Context, since time.Time) (map[string]int, error) {
	const q = `SELECT category::text, count(*) FROM event_logs WHERE created_at >= $1 GROUP BY category`
	return s.eventCounts(ctx, q, since, "olay kategori sayımı")
}

// LatestComplianceByDevice, uyum verisi (disk_encryption/firewall) taşıyan her
// cihazın EN SON durumunu döner. DISTINCT ON ile cihaz başına en yeni uyum-olayı
// seçilir; JSONB alanları metne çıkarılır.
func (s *Store) LatestComplianceByDevice(ctx context.Context) (map[string]adminread.ComplianceStatus, error) {
	const q = `
		SELECT DISTINCT ON (device_id) device_id::text,
		       COALESCE(details->>'disk_encryption',''), COALESCE(details->>'firewall','')
		  FROM event_logs
		 WHERE details ? 'disk_encryption' OR details ? 'firewall'
		 ORDER BY device_id, created_at DESC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: uyum durumu sorgusu: %w", err)
	}
	defer rows.Close()

	out := map[string]adminread.ComplianceStatus{}
	for rows.Next() {
		var id, enc, fw string
		if err := rows.Scan(&id, &enc, &fw); err != nil {
			return nil, fmt.Errorf("db: uyum durumu okuma: %w", err)
		}
		out[id] = adminread.ComplianceStatus{Enc: enc, Fw: fw}
	}
	return out, rows.Err()
}

// SearchSoftware, her cihazın EN SON yazılım envanterinde query'yi (küçük/büyük
// harf duyarsız alt-dize) içeren paketleri arar. DISTINCT ON ile cihaz başına en
// yeni envanter olayı seçilir; software dizisi JSON olarak çıkarılıp Go'da
// süzülür (küçük fleet için yeterli; büyük ölçekte JSONB dizin ile hızlandırılır).
func (s *Store) SearchSoftware(ctx context.Context, query string) (map[string][]string, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	out := map[string][]string{}
	if q == "" {
		return out, nil
	}
	const sql = `
		SELECT DISTINCT ON (device_id) device_id::text, COALESCE(details->>'software','[]')
		  FROM event_logs
		 WHERE details ? 'software'
		 ORDER BY device_id, created_at DESC`
	rows, err := s.pool.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("db: yazılım arama: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, swJSON string
		if err := rows.Scan(&id, &swJSON); err != nil {
			return nil, fmt.Errorf("db: yazılım arama okuma: %w", err)
		}
		var sw []string
		if err := json.Unmarshal([]byte(swJSON), &sw); err != nil {
			continue
		}
		var m []string
		for _, name := range sw {
			if strings.Contains(strings.ToLower(name), q) {
				m = append(m, name)
			}
		}
		if len(m) > 0 {
			out[id] = m
		}
	}
	return out, rows.Err()
}

// LatestSoftwareByDevice, her cihazın EN SON yazılım envanterini döner (DISTINCT
// ON ile en yeni envanter olayı; software dizisi JSON'dan çıkarılır).
func (s *Store) LatestSoftwareByDevice(ctx context.Context) (map[string][]string, error) {
	const sql = `
		SELECT DISTINCT ON (device_id) device_id::text, COALESCE(details->>'software','[]')
		  FROM event_logs
		 WHERE details ? 'software'
		 ORDER BY device_id, created_at DESC`
	rows, err := s.pool.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("db: en son yazılım: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, swJSON string
		if err := rows.Scan(&id, &swJSON); err != nil {
			return nil, fmt.Errorf("db: en son yazılım okuma: %w", err)
		}
		var sw []string
		if json.Unmarshal([]byte(swJSON), &sw) == nil && len(sw) > 0 {
			out[id] = sw
		}
	}
	return out, rows.Err()
}

// eventCounts, tek anahtar+adet dönen GROUP BY sorgularını çalıştırır.
func (s *Store) eventCounts(ctx context.Context, q string, since time.Time, what string) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, q, since)
	if err != nil {
		return nil, fmt.Errorf("db: %s: %w", what, err)
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var key string
		var n int
		if err := rows.Scan(&key, &n); err != nil {
			return nil, fmt.Errorf("db: %s okuma: %w", what, err)
		}
		out[key] = n
	}
	return out, rows.Err()
}

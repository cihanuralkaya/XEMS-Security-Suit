package db

// Bu dosya, yönetici (admin) kullanıcı yönetiminin PostgreSQL sorgularını içerir:
// oluşturma, rol değiştirme, pasifleştirme ve listeleme. Parola hash'i (Argon2id)
// uygulama katmanında üretilir; buraya yalnız hazır hash gelir.

import (
	"context"
	"fmt"

	"xems.corp/suite/server/internal/admin"
)

// CreateAdmin, yeni bir yönetici ekler ve id'sini döner.
func (s *Store) CreateAdmin(ctx context.Context, email, passwordHash string, role admin.Role) (string, error) {
	const q = `
		INSERT INTO admins (email, role, password_hash)
		VALUES ($1, $2::admin_role, $3)
		RETURNING id::text`
	var id string
	if err := s.pool.QueryRow(ctx, q, email, string(role), passwordHash).Scan(&id); err != nil {
		return "", fmt.Errorf("db: yönetici oluşturma: %w", err)
	}
	return id, nil
}

// SetAdminRole, bir yöneticinin rolünü değiştirir.
func (s *Store) SetAdminRole(ctx context.Context, id string, role admin.Role) error {
	const q = `UPDATE admins SET role = $2::admin_role WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, id, string(role)); err != nil {
		return fmt.Errorf("db: yönetici rolü güncelleme: %w", err)
	}
	return nil
}

// DeactivateAdmin, bir yöneticiyi pasifleştirir (is_active=false).
func (s *Store) DeactivateAdmin(ctx context.Context, id string) error {
	const q = `UPDATE admins SET is_active = false WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("db: yönetici pasifleştirme: %w", err)
	}
	return nil
}

// ListAdmins, tüm yöneticileri e-postaya göre sıralı döner. Parola hash'i ASLA
// seçilmez/dönmez.
func (s *Store) ListAdmins(ctx context.Context) ([]admin.AdminInfo, error) {
	const q = `SELECT id::text, email, role, is_active FROM admins ORDER BY email`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: yönetici listesi: %w", err)
	}
	defer rows.Close()
	var out []admin.AdminInfo
	for rows.Next() {
		var a admin.AdminInfo
		var role string
		if err := rows.Scan(&a.ID, &a.Email, &role, &a.Active); err != nil {
			return nil, fmt.Errorf("db: yönetici okuma: %w", err)
		}
		a.Role = admin.Role(role)
		out = append(out, a)
	}
	return out, rows.Err()
}

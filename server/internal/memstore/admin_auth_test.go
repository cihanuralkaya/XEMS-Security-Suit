package memstore

import (
	"context"
	"testing"

	"xems.corp/suite/server/internal/admin"
)

// Pasifleştirilen yönetici artık LookupAdmin ile çözülmemeli (giriş yapamaz).
// db implementasyonu da (WHERE ... AND is_active) aynı davranışı gösterir.
func TestLookupAdminExcludesDeactivated(t *testing.T) {
	s := New()
	id := s.SeedAdmin("soc@x", "hash-xyz", admin.RoleOperator)

	if gotID, hash, err := s.LookupAdmin(context.Background(), "soc@x"); err != nil || gotID != id || hash != "hash-xyz" {
		t.Fatalf("aktif admin çözülmeliydi: id=%q hash=%q err=%v", gotID, hash, err)
	}

	if err := s.DeactivateAdmin(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	gotID, hash, err := s.LookupAdmin(context.Background(), "soc@x")
	if err != nil {
		t.Fatal(err)
	}
	if gotID != "" || hash != "" {
		t.Fatalf("pasif admin çözülmemeliydi (hesap sızıntısı): id=%q hash=%q", gotID, hash)
	}
}

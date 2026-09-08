package memstore

import (
	"context"
	"testing"
	"time"

	"xems.corp/suite/server/internal/model"
)

// Olay kimlikleri KARARLI olmalı: aynı olay, ardışık ListEvents çağrılarında
// aynı ID'yi taşımalı (konsol genişletme durumu + kimlik-tabanlı etkileşim
// bunun üzerine kuruludur). Regresyon: eskiden ID her listelemede randID ile
// yeniden üretiliyordu.
func TestEventIDsStableAcrossList(t *testing.T) {
	ctx := context.Background()
	s := New()
	d := enrollDevice(t, s)
	if _, err := s.SaveEvents(ctx, d, []model.Event{
		{Sequence: 1, Category: "SYSTEM", Severity: "INFO", Message: "bir", OccurredAt: time.Now()},
		{Sequence: 2, Category: "SECURITY", Severity: "HIGH", Message: "iki", OccurredAt: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}

	first, err := s.ListEvents(ctx, "", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ListEvents(ctx, "", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("2 olay beklenirdi: %d/%d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID == "" {
			t.Fatalf("olay kimliği boş olmamalı")
		}
		if first[i].ID != second[i].ID {
			t.Fatalf("olay kimliği kararsız: %q != %q", first[i].ID, second[i].ID)
		}
	}
	if first[0].ID == first[1].ID {
		t.Fatalf("farklı olaylar farklı kimlik taşımalı")
	}
}

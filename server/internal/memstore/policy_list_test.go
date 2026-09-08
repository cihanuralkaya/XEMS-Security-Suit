package memstore

import (
	"context"
	"testing"

	"xems.corp/suite/server/internal/admin"
	"xems.corp/suite/server/internal/enroll"
)

// ListPolicies, kural ve atanmış cihaz sayımlarını doğru raporlamalı ve
// çıktı ada göre deterministik sıralı olmalı.
func TestListPoliciesCountsAndOrder(t *testing.T) {
	ctx := context.Background()
	s := New()

	// "B-Politika": 2 kural, 0 atanmış cihaz.
	bID, err := s.CreatePolicy(ctx, "B-Politika", "v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, tgt := range []string{"oyun.exe", "torrent.exe"} {
		if err := s.AddPolicyRule(ctx, bID, admin.RuleInput{Type: "APP_BLOCK_ALWAYS", Target: tgt}); err != nil {
			t.Fatal(err)
		}
	}

	// "A-Politika": 1 kural, 2 atanmış cihaz.
	aID, err := s.CreatePolicy(ctx, "A-Politika", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddPolicyRule(ctx, aID, admin.RuleInput{Type: "APP_BLOCK_ALWAYS", Target: "mesai.exe"}); err != nil {
		t.Fatal(err)
	}
	// İki AYRI cihaz (farklı MAC blind index; aynı MAC upsert'te tekilleşir).
	d1, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("mac-1")})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("mac-2")})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{d1, d2} {
		if err := s.AssignPolicy(ctx, d, aID); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := s.ListPolicies(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("2 politika beklenirdi, %d", len(rows))
	}
	// Ada göre sıralı: A-Politika önce.
	if rows[0].Name != "A-Politika" || rows[1].Name != "B-Politika" {
		t.Fatalf("ada göre sıralı olmalıydı: %q, %q", rows[0].Name, rows[1].Name)
	}
	if rows[0].RuleCount != 1 || rows[0].DeviceCount != 2 {
		t.Fatalf("A-Politika 1 kural / 2 cihaz beklenirdi: %+v", rows[0])
	}
	if rows[1].RuleCount != 2 || rows[1].DeviceCount != 0 {
		t.Fatalf("B-Politika 2 kural / 0 cihaz beklenirdi: %+v", rows[1])
	}

	// limit uygulanmalı.
	if got, _ := s.ListPolicies(ctx, 1); len(got) != 1 || got[0].Name != "A-Politika" {
		t.Fatalf("limit=1 yalnız A-Politika dönmeliydi: %+v", got)
	}
}

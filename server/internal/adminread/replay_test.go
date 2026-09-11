package adminread

import (
	"context"
	"testing"
	"time"

	"xems.corp/suite/server/internal/detect"
)

func TestReplayDetections(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	store := &memStore{events: []EventRow{
		{ID: "e1", DeviceID: "d1", Category: "SECURITY", Severity: "HIGH",
			Message: "powershell -enc AAAA çalıştırıldı", OccurredAt: t0, CreatedAt: t0},
		{ID: "e2", DeviceID: "d2", Category: "SECURITY", Severity: "LOW",
			Message: "normal oturum açma", OccurredAt: t0, CreatedAt: t0},
		{ID: "e3", DeviceID: "d1", Category: "SECURITY", Severity: "HIGH",
			Message: "PowerShell indirici encoded komut", OccurredAt: t0, CreatedAt: t0},
	}}
	svc := NewService(store, newCipher(t))

	// Aday kural DRAFT durumda — replay yine de değerlendirmeli (activateForReplay).
	candidate := detect.Rule{
		ID: "CAND-1", Name: "Encoded PowerShell", Severity: "HIGH", Status: "draft",
		Contains: []string{"powershell", "enc"},
	}
	rep, err := svc.ReplayDetections(context.Background(), EventFilter{}, []detect.Rule{candidate})
	if err != nil {
		t.Fatalf("ReplayDetections: %v", err)
	}
	if rep.Scanned != 3 {
		t.Errorf("taranan = %d, beklenen 3", rep.Scanned)
	}
	// e1 ("enc") ve e3 ("encoded") "enc" alt-dizesini içerir → 2 eşleşme.
	if rep.Matched != 2 || rep.ByRule["CAND-1"] != 2 {
		t.Errorf("eşleşme = %d, by_rule = %v; beklenen 2", rep.Matched, rep.ByRule)
	}
	if len(rep.Matches) != 2 {
		t.Fatalf("örnek eşleşme = %d, beklenen 2", len(rep.Matches))
	}
	if rep.Matches[0].EventID == "" || rep.Matches[0].RuleID != "CAND-1" {
		t.Errorf("eşleşme meta verisi eksik: %+v", rep.Matches[0])
	}
}

func TestReplayDetectionsNoMatch(t *testing.T) {
	store := &memStore{events: []EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "LOW", Message: "sıradan olay"},
	}}
	svc := NewService(store, newCipher(t))
	rep, err := svc.ReplayDetections(context.Background(), EventFilter{},
		[]detect.Rule{{ID: "R", Name: "n", Severity: "HIGH", Contains: []string{"mimikatz"}}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Scanned != 1 || rep.Matched != 0 {
		t.Errorf("taranan=%d eşleşen=%d; beklenen 1/0", rep.Scanned, rep.Matched)
	}
}

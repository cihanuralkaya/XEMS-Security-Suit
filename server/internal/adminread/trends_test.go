package adminread

import (
	"testing"
	"time"
)

func TestComputeTrendsMTTD(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	events := []EventDTO{
		// SECURITY: 60s alım gecikmesi (created − occurred).
		{Category: "SECURITY", OccurredAt: now.Add(-2 * time.Minute), CreatedAt: now.Add(-1 * time.Minute)},
		// SECURITY: 30s gecikme.
		{Category: "SECURITY", OccurredAt: now.Add(-2 * time.Minute), CreatedAt: now.Add(-90 * time.Second)},
		// SYSTEM: MTTD'ye dahil DEĞİL.
		{Category: "SYSTEM", OccurredAt: now.Add(-10 * time.Minute), CreatedAt: now},
	}
	tr := ComputeTrends(events, now, 7)
	if tr.DetectN != 2 {
		t.Fatalf("2 MTTD örneği beklenirdi, %d", tr.DetectN)
	}
	if tr.MTTDSeconds != 45 { // (60+30)/2
		t.Fatalf("MTTD 45s beklenirdi, %v", tr.MTTDSeconds)
	}
}

func TestComputeTrendsMTTR(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	events := []EventDTO{
		// Triyaj edildi (RESOLVED): created→ack 120s.
		{Category: "SECURITY", CreatedAt: now.Add(-5 * time.Minute),
			AckStatus: "RESOLVED", AckAt: now.Add(-3 * time.Minute)},
		// Yalnız atama (assignee) da triyaj sayılır: 60s.
		{Category: "SECURITY", CreatedAt: now.Add(-5 * time.Minute),
			AckAssignee: "analyst@corp", AckAt: now.Add(-4 * time.Minute)},
		// Triyaj yok → MTTR'ye dahil değil.
		{Category: "SECURITY", CreatedAt: now.Add(-5 * time.Minute)},
	}
	tr := ComputeTrends(events, now, 7)
	if tr.RespondN != 2 {
		t.Fatalf("2 MTTR örneği beklenirdi, %d", tr.RespondN)
	}
	if tr.MTTRSeconds != 90 { // (120+60)/2
		t.Fatalf("MTTR 90s beklenirdi, %v", tr.MTTRSeconds)
	}
}

func TestComputeTrendsSkewIgnored(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	events := []EventDTO{
		// Negatif MTTD (occurred > created, saat kayması) → yok sayılır.
		{Category: "SECURITY", OccurredAt: now, CreatedAt: now.Add(-1 * time.Minute)},
		// Negatif MTTR (ack < created) → yok sayılır.
		{Category: "SECURITY", CreatedAt: now, AckStatus: "RESOLVED", AckAt: now.Add(-1 * time.Minute)},
	}
	tr := ComputeTrends(events, now, 7)
	if tr.DetectN != 0 || tr.RespondN != 0 {
		t.Fatalf("saat-kaymalı örnekler yok sayılmalı, detect=%d respond=%d", tr.DetectN, tr.RespondN)
	}
}

func TestComputeTrendsDailyContiguous(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	tr := ComputeTrends(nil, now, 7)
	if len(tr.Daily) != 7 {
		t.Fatalf("7 günlük nokta beklenirdi (boş günler dahil), %d", len(tr.Daily))
	}
	// Eskiden yeniye sıralı; son gün bugün.
	if tr.Daily[0].Day != "2026-03-04" || tr.Daily[6].Day != "2026-03-10" {
		t.Fatalf("gün aralığı yanlış: %s .. %s", tr.Daily[0].Day, tr.Daily[6].Day)
	}
	if tr.MTTDSeconds != 0 || tr.MTTRSeconds != 0 {
		t.Fatal("olay yoksa ortalamalar 0 olmalı")
	}
}

func TestComputeTrendsDefaultsDays(t *testing.T) {
	now := time.Now().UTC()
	if tr := ComputeTrends(nil, now, 0); tr.WindowDays != 7 || len(tr.Daily) != 7 {
		t.Fatalf("days<=0 varsayılan 7 olmalı, window=%d daily=%d", tr.WindowDays, len(tr.Daily))
	}
}

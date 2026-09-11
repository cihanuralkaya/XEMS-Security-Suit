package retention

import (
	"testing"
	"time"
)

func mon(y int, m time.Month) time.Time { return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC) }

func TestClassifyPartitions(t *testing.T) {
	// now = 2026-09-15; eşikler: hot<=30g, warm<=90g, cold<=365g, ötesi drop.
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	cfg := TierConfig{HotDays: 30, WarmDays: 90, ColdDays: 365}
	existing := []time.Time{
		mon(2026, 9), // güncel ay → hot
		mon(2026, 8), // sonu 09-01, yaş ~14g → hot
		mon(2026, 6), // sonu 07-01, yaş ~76g → warm
		mon(2026, 3), // sonu 04-01, yaş ~167g → cold
		mon(2025, 1), // çok eski → drop
	}
	got := ClassifyPartitions(now, cfg, existing)
	want := map[time.Time]Tier{
		mon(2026, 9): TierHot,
		mon(2026, 8): TierHot,
		mon(2026, 6): TierWarm,
		mon(2026, 3): TierCold,
		mon(2025, 1): TierDrop,
	}
	for m, w := range want {
		if got[m] != w {
			t.Errorf("%s: katman %q, beklenen %q", PartitionName(m), got[m], w)
		}
	}
}

func TestPlanTiersOnlyChanges(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	cfg := TierConfig{HotDays: 30, WarmDays: 90, ColdDays: 365}
	existing := []time.Time{mon(2026, 6), mon(2026, 9)}
	// mevcut: 2026-06 hot (yanlış/eskimiş), 2026-09 hot (doğru)
	current := map[time.Time]Tier{mon(2026, 6): TierHot, mon(2026, 9): TierHot}
	trans := PlanTiers(now, cfg, existing, current)
	// yalnız 2026-06 değişmeli (hot→warm)
	if len(trans) != 1 {
		t.Fatalf("yalnız 1 geçiş beklenir, %d: %+v", len(trans), trans)
	}
	if trans[0].Month != mon(2026, 6) || trans[0].From != TierHot || trans[0].To != TierWarm {
		t.Fatalf("hatalı geçiş: %+v", trans[0])
	}
	if trans[0].Partition != "event_logs_2026_06" {
		t.Errorf("partition adı: %q", trans[0].Partition)
	}
}

func TestPlanTiersNilCurrentAllTargets(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	cfg := TierConfig{HotDays: 30, WarmDays: 90, ColdDays: 365}
	existing := []time.Time{mon(2026, 9), mon(2026, 6)}
	trans := PlanTiers(now, cfg, existing, nil)
	if len(trans) != 2 {
		t.Fatalf("nil current → tüm partition'lar için geçiş: %d", len(trans))
	}
	// ay sırasıyla (en eski önce)
	if !trans[0].Month.Before(trans[1].Month) {
		t.Error("geçişler ay sırasıyla dönmeli")
	}
}

func TestNormalize(t *testing.T) {
	c := TierConfig{HotDays: 100, WarmDays: 50, ColdDays: 10}.Normalize()
	if c.WarmDays != 100 || c.ColdDays != 100 {
		t.Errorf("eşikler artan olmalı: %+v", c)
	}
}

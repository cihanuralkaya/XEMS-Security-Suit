package retention

import (
	"sort"
	"time"
)

// tier.go — OLAY DEPOLAMA YAŞAM-DÖNGÜSÜ: HOT / WARM / COLD / DROP katmanlaması (§39).
// Aylık partition'lar yaşlarına göre katmanlara ayrılır; böylece sık erişilen taze
// veri hızlı depoda (hot), eskiyen veri ucuz/sıkıştırılmış depoda (warm→cold) tutulur
// ve saklama süresi dolanlar düşürülür. Planlama SAF/deterministiktir; fiziksel
// taşıma (tablespace/DETACH/arşiv) çağırana/DDL'e bırakılır (bkz. docs/STATUS.md).

// Tier, bir partition'ın depolama katmanıdır.
type Tier string

const (
	TierHot  Tier = "hot"  // taze, sık erişilen — hızlı depo
	TierWarm Tier = "warm" // eskiyen — ucuz/sıkıştırılmış depo
	TierCold Tier = "cold" // arşiv — nadiren erişilen
	TierDrop Tier = "drop" // saklama süresi doldu — düşürülecek
)

// TierConfig, katman eşiklerini GÜN cinsinden tutar. Bir partition'ın YAŞı
// (now - partition sonu) eşikle karşılaştırılır:
//   - yaş <= HotDays            → hot
//   - HotDays < yaş <= WarmDays → warm
//   - WarmDays < yaş <= ColdDays→ cold
//   - yaş > ColdDays            → drop (saklama sonu)
//
// ColdDays, etkin saklama süresidir (bunun ötesi düşürülür). Eşikler artan olmalıdır;
// değilse Normalize düzeltir.
type TierConfig struct {
	HotDays  int
	WarmDays int
	ColdDays int
}

// Normalize, eşiklerin artan (hot<=warm<=cold) olmasını sağlar.
func (c TierConfig) Normalize() TierConfig {
	if c.WarmDays < c.HotDays {
		c.WarmDays = c.HotDays
	}
	if c.ColdDays < c.WarmDays {
		c.ColdDays = c.WarmDays
	}
	return c
}

// Transition, bir partition'ın katman değişimidir (planlanan eylem).
type Transition struct {
	Month     time.Time // partition ay-başlangıcı
	Partition string    // partition tablo adı
	From      Tier      // mevcut (bilinen) katman; bilinmiyorsa ""
	To        Tier      // hedef katman
}

// classify, bir ay-partition'ının katmanını yaşına göre döner. Yaş, partition'ın
// SONU (bir sonraki ay başı) ile now arasındaki gündür — böylece ay tamamen
// geçmeden yaşlanmış sayılmaz (muhafazakâr).
func classify(now, month time.Time, c TierConfig) Tier {
	end := month.AddDate(0, 1, 0)
	ageDays := int(now.UTC().Sub(end).Hours() / 24)
	switch {
	case ageDays <= c.HotDays:
		return TierHot
	case ageDays <= c.WarmDays:
		return TierWarm
	case ageDays <= c.ColdDays:
		return TierCold
	default:
		return TierDrop
	}
}

// ClassifyPartitions, mevcut partition'ları katmanlarına eşler (ay→Tier).
func ClassifyPartitions(now time.Time, cfg TierConfig, existing []time.Time) map[time.Time]Tier {
	cfg = cfg.Normalize()
	out := make(map[time.Time]Tier, len(existing))
	for _, e := range existing {
		m := MonthStart(e)
		out[m] = classify(now, m, cfg)
	}
	return out
}

// PlanTiers, her partition'ın HEDEF katmanına göre gereken geçişleri döner. current
// (ay→mevcut katman) verilirse yalnız DEĞİŞEN partition'lar için geçiş üretilir;
// nil ise tüm partition'lar için hedef katman geçişi üretilir. Sonuç ay sırasıyla döner.
func PlanTiers(now time.Time, cfg TierConfig, existing []time.Time, current map[time.Time]Tier) []Transition {
	cfg = cfg.Normalize()
	var out []Transition
	for _, e := range existing {
		m := MonthStart(e)
		to := classify(now, m, cfg)
		from := Tier("")
		if current != nil {
			if cur, ok := current[m]; ok {
				from = cur
				if cur == to {
					continue // değişiklik yok
				}
			}
		}
		out = append(out, Transition{Month: m, Partition: PartitionName(m), From: from, To: to})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Month.Before(out[j].Month) })
	return out
}

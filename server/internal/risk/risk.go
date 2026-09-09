// Package risk, çok-faktörlü bir RİSK SKORLAMA motorudur. Tek başına önem düzeyi
// (severity) yetersizdir; gerçek risk, varlığın kritikliği, maruziyeti (exposure),
// tespitin güveni (confidence) ve istismar-edilebilirliği (exploitability) ile
// ölçeklenir. Bu paket SAF ve testlidir; girdi sinyalleri çağıran katmanda
// (mevcut olay/uyum/zafiyet verisinden) toplanır.
package risk

import "sort"

// Severity ağırlıkları (0-100 taban risk).
var severityWeight = map[string]float64{
	"INFO": 5, "LOW": 20, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 90,
}

// Factors, tek bir bulgunun risk faktörleridir.
type Factors struct {
	Severity         string  // INFO..CRITICAL
	AssetCriticality int     // 1..5 (3 = nötr); varlığın iş-kritikliği
	Exposure         int     // 0..3 (0 iç ağ, 3 internete açık)
	Confidence       float64 // 0..1 (tespit güveni)
	Exploitability   float64 // 0..1 (bilinen istismar / kolaylık)
}

// clampf, bir değeri [lo,hi] aralığına sıkıştırır.
func clampf(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// assetFactor, varlık kritikliğini (1..5) bir çarpana (0.6..1.4) eşler; 3 = 1.0.
func assetFactor(c int) float64 {
	if c <= 0 {
		c = 3 // belirtilmemiş → nötr
	}
	if c > 5 {
		c = 5
	}
	return 0.6 + 0.2*float64(c-1) // 1→0.6, 3→1.0, 5→1.4
}

// Score, tek bir bulgunun risk skorunu (0-100 tamsayı) hesaplar.
//
//	taban = severityWeight
//	taban *= assetFactor(criticality)      // 0.6..1.4
//	taban += exposure*5                     // 0..15 maruziyet eklentisi
//	taban += exploitability*15              // 0..15 istismar eklentisi
//	taban *= (0.5 + 0.5*confidence)         // düşük güven riski yarıya indirir
func Score(f Factors) int {
	base := severityWeight[f.Severity]
	base *= assetFactor(f.AssetCriticality)
	if f.Exposure > 0 {
		base += clampf(float64(f.Exposure), 0, 3) * 5
	}
	base += clampf(f.Exploitability, 0, 1) * 15
	conf := f.Confidence
	if conf <= 0 {
		conf = 1 // belirtilmemiş → tam güven
	}
	base *= 0.5 + 0.5*clampf(conf, 0, 1)
	return int(clampf(base+0.5, 0, 100)) // yuvarla + sıkıştır
}

// Aggregate, bir varlığın BİRDEN ÇOK bulgusundan tek bir risk skoru üretir. En
// yüksek bulgu baskındır; ek bulgular azalan katkı yapar (doygunluk) — böylece çok
// sayıda düşük-riskli bulgu, tek bir kritik bulgunun üstüne saturasyonla eklenir.
// Sonuç 0-100 ile sınırlıdır.
func Aggregate(scores []int) int {
	if len(scores) == 0 {
		return 0
	}
	s := append([]int(nil), scores...)
	sort.Sort(sort.Reverse(sort.IntSlice(s)))
	total := float64(s[0])
	weight := 0.35
	for i := 1; i < len(s); i++ {
		total += float64(s[i]) * weight
		weight *= 0.5 // her ek bulgunun katkısı yarılanır
	}
	return int(clampf(total, 0, 100))
}

// Band, sayısal skoru insan-okunur bir risk bandına çevirir (konsol rozeti).
func Band(score int) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 35:
		return "MEDIUM"
	case score >= 15:
		return "LOW"
	default:
		return "INFO"
	}
}

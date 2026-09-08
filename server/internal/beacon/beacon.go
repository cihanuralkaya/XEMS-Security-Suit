// Package beacon, ağ-bağlantı telemetrisi (netconn) geçmişinde C2 "beacon"
// periyodikliğini tespit eder: bir (cihaz, uzak-IP) çifti düzenli aralıklarla,
// DÜŞÜK JITTER ile bağlanıyorsa klasik komuta-kontrol imzasıdır. netconn bilinen
// IP'leri (IoC) yakalar; beacon analizi BİLİNMEYEN C2'yi (gösterge olmadan)
// yakalar — yüksek savunma değeri.
//
// Saf istatistik (anomaly deseniyle aynı yaklaşım): aralıkların değişim katsayısı
// (CoV = stddev/ortalama) eşiğin altındaysa ve yeterli örnek varsa beacon adayı.
package beacon

import (
	"math"
	"sort"
	"time"
)

// Conn, tek bir giden bağlantı gözlemidir (netconn olayından türetilir).
type Conn struct {
	DeviceID string
	RemoteIP string
	At       time.Time
}

// Finding, olası bir beacon bulgusudur.
type Finding struct {
	DeviceID     string
	RemoteIP     string
	Count        int           // gözlem sayısı
	MeanInterval time.Duration // ortalama bağlantı aralığı
	CoV          float64       // değişim katsayısı (düşük = düzenli = beacon)
}

// Analyze, bağlantıları (cihaz, uzak-IP) çiftine gruplar ve düzenli-aralıklı
// (düşük-CoV) çiftleri beacon adayı olarak döner. minSamples'tan az gözlemli ya da
// CoV > maxCoV olan çiftler elenir. Sonuç deterministik (cihaz+IP'ye göre sıralı).
func Analyze(conns []Conn, minSamples int, maxCoV float64) []Finding {
	if minSamples < 3 {
		minSamples = 3 // aralık istatistiği için en az 3 gözlem (2 aralık)
	}
	groups := map[string][]time.Time{}
	keyDev := map[string][2]string{}
	for _, c := range conns {
		if c.RemoteIP == "" {
			continue
		}
		k := c.DeviceID + "|" + c.RemoteIP
		groups[k] = append(groups[k], c.At)
		keyDev[k] = [2]string{c.DeviceID, c.RemoteIP}
	}
	var out []Finding
	for k, times := range groups {
		if len(times) < minSamples {
			continue
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		// Ardışık aralıklar (saniye).
		var intervals []float64
		for i := 1; i < len(times); i++ {
			d := times[i].Sub(times[i-1]).Seconds()
			if d > 0 {
				intervals = append(intervals, d)
			}
		}
		if len(intervals) < minSamples-1 {
			continue
		}
		mean, cov := meanCoV(intervals)
		if mean <= 0 || cov > maxCoV {
			continue
		}
		out = append(out, Finding{
			DeviceID:     keyDev[k][0],
			RemoteIP:     keyDev[k][1],
			Count:        len(times),
			MeanInterval: time.Duration(mean * float64(time.Second)),
			CoV:          cov,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceID != out[j].DeviceID {
			return out[i].DeviceID < out[j].DeviceID
		}
		return out[i].RemoteIP < out[j].RemoteIP
	})
	return out
}

// meanCoV, örneklerin ortalamasını ve değişim katsayısını (stddev/mean) döner.
func meanCoV(xs []float64) (mean, cov float64) {
	if len(xs) == 0 {
		return 0, math.Inf(1)
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	if mean == 0 {
		return 0, math.Inf(1)
	}
	var ss float64
	for _, x := range xs {
		d := x - mean
		ss += d * d
	}
	std := math.Sqrt(ss / float64(len(xs)))
	return mean, std / mean
}

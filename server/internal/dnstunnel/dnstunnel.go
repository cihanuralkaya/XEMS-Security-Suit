// Package dnstunnel, DNS TÜNELLEME / DNS ÜZERİNDEN VERİ SIZDIRMA tespiti sağlar:
// bir uç nokta kısa bir pencerede TEK bir üst (kayıtlı) alan adının ÇOK SAYIDA farklı
// ALT alanını sorguladığında, bu klasik bir DNS-tüneli (veriyi alt-alan etiketlerine
// kodlama) imzasıdır. Beacon periyodikliği ve yanal-hareket fan-out'undan FARKLI bir
// sinyaldir. Saf istatistik, testli; DNS olay verisi (agent dnsmon telemetrisi) girdi.
package dnstunnel

import (
	"sort"
	"strings"
	"time"
)

// Query, tek bir DNS sorgu gözlemidir (agent DNS olayından türetilir).
type Query struct {
	DeviceID string
	Domain   string // tam sorgulanan alan (ör. "aGVsbG8.data.evil.com")
	At       time.Time
}

// Finding, olası bir DNS-tüneli bulgusudur.
type Finding struct {
	DeviceID           string
	Parent             string // üst (kayıtlı) alan (ör. "evil.com")
	DistinctSubdomains int    // pencerede bu üst alan altındaki farklı tam alan sayısı
	Window             time.Duration
}

// registeredDomain, bir alan adının son iki etiketini (yaklaşık kayıtlı alan; PSL
// olmadan) döner: "a.b.evil.com" → "evil.com". Tek etiket ise kendisi.
func registeredDomain(d string) string {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	parts := strings.Split(d, ".")
	if len(parts) <= 2 {
		return d
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// Analyze, her (cihaz, üst-alan) için herhangi bir `window` uzunluğundaki kayan
// pencerede görülen AZAMİ farklı ALT alan sayısını hesaplar; bu sayı minSubdomains'i
// aşan çiftleri DNS-tüneli adayı olarak döner. Sonuç deterministik (cihaz+üst-alan).
func Analyze(queries []Query, minSubdomains int, window time.Duration) []Finding {
	if minSubdomains < 3 {
		minSubdomains = 3
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	type ev struct {
		full string
		at   time.Time
	}
	type key struct{ dev, parent string }
	groups := map[key][]ev{}
	for _, q := range queries {
		if q.Domain == "" {
			continue
		}
		parent := registeredDomain(q.Domain)
		full := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(q.Domain), "."))
		// Yalnız üst alandan DAHA derin (gerçek alt alan) sorguları say.
		if full == parent {
			continue
		}
		k := key{q.DeviceID, parent}
		groups[k] = append(groups[k], ev{full, q.At})
	}

	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].dev != keys[j].dev {
			return keys[i].dev < keys[j].dev
		}
		return keys[i].parent < keys[j].parent
	})

	var out []Finding
	for _, k := range keys {
		evs := groups[k]
		sort.Slice(evs, func(i, j int) bool { return evs[i].at.Before(evs[j].at) })
		best, lo := 0, 0
		counts := map[string]int{}
		for hi := 0; hi < len(evs); hi++ {
			counts[evs[hi].full]++
			for evs[hi].at.Sub(evs[lo].at) > window {
				counts[evs[lo].full]--
				if counts[evs[lo].full] == 0 {
					delete(counts, evs[lo].full)
				}
				lo++
			}
			if len(counts) > best {
				best = len(counts)
			}
		}
		if best >= minSubdomains {
			out = append(out, Finding{DeviceID: k.dev, Parent: k.parent, DistinctSubdomains: best, Window: window})
		}
	}
	return out
}

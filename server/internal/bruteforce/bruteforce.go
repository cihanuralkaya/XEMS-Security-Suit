// Package bruteforce, KABA-KUVVET / parola-püskürtme (password spraying) tespiti
// sağlar: tek bir kaynak ana bilgisayardan kısa bir pencerede ÇOK SAYIDA başarısız
// oturum-açma denemesi, klasik bir kimlik-bilgisi-erişimi (T1110) imzasıdır. Tek tek
// 4625/4771 olayları düşük önemli olsa da, bir SERİ (burst) tek bir yüksek-önemli
// kampanya bulgusuna toplanır. Saf istatistik — kayan-pencere, testli.
//
// Girdi, normalize edilmiş başarısız-oturum-açma olaylarıdır (Windows olay günlüğü
// alımından: 4625 failed logon, 4771 Kerberos pre-auth failed). Kaynak ana bilgisayar
// (DeviceID) başına gruplanır.
package bruteforce

import (
	"sort"
	"time"
)

// Attempt, tek bir başarısız oturum-açma denemesidir (kaynak + zaman).
type Attempt struct {
	DeviceID string
	At       time.Time
}

// Finding, olası bir kaba-kuvvet/püskürtme bulgusudur.
type Finding struct {
	DeviceID string        // kaynak ana bilgisayar
	Count    int           // penceredeki AZAMİ başarısız deneme sayısı
	Window   time.Duration // değerlendirme penceresi
}

// Analyze, her cihaz için herhangi bir `window` uzunluğundaki kayan pencerede
// gözlenen AZAMİ başarısız-deneme sayısını hesaplar; bu sayı minAttempts'i aşan
// cihazları olası kaba-kuvvet olarak döner. Sonuç deterministik (cihaz kimliğine
// göre sıralı). minAttempts<3 → 3; window<=0 → 5dk.
func Analyze(attempts []Attempt, minAttempts int, window time.Duration) []Finding {
	if minAttempts < 3 {
		minAttempts = 3
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	byDev := map[string][]time.Time{}
	for _, a := range attempts {
		byDev[a.DeviceID] = append(byDev[a.DeviceID], a.At)
	}

	devs := make([]string, 0, len(byDev))
	for d := range byDev {
		devs = append(devs, d)
	}
	sort.Strings(devs)

	var out []Finding
	for _, dev := range devs {
		ts := byDev[dev]
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		best, lo := 0, 0
		for hi := 0; hi < len(ts); hi++ {
			for ts[hi].Sub(ts[lo]) > window {
				lo++
			}
			if n := hi - lo + 1; n > best {
				best = n
			}
		}
		if best >= minAttempts {
			out = append(out, Finding{DeviceID: dev, Count: best, Window: window})
		}
	}
	return out
}

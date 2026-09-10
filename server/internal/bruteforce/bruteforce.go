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

// Attempt, tek bir başarısız oturum-açma denemesidir (kaynak + zaman). SourceIP ve
// TargetUser opsiyoneldir (Windows EventData zenginleştirmesinden gelir).
type Attempt struct {
	DeviceID   string
	At         time.Time
	SourceIP   string // opsiyonel — saldırgan IP (4625 IpAddress)
	TargetUser string // opsiyonel — hedeflenen hesap (4625 TargetUserName)
}

// Finding, olası bir kaba-kuvvet/püskürtme bulgusudur.
type Finding struct {
	DeviceID        string        // kaynak ana bilgisayar
	Count           int           // penceredeki AZAMİ başarısız deneme sayısı
	Window          time.Duration // değerlendirme penceresi
	DistinctSources int           // farklı saldırgan IP sayısı
	DistinctTargets int           // hedeflenen farklı hesap sayısı
	TopSource       string        // en çok görülen saldırgan IP (öznitelik)
}

// LogonEvent, başarılı ya da başarısız bir oturum-açma olayıdır (başarı-serisi
// tespiti için). SourceIP opsiyoneldir.
type LogonEvent struct {
	DeviceID string
	At       time.Time
	SourceIP string
	Success  bool
}

// SuccessFinding, olası BAŞARILI bir kaba-kuvvettir: bir başarılı oturum açma, aynı
// ana bilgisayarda kısa pencerede çok sayıda BAŞARISIZ denemenin ARDINDAN gelmiştir —
// klasik "hesap ele geçirildi" sinyali (T1110 → geçerli hesaplar).
type SuccessFinding struct {
	DeviceID       string
	SourceIP       string    // başarılı oturumun kaynak IP'si (öznitelik)
	FailuresBefore int       // başarıdan önce penceredeki başarısız deneme sayısı
	At             time.Time // başarılı oturum zamanı
}

// AnalyzeSuccessAfterBurst, her cihaz için, penceresinde >= minFailures başarısız
// denemenin ardından gelen İLK başarılı oturum açmayı olası başarılı-kaba-kuvvet olarak
// döner (cihaz başına bir kez). Eşleşme ana bilgisayar (DeviceID) düzeyindedir; başarılı
// oturumun kaynak IP'si öznitelik olarak taşınır. Saf, kayan-pencere O(n). Deterministik
// (cihaz kimliğine göre sıralı). minFailures<3 → 3; window<=0 → 5dk.
func AnalyzeSuccessAfterBurst(evs []LogonEvent, minFailures int, window time.Duration) []SuccessFinding {
	if minFailures < 3 {
		minFailures = 3
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	byDev := map[string][]LogonEvent{}
	for _, e := range evs {
		byDev[e.DeviceID] = append(byDev[e.DeviceID], e)
	}
	devs := make([]string, 0, len(byDev))
	for d := range byDev {
		devs = append(devs, d)
	}
	sort.Strings(devs)

	var out []SuccessFinding
	for _, dev := range devs {
		es := byDev[dev]
		sort.Slice(es, func(i, j int) bool { return es[i].At.Before(es[j].At) })
		lo, failCount := 0, 0
		for hi := 0; hi < len(es); hi++ {
			if !es[hi].Success {
				failCount++
			}
			for es[hi].At.Sub(es[lo].At) > window {
				if !es[lo].Success {
					failCount--
				}
				lo++
			}
			if es[hi].Success && failCount >= minFailures {
				out = append(out, SuccessFinding{
					DeviceID: dev, SourceIP: es[hi].SourceIP, FailuresBefore: failCount, At: es[hi].At,
				})
				break // cihaz başına ilk başarı yeterli
			}
		}
	}
	return out
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
	byDev := map[string][]Attempt{}
	for _, a := range attempts {
		byDev[a.DeviceID] = append(byDev[a.DeviceID], a)
	}

	devs := make([]string, 0, len(byDev))
	for d := range byDev {
		devs = append(devs, d)
	}
	sort.Strings(devs)

	var out []Finding
	for _, dev := range devs {
		as := byDev[dev]
		sort.Slice(as, func(i, j int) bool { return as[i].At.Before(as[j].At) })
		best, lo := 0, 0
		for hi := 0; hi < len(as); hi++ {
			for as[hi].At.Sub(as[lo].At) > window {
				lo++
			}
			if n := hi - lo + 1; n > best {
				best = n
			}
		}
		if best < minAttempts {
			continue
		}
		// Öznitelik: cihaz için (batch = tek pencere) farklı kaynak IP / hedef hesap
		// sayıları ve en sık saldırgan IP. Çok sayıda hedef → parola-püskürtme sinyali.
		srcCount := map[string]int{}
		targets := map[string]bool{}
		for _, a := range as {
			if a.SourceIP != "" {
				srcCount[a.SourceIP]++
			}
			if a.TargetUser != "" {
				targets[a.TargetUser] = true
			}
		}
		top, topN := "", 0
		for ip, n := range srcCount {
			if n > topN || (n == topN && ip < top) {
				top, topN = ip, n
			}
		}
		out = append(out, Finding{
			DeviceID: dev, Count: best, Window: window,
			DistinctSources: len(srcCount), DistinctTargets: len(targets), TopSource: top,
		})
	}
	return out
}

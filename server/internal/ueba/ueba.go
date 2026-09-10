// Package ueba, AYRICALIKLI KULLANICI (yönetici) DAVRANIŞ ANALİTİĞİ sağlar. Denetim
// izinden (audit log) her yöneticinin etkinlik profilini çıkarır ve anormal örüntüleri
// (kısa pencerede yıkıcı-eylem serisi, yüksek yıkıcı-eylem oranı) işaretler — ele
// geçmiş ya da kötü-niyetli bir yönetici hesabının erken tespiti (iç tehdit / UEBA).
//
// SAF ve testlidir; girdi denetim kayıtlarıdır (depo-bağımsız). Yeni veri gerekmez —
// mevcut audit_log (admin + action + created_at) üzerine çalışır.
package ueba

import (
	"sort"
	"strings"
	"time"
)

// Entry, tek bir denetim kaydının analiz için ham biçimidir.
type Entry struct {
	Admin  string
	Action string
	At     time.Time
}

// destructiveKeywords, yıkıcı/yüksek-etkili eylemleri tanır (action string'inde
// büyük-harf alt-dize). Bu eylemlerin serisi ele geçmiş hesabın güçlü işaretidir.
var destructiveKeywords = []string{"WIPE", "QUARANTINE", "DELETE", "REVOKE", "LOCK", "RESTART", "OFFBOARD", "PURGE", "DISABLE"}

// IsDestructive, bir eylemin yıkıcı/yüksek-etkili olup olmadığını döner.
func IsDestructive(action string) bool {
	a := strings.ToUpper(action)
	for _, k := range destructiveKeywords {
		if strings.Contains(a, k) {
			return true
		}
	}
	return false
}

// Profile, tek bir yöneticinin etkinlik profilidir.
type Profile struct {
	Admin       string    `json:"admin"`
	Total       int       `json:"total"`
	Destructive int       `json:"destructive"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
}

// Finding, bir davranış anomalisidir.
type Finding struct {
	Admin    string `json:"admin"`
	Severity string `json:"severity"` // HIGH | MEDIUM
	Reason   string `json:"reason"`
}

// Report, UEBA analizinin sonucudur.
type Report struct {
	Profiles []Profile `json:"profiles"`
	Findings []Finding `json:"findings"`
}

// Options, anomali eşikleridir.
type Options struct {
	BurstThreshold   int           // pencerede bu kadar yıkıcı eylem → HIGH
	BurstWindow      time.Duration // yıkıcı-eylem serisi penceresi
	MinTotalForRatio int           // oran değerlendirmesi için asgari toplam eylem
	RatioThreshold   float64       // yıkıcı/toplam bu oranı aşarsa → MEDIUM
}

// DefaultOptions, makul varsayılan eşikler.
func DefaultOptions() Options {
	return Options{BurstThreshold: 5, BurstWindow: 10 * time.Minute, MinTotalForRatio: 10, RatioThreshold: 0.5}
}

// Analyze, denetim kayıtlarından yönetici profillerini ve anomalileri hesaplar.
// SAF fonksiyon. opts sıfır alanları DefaultOptions ile doldurulur.
func Analyze(entries []Entry, opts Options) Report {
	d := DefaultOptions()
	if opts.BurstThreshold <= 0 {
		opts.BurstThreshold = d.BurstThreshold
	}
	if opts.BurstWindow <= 0 {
		opts.BurstWindow = d.BurstWindow
	}
	if opts.MinTotalForRatio <= 0 {
		opts.MinTotalForRatio = d.MinTotalForRatio
	}
	if opts.RatioThreshold <= 0 {
		opts.RatioThreshold = d.RatioThreshold
	}

	type acc struct {
		prof     Profile
		destTime []time.Time
	}
	byAdmin := map[string]*acc{}
	for _, e := range entries {
		if e.Admin == "" {
			continue
		}
		a := byAdmin[e.Admin]
		if a == nil {
			a = &acc{prof: Profile{Admin: e.Admin, First: e.At, Last: e.At}}
			byAdmin[e.Admin] = a
		}
		a.prof.Total++
		if e.At.Before(a.prof.First) {
			a.prof.First = e.At
		}
		if e.At.After(a.prof.Last) {
			a.prof.Last = e.At
		}
		if IsDestructive(e.Action) {
			a.prof.Destructive++
			a.destTime = append(a.destTime, e.At)
		}
	}

	var rep Report
	admins := make([]string, 0, len(byAdmin))
	for k := range byAdmin {
		admins = append(admins, k)
	}
	sort.Strings(admins)
	for _, name := range admins {
		a := byAdmin[name]
		rep.Profiles = append(rep.Profiles, a.prof)
		// Yıkıcı-eylem serisi (burst): pencerede eşik veya üstü → HIGH.
		if n := maxInWindow(a.destTime, opts.BurstWindow); n >= opts.BurstThreshold {
			rep.Findings = append(rep.Findings, Finding{
				Admin: name, Severity: "HIGH",
				Reason: "kısa pencerede " + itoa(n) + " yıkıcı eylem (olası ele geçmiş/kötü-niyetli hesap)",
			})
		} else if a.prof.Total >= opts.MinTotalForRatio &&
			float64(a.prof.Destructive)/float64(a.prof.Total) >= opts.RatioThreshold {
			// Yüksek yıkıcı-eylem oranı → MEDIUM.
			rep.Findings = append(rep.Findings, Finding{
				Admin: name, Severity: "MEDIUM",
				Reason: "yüksek yıkıcı-eylem oranı (" + itoa(a.prof.Destructive) + "/" + itoa(a.prof.Total) + ")",
			})
		}
	}
	return rep
}

// maxInWindow, sıralı olmayan zaman damgalarında herhangi bir `window` uzunluğundaki
// kayan pencereye düşen AZAMİ olay sayısını döner.
func maxInWindow(times []time.Time, window time.Duration) int {
	if len(times) == 0 {
		return 0
	}
	ts := append([]time.Time(nil), times...)
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
	return best
}

// itoa, küçük pozitif tamsayı → string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

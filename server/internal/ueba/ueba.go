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
	// Varlık (entity) sinyalleri — opsiyonel; boş bırakılırsa ilgili anomali atlanır (§28).
	Device   string // eylemin geldiği cihaz/kaynak
	Location string // coğrafi/ağ konumu (ör. ülke/şube)
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
	OffHours    int       `json:"off_hours,omitempty"`     // mesai-dışı eylem sayısı (§28)
	NewDevices  int       `json:"new_devices,omitempty"`   // bilinmeyen cihazdan eylem sayısı
	NewLocs     int       `json:"new_locations,omitempty"` // bilinmeyen konumdan eylem sayısı
	RiskScore   int       `json:"risk_score"`              // 0..100 türetilmiş kullanıcı riski
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
	// Varlık-davranışı seçenekleri (§28) — opsiyonel:
	BusinessStartHour int // mesai başlangıcı (UTC saat, 0-23). Start==End ise mesai-dışı devre dışı.
	BusinessEndHour   int // mesai bitişi (UTC saat, 0-23; hariç)
	// KnownDevices/KnownLocations: admin → bilinen küme. Verilmezse ilgili anomali atlanır.
	KnownDevices   map[string]map[string]bool
	KnownLocations map[string]map[string]bool
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
		// Varlık anomalileri (§28): mesai-dışı, bilinmeyen cihaz/konum.
		if offHours(e.At, opts) {
			a.prof.OffHours++
		}
		if e.Device != "" && known(opts.KnownDevices, e.Admin) && !opts.KnownDevices[e.Admin][e.Device] {
			a.prof.NewDevices++
		}
		if e.Location != "" && known(opts.KnownLocations, e.Admin) && !opts.KnownLocations[e.Admin][e.Location] {
			a.prof.NewLocs++
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
		burst := maxInWindow(a.destTime, opts.BurstWindow)
		// Yıkıcı-eylem serisi (burst): pencerede eşik veya üstü → HIGH.
		if burst >= opts.BurstThreshold {
			rep.Findings = append(rep.Findings, Finding{
				Admin: name, Severity: "HIGH",
				Reason: "kısa pencerede " + itoa(burst) + " yıkıcı eylem (olası ele geçmiş/kötü-niyetli hesap)",
			})
		} else if a.prof.Total >= opts.MinTotalForRatio &&
			float64(a.prof.Destructive)/float64(a.prof.Total) >= opts.RatioThreshold {
			// Yüksek yıkıcı-eylem oranı → MEDIUM.
			rep.Findings = append(rep.Findings, Finding{
				Admin: name, Severity: "MEDIUM",
				Reason: "yüksek yıkıcı-eylem oranı (" + itoa(a.prof.Destructive) + "/" + itoa(a.prof.Total) + ")",
			})
		}
		// Varlık-davranışı anomalileri (§28).
		if a.prof.NewDevices > 0 {
			rep.Findings = append(rep.Findings, Finding{Admin: name, Severity: "MEDIUM",
				Reason: "bilinmeyen cihazdan " + itoa(a.prof.NewDevices) + " eylem"})
		}
		if a.prof.NewLocs > 0 {
			rep.Findings = append(rep.Findings, Finding{Admin: name, Severity: "MEDIUM",
				Reason: "bilinmeyen konumdan " + itoa(a.prof.NewLocs) + " eylem"})
		}
		if a.prof.OffHours > 0 && a.prof.Destructive > 0 {
			rep.Findings = append(rep.Findings, Finding{Admin: name, Severity: "MEDIUM",
				Reason: "mesai-dışı " + itoa(a.prof.OffHours) + " eylem (yıkıcı etkinlikle birlikte)"})
		}
		a.prof.RiskScore = riskScore(a.prof, burst, opts.BurstThreshold)
		rep.Profiles = append(rep.Profiles, a.prof)
	}
	return rep
}

// offHours, bir zamanın mesai saatleri DIŞINDA olup olmadığını döner. Start==End ise
// mesai-dışı tespiti devre dışıdır (false). Pencere Start(dahil)..End(hariç), UTC.
func offHours(t time.Time, opts Options) bool {
	if opts.BusinessStartHour == opts.BusinessEndHour {
		return false
	}
	h := t.UTC().Hour()
	if opts.BusinessStartHour < opts.BusinessEndHour {
		return h < opts.BusinessStartHour || h >= opts.BusinessEndHour
	}
	// Gece aşan pencere (ör. 22..6): mesai içi = h>=Start || h<End.
	return !(h >= opts.BusinessStartHour || h < opts.BusinessEndHour)
}

func known(m map[string]map[string]bool, admin string) bool {
	_, ok := m[admin]
	return ok
}

// riskScore, profil sinyallerinden 0..100 türetilmiş kullanıcı riski hesaplar (§28).
// Sinyaller ağırlıklandırılır ve tavanlanır.
func riskScore(p Profile, burst, burstThreshold int) int {
	score := 0
	if burstThreshold > 0 && burst >= burstThreshold {
		score += 50
	}
	if p.Total > 0 {
		score += int(float64(p.Destructive) / float64(p.Total) * 25)
	}
	score += p.NewDevices * 10
	score += p.NewLocs * 10
	score += p.OffHours * 3
	if score > 100 {
		score = 100
	}
	return score
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

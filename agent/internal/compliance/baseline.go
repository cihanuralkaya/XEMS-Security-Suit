package compliance

// Bu dosya, ham uyum sinyallerini (disk şifreleme, güvenlik duvarı) CIS-tarzı bir
// GÜVENLİK TABANI (baseline) değerlendirmesine çevirir: her denetim adlandırılmış
// bir kontroldür (ID + başlık + önem), geçti/kaldı/bilinmiyor sonucu üretir ve bir
// uyum SKORU hesaplanır. Bu katman saf/testlidir; OS sorgusu Checker'a (platform
// dosyaları) bırakılır. Kontrol kataloğu, yeni güvenilir sinyaller eklendikçe
// genişletilebilir (Checker'a yeni metot + katalog satırı).

// Status, tek bir CIS kontrolünün sonucudur.
type Status string

const (
	StatusPass    Status = "pass"    // kontrol karşılandı
	StatusFail    Status = "fail"    // kontrol ihlal edildi (uyumsuz)
	StatusUnknown Status = "unknown" // durum belirlenemedi (skora dahil edilmez)
)

// Önem seviyeleri (bir kontrolün başarısızlığının ağırlığı).
const (
	SevHigh   = "HIGH"
	SevMedium = "MEDIUM"
	SevLow    = "LOW"
)

// Check, tek bir CIS-tarzı kontrolün değerlendirme sonucudur.
type Check struct {
	ID       string `json:"id"`       // ör. "CIS-1.1"
	Title    string `json:"title"`    // insan-okunur başlık
	Severity string `json:"severity"` // HIGH | MEDIUM | LOW
	Status   Status `json:"status"`   // pass | fail | unknown
	Detail   string `json:"detail"`   // ham sinyal (ör. "off")
}

// Report, tüm taban değerlendirmesinin sonucudur.
type Report struct {
	Checks  []Check `json:"checks"`
	Passed  int     `json:"passed"`
	Failed  int     `json:"failed"`
	Unknown int     `json:"unknown"`
}

// ScorePct, uyum skorunu yüzde olarak döner: geçen / (geçen + kalan) * 100.
// Bilinmeyen kontroller paydaya DAHİL EDİLMEZ (durum belirlenemediyse cezalandırma
// yok). Değerlendirilebilir kontrol yoksa 100 döner (bilinen ihlal yok).
func (r Report) ScorePct() int {
	denom := r.Passed + r.Failed
	if denom == 0 {
		return 100
	}
	return r.Passed * 100 / denom
}

// HasFailure, HIGH veya MEDIUM önemli herhangi bir kontrol başarısızsa true döner
// (güvenlik-duruşu ihlali eşiği). Yalnız LOW başarısızlık duruş uyarısı sayılmaz.
func (r Report) HasFailure() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail && (c.Severity == SevHigh || c.Severity == SevMedium) {
			return true
		}
	}
	return false
}

// FailedTitles, başarısız (fail) kontrollerin başlıklarını döner (olay mesajı için).
func (r Report) FailedTitles() []string {
	var out []string
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			out = append(out, c.Title)
		}
	}
	return out
}

// statusFor, bir "on/off/unknown" ham sinyalini Status'a çevirir.
func statusFor(signal, on, off string) Status {
	switch signal {
	case on:
		return StatusPass
	case off:
		return StatusFail
	default:
		return StatusUnknown
	}
}

// Evaluate, Checker sinyallerini CIS-tarzı bir taban raporuna çevirir. Kontrol
// kataloğu burada tanımlıdır (ID + başlık + önem); sıralama kararlıdır.
func Evaluate(chk Checker) Report {
	catalog := []struct {
		id, title, sev string
		signal         string
		on, off        string
	}{
		{"CIS-1.1", "Sistem diski şifrelemesi etkin", SevHigh, chk.DiskEncryption(), EncOn, EncOff},
		{"CIS-9.1", "Ana bilgisayar güvenlik duvarı etkin", SevHigh, chk.Firewall(), FwOn, FwOff},
	}

	r := Report{}
	for _, c := range catalog {
		st := statusFor(c.signal, c.on, c.off)
		switch st {
		case StatusPass:
			r.Passed++
		case StatusFail:
			r.Failed++
		default:
			r.Unknown++
		}
		r.Checks = append(r.Checks, Check{
			ID: c.id, Title: c.title, Severity: c.sev, Status: st, Detail: c.signal,
		})
	}
	return r
}

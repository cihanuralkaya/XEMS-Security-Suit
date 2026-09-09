package notify

import (
	"strings"
	"sync"
	"time"
)

// Bu dosya, bildirim YÖNLENDİRME (routing) ve YÜKSELTME (escalation) sağlar:
//   - Route: bir hedef notifier'a yalnız EŞLEŞEN uyarıları geçiren kural
//     (min önem + kategori + ATT&CK tekniği süzgeci).
//   - Router: bir uyarıyı eşleşen tüm rotalara dağıtan fan-out (Notifier).
//   - Escalator: bir anahtar (cihaz|kategori) için pencere içinde tekrarlayan
//     yüksek-önem uyarıları eşiği aşınca CRITICAL "ESCALATED" uyarısına yükseltir
//     (on-call'a sayfa atma deseni). Saf/testli (saat enjekte edilebilir).

// set, küçük harfe normalize edilmiş bir üyelik kümesidir.
func newSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, s := range items {
		if s = strings.ToUpper(strings.TrimSpace(s)); s != "" {
			m[s] = true
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// Route, bir hedef notifier'a hangi uyarıların gideceğini belirleyen kuraldır.
type Route struct {
	Name       string
	minSev     int
	categories map[string]bool // boş → hepsi
	techniques map[string]bool // boş → hepsi
	target     Notifier
}

// NewRoute, bir yönlendirme kuralı oluşturur. minSeverity boşsa süzgeç yoktur
// (rank 0); categories/techniques boşsa o boyutta süzgeç yoktur.
func NewRoute(name, minSeverity string, categories, techniques []string, target Notifier) Route {
	return Route{
		Name:       name,
		minSev:     sevRank(minSeverity),
		categories: newSet(categories),
		techniques: newSet(techniques),
		target:     target,
	}
}

// Matches, uyarının bu rotanın kurallarına uyup uymadığını döner (saf).
func (r Route) Matches(a Alert) bool {
	if sevRank(a.Severity) < r.minSev {
		return false
	}
	if r.categories != nil && !r.categories[strings.ToUpper(a.Category)] {
		return false
	}
	if r.techniques != nil && !r.techniques[strings.ToUpper(a.TechniqueID)] {
		return false
	}
	return true
}

// Router, bir uyarıyı eşleşen TÜM rotaların hedeflerine dağıtır (fan-out).
type Router struct{ routes []Route }

// NewRouter, hedefi nil olmayan rotalardan bir yönlendirici oluşturur.
func NewRouter(routes ...Route) *Router {
	var kept []Route
	for _, r := range routes {
		if r.target != nil {
			kept = append(kept, r)
		}
	}
	return &Router{routes: kept}
}

// Notify, uyarıyı eşleşen her rotaya iletir.
func (r *Router) Notify(a Alert) {
	for _, rt := range r.routes {
		if rt.Matches(a) {
			rt.target.Notify(a)
		}
	}
}

// Len, rota sayısını döner.
func (r *Router) Len() int { return len(r.routes) }

// Escalator, bir hedef notifier'ı sarar: her uyarıyı OLDUĞU GİBİ iletir, ayrıca
// aynı anahtar (cihaz|kategori) için `window` içinde `threshold` veya daha çok
// uyarı birikirse, hedefe bir kez CRITICAL "ESCALATED" uyarısı gönderir. Yalnız
// `minSev` ve üstündeki uyarılar sayılır. Aynı anahtar için pencere başına bir
// kez yükseltir (gürültü azaltma).
type Escalator struct {
	target    Notifier
	minSev    int
	threshold int
	window    time.Duration
	now       func() time.Time

	mu      sync.Mutex
	times   map[string][]time.Time
	lastEsc map[string]time.Time
}

// NewEscalator oluşturur. threshold<=0 veya window<=0 ise yükseltme etkin değildir
// (yalnız iletim). now nil ise time.Now kullanılır.
func NewEscalator(target Notifier, minSeverity string, threshold int, window time.Duration, now func() time.Time) *Escalator {
	if now == nil {
		now = time.Now
	}
	ms := sevRank(minSeverity)
	if ms == 0 {
		ms = sevRank("HIGH")
	}
	return &Escalator{
		target: target, minSev: ms, threshold: threshold, window: window, now: now,
		times: map[string][]time.Time{}, lastEsc: map[string]time.Time{},
	}
}

func escKey(a Alert) string { return a.DeviceID + "|" + a.Category }

// Notify, uyarıyı iletir ve gerekiyorsa yükseltir.
func (e *Escalator) Notify(a Alert) {
	if e.target != nil {
		e.target.Notify(a)
	}
	if e.threshold <= 0 || e.window <= 0 {
		return
	}
	if sevRank(a.Severity) < e.minSev {
		return
	}
	if esc, ok := e.record(a); ok {
		e.target.Notify(esc)
	}
}

// record, uyarıyı pencereye kaydeder ve eşik aşıldıysa yükseltme uyarısını + true
// döner (pencere başına bir kez). Saat enjekte edilebilir olduğundan testlidir.
func (e *Escalator) record(a Alert) (Alert, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	k := escKey(a)
	now := e.now()
	cutoff := now.Add(-e.window)

	// Pencere dışını buda + bu uyarıyı ekle.
	kept := e.times[k][:0]
	for _, t := range e.times[k] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	e.times[k] = kept

	if len(kept) < e.threshold {
		return Alert{}, false
	}
	// Pencere başına bir kez: son yükseltme hâlâ pencere içindeyse tekrar etme.
	if last, ok := e.lastEsc[k]; ok && last.After(cutoff) {
		return Alert{}, false
	}
	e.lastEsc[k] = now

	esc := a
	esc.Severity = "CRITICAL"
	esc.Message = "ESCALATED (" + itoa(len(kept)) + "x): " + a.Message
	return esc, true
}

// itoa, küçük pozitif tamsayı → string (strconv'a bağımlılık olmadan).
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

package correlate

import (
	"sort"
	"sync"
	"time"
)

// Bu dosya, ÇOK-SİNYAL (multi-signal) korelasyon sağlar (gelişmiş korelasyon):
// tek bir tespit tek başına düşük güven taşıyabilir, ancak aynı cihazda kısa bir
// pencerede BİRDEN ÇOK FARKLI sinyal (ör. şüpheli süreç + ağ bağlantısı + IoC +
// kalıcılık) birikirse bu YÜKSEK GÜVENLİ bir saldırı zinciridir. ChainDetector
// bunu tespit eder ve pencere başına bir kez tetikler. Saf/testli (saat enjekte).

type chainState struct {
	signals map[string]time.Time // farklı sinyal → son görülme
	firedAt time.Time            // son tetikleme (pencere başına bir kez)
}

// ChainDetector, cihaz başına farklı sinyalleri bir pencerede sayar ve eşik
// aşılınca yüksek-güvenli zincir tetikler.
type ChainDetector struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	now       func() time.Time
	devs      map[string]*chainState
}

// NewChainDetector oluşturur. window<=0 → 15dk; threshold<=0 → 3; now nil → time.Now.
func NewChainDetector(window time.Duration, threshold int, now func() time.Time) *ChainDetector {
	if window <= 0 {
		window = 15 * time.Minute
	}
	if threshold <= 0 {
		threshold = 3
	}
	if now == nil {
		now = time.Now
	}
	return &ChainDetector{window: window, threshold: threshold, now: now, devs: map[string]*chainState{}}
}

// Observe, bir cihaz için bir sinyal (teknik/kategori/aşama etiketi) kaydeder.
// Pencerede FARKLI sinyal sayısı eşiği aşarsa (ve bu pencerede henüz tetiklenmediyse)
// fired=true ve biriken farklı sinyaller döner. Aksi halde fired=false.
func (c *ChainDetector) Observe(deviceID, signal string, at time.Time) (fired bool, signals []string) {
	if signal == "" {
		return false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	st := c.devs[deviceID]
	if st == nil {
		st = &chainState{signals: map[string]time.Time{}}
		c.devs[deviceID] = st
	}
	cutoff := at.Add(-c.window)
	// Pencere dışını buda.
	for s, t := range st.signals {
		if !t.After(cutoff) {
			delete(st.signals, s)
		}
	}
	st.signals[signal] = at

	if len(st.signals) < c.threshold {
		return false, nil
	}
	// Pencere başına bir kez: son tetikleme hâlâ pencere içindeyse tekrar etme.
	if !st.firedAt.IsZero() && st.firedAt.After(cutoff) {
		return false, nil
	}
	st.firedAt = at
	out := make([]string, 0, len(st.signals))
	for s := range st.signals {
		out = append(out, s)
	}
	sort.Strings(out)
	return true, out
}

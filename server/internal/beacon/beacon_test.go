package beacon

import (
	"testing"
	"time"
)

// Düzenli aralıklı (düşük-jitter) bağlantılar beacon olarak yakalanmalı; düzensiz
// olanlar elenmeli.
func TestAnalyzeDetectsRegularBeacon(t *testing.T) {
	base := time.Now()
	var conns []Conn
	// dev1 → 9.9.9.9: her 60 sn (±1 sn jitter) — beacon.
	for i := 0; i < 10; i++ {
		jit := time.Duration(i%2) * time.Second // 0/1 sn
		conns = append(conns, Conn{DeviceID: "dev1", RemoteIP: "9.9.9.9", At: base.Add(time.Duration(i)*60*time.Second + jit)})
	}
	// dev1 → 8.8.8.8: düzensiz aralıklar — beacon DEĞİL.
	irregular := []int{0, 5, 90, 91, 400, 402, 800}
	for _, s := range irregular {
		conns = append(conns, Conn{DeviceID: "dev1", RemoteIP: "8.8.8.8", At: base.Add(time.Duration(s) * time.Second)})
	}

	found := Analyze(conns, 5, 0.25)
	if len(found) != 1 {
		t.Fatalf("yalnız 1 beacon (9.9.9.9) beklendi: %+v", found)
	}
	f := found[0]
	if f.RemoteIP != "9.9.9.9" || f.Count != 10 {
		t.Fatalf("beacon bulgusu beklenmedik: %+v", f)
	}
	if f.MeanInterval < 55*time.Second || f.MeanInterval > 65*time.Second {
		t.Fatalf("ortalama aralık ~60sn olmalı: %v", f.MeanInterval)
	}
}

// Yetersiz örnek beacon üretmemeli.
func TestAnalyzeTooFewSamples(t *testing.T) {
	base := time.Now()
	conns := []Conn{
		{DeviceID: "d", RemoteIP: "1.1.1.1", At: base},
		{DeviceID: "d", RemoteIP: "1.1.1.1", At: base.Add(time.Minute)},
	}
	if f := Analyze(conns, 5, 0.25); len(f) != 0 {
		t.Fatalf("yetersiz örnekle beacon olmamalı: %+v", f)
	}
}

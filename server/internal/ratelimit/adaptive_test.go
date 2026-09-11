package ratelimit

import "testing"

func TestAdaptiveAIMD(t *testing.T) {
	a := NewAdaptive(1, 10) // başlangıç sınır 10
	if a.Limit() != 10 {
		t.Fatalf("başlangıç sınır 10 olmalı, %d", a.Limit())
	}
	// Overload → yarıya düş
	a.Observe(Overload)
	if a.Limit() != 5 {
		t.Fatalf("overload sonrası 5 beklenir, %d", a.Limit())
	}
	a.Observe(Timeout) // 5 → 2
	if a.Limit() != 2 {
		t.Fatalf("timeout sonrası 2 beklenir, %d", a.Limit())
	}
	// min'in altına inmez
	a.Observe(Overload) // 2 → 1
	a.Observe(Overload) // 1 → min(1)
	if a.Limit() != 1 {
		t.Fatalf("min=1 altına inmemeli, %d", a.Limit())
	}
	// 10 başarı → +1 (toplamsal)
	for i := 0; i < 10; i++ {
		a.Observe(Success)
	}
	if a.Limit() != 2 {
		t.Fatalf("10 başarı sonrası 2 beklenir, %d", a.Limit())
	}
}

func TestAdaptiveAcquireRelease(t *testing.T) {
	a := NewAdaptive(1, 2) // sınır 2
	if !a.TryAcquire() || !a.TryAcquire() {
		t.Fatal("2 yer alınmalı")
	}
	if a.TryAcquire() {
		t.Fatal("3. alım reddedilmeli (sınır 2)")
	}
	if a.Inflight() != 2 {
		t.Fatalf("inflight 2 olmalı, %d", a.Inflight())
	}
	a.Release()
	if !a.TryAcquire() {
		t.Fatal("release sonrası tekrar alınabilmeli")
	}
}

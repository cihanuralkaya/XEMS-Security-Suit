package ratelimit

import (
	"testing"
	"time"
)

func TestDisabledWhenRateZero(t *testing.T) {
	l := New(0, 5, nil)
	for i := 0; i < 1000; i++ {
		if !l.Allow("k") {
			t.Fatal("rate<=0 iken her zaman izin verilmeli")
		}
	}
}

func TestBurstThenBlock(t *testing.T) {
	now := time.Unix(1000, 0)
	clk := &now
	l := New(1, 3, func() time.Time { return *clk }) // 1 token/sn, tavan 3
	// İlk 3 istek (burst) geçer.
	for i := 0; i < 3; i++ {
		if !l.Allow("ip1") {
			t.Fatalf("burst içi istek %d geçmeli", i)
		}
	}
	// 4. istek (aynı an) engellenir.
	if l.Allow("ip1") {
		t.Fatal("burst tükendikten sonra engellenmeli")
	}
}

func TestRefillOverTime(t *testing.T) {
	now := time.Unix(1000, 0)
	clk := &now
	l := New(2, 2, func() time.Time { return *clk }) // 2 token/sn
	l.Allow("ip1")
	l.Allow("ip1") // tavan tüketildi
	if l.Allow("ip1") {
		t.Fatal("tavan tükendi, engellenmeli")
	}
	*clk = clk.Add(time.Second) // 2 token yenilenir
	if !l.Allow("ip1") || !l.Allow("ip1") {
		t.Fatal("1 sn sonra 2 token yenilenmeli")
	}
	if l.Allow("ip1") {
		t.Fatal("yenilenen tavandan fazlası engellenmeli")
	}
}

func TestPerKeyIsolation(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(1, 1, func() time.Time { return now })
	if !l.Allow("a") {
		t.Fatal("a ilk istek geçmeli")
	}
	if !l.Allow("b") {
		t.Fatal("b kendi kovasına sahip olmalı (izolasyon)")
	}
	if l.Allow("a") {
		t.Fatal("a tavanı tükendi")
	}
}

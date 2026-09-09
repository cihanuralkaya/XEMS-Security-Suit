package correlate

import (
	"testing"
	"time"
)

func TestChainFiresOnThreshold(t *testing.T) {
	now := time.Unix(1000, 0)
	clk := &now
	cd := NewChainDetector(15*time.Minute, 3, func() time.Time { return *clk })

	if fired, _ := cd.Observe("d1", "process", now); fired {
		t.Fatal("tek sinyal tetiklememeli")
	}
	*clk = clk.Add(time.Minute)
	if fired, _ := cd.Observe("d1", "network", *clk); fired {
		t.Fatal("iki sinyal tetiklememeli")
	}
	*clk = clk.Add(time.Minute)
	fired, sigs := cd.Observe("d1", "ioc", *clk)
	if !fired {
		t.Fatal("üç farklı sinyal yüksek-güvenli zincir tetiklemeli")
	}
	if len(sigs) != 3 {
		t.Fatalf("3 sinyal beklenirdi, %v", sigs)
	}
}

func TestChainDistinctOnly(t *testing.T) {
	now := time.Unix(1000, 0)
	cd := NewChainDetector(15*time.Minute, 3, func() time.Time { return now })
	// Aynı sinyal 3 kez → farklı sayısı 1 → tetiklemez.
	cd.Observe("d1", "process", now)
	cd.Observe("d1", "process", now)
	if fired, _ := cd.Observe("d1", "process", now); fired {
		t.Fatal("aynı sinyal tekrarı zincir tetiklememeli (yalnız farklı sinyaller)")
	}
}

func TestChainOncePerWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	clk := &now
	cd := NewChainDetector(15*time.Minute, 3, func() time.Time { return *clk })
	cd.Observe("d1", "a", *clk)
	cd.Observe("d1", "b", *clk)
	if fired, _ := cd.Observe("d1", "c", *clk); !fired {
		t.Fatal("eşikte tetiklemeli")
	}
	// 4. farklı sinyal aynı pencerede → tekrar tetiklememeli.
	if fired, _ := cd.Observe("d1", "d", *clk); fired {
		t.Fatal("pencere başına bir kez tetiklemeli")
	}
}

func TestChainWindowExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	clk := &now
	cd := NewChainDetector(5*time.Minute, 3, func() time.Time { return *clk })
	cd.Observe("d1", "a", *clk)
	*clk = clk.Add(10 * time.Minute) // pencere geçti
	cd.Observe("d1", "b", *clk)
	*clk = clk.Add(time.Minute)
	// 'a' pencere dışı kaldı → yalnız b,c var → 2 < 3 → tetiklemez.
	if fired, _ := cd.Observe("d1", "c", *clk); fired {
		t.Fatal("pencere dışı sinyaller sayılmamalı")
	}
}

func TestChainPerDeviceIsolated(t *testing.T) {
	now := time.Unix(1000, 0)
	cd := NewChainDetector(15*time.Minute, 3, func() time.Time { return now })
	cd.Observe("d1", "a", now)
	cd.Observe("d1", "b", now)
	cd.Observe("d2", "x", now) // farklı cihaz
	if fired, _ := cd.Observe("d1", "c", now); !fired {
		t.Fatal("d1 kendi eşiğinde tetiklemeli")
	}
	if fired, _ := cd.Observe("d2", "y", now); fired {
		t.Fatal("d2 yalnız 2 sinyalle tetiklememeli (cihaz izolasyonu)")
	}
}

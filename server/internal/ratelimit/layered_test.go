package ratelimit

import "testing"

func TestLayeredAnyLayerDenies(t *testing.T) {
	l := NewLayered()
	l.SetLayer(Global, 1000, 1000) // bol
	l.SetLayer(Agent, 1, 1)        // ajan-başına 1 burst

	keys := map[Layer]string{Agent: "a1"}
	if ok, _ := l.Allow(keys); !ok {
		t.Fatal("ilk istek izinli olmalı")
	}
	// aynı ajan ikinci istek → Agent katmanı reddeder
	if ok, layer := l.Allow(keys); ok || layer != Agent {
		t.Fatalf("ikinci istek Agent katmanınca reddedilmeli, ok=%v layer=%q", ok, layer)
	}
	// farklı ajan → izinli
	if ok, _ := l.Allow(map[Layer]string{Agent: "a2"}); !ok {
		t.Fatal("farklı ajan izinli olmalı")
	}
}

func TestLayeredGlobalAlwaysApplied(t *testing.T) {
	l := NewLayered()
	l.SetLayer(Global, 1, 1) // toplam 1 burst
	if ok, _ := l.Allow(nil); !ok {
		t.Fatal("ilk global istek izinli")
	}
	if ok, layer := l.Allow(nil); ok || layer != Global {
		t.Fatalf("global tükendi, reddedilmeli: ok=%v layer=%q", ok, layer)
	}
}

func TestLayeredUnconfiguredSkipped(t *testing.T) {
	l := NewLayered() // hiç katman yok
	if ok, layer := l.Allow(map[Layer]string{Tenant: "t1"}); !ok || layer != "" {
		t.Fatalf("katmansız her şey izinli olmalı: ok=%v layer=%q", ok, layer)
	}
}

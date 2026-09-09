package risk

import "testing"

func TestScoreOrdering(t *testing.T) {
	// Yüksek önem + kritik varlık + internete açık + istismar → düşük önemden yüksek.
	low := Score(Factors{Severity: "LOW", AssetCriticality: 3, Confidence: 1})
	crit := Score(Factors{Severity: "CRITICAL", AssetCriticality: 5, Exposure: 3, Exploitability: 1, Confidence: 1})
	if !(crit > low) {
		t.Fatalf("kritik (%d) düşükten (%d) büyük olmalı", crit, low)
	}
	if crit < 90 {
		t.Fatalf("kritik senaryo yüksek skor vermeli, %d", crit)
	}
	if low > 30 {
		t.Fatalf("düşük senaryo düşük skor vermeli, %d", low)
	}
}

func TestScoreConfidenceHalves(t *testing.T) {
	full := Score(Factors{Severity: "HIGH", AssetCriticality: 3, Confidence: 1})
	half := Score(Factors{Severity: "HIGH", AssetCriticality: 3, Confidence: 0.0}) // 0 → tam sayılır
	// Confidence 0 tam güven sayılır (belirtilmemiş); açık düşük güven daha az olmalı.
	lowConf := Score(Factors{Severity: "HIGH", AssetCriticality: 3, Confidence: 0.2})
	if !(lowConf < full) {
		t.Fatalf("düşük güven (%d) tam güvenden (%d) az olmalı", lowConf, full)
	}
	if half != full {
		t.Fatalf("confidence=0 tam güven sayılmalı (%d==%d)", half, full)
	}
}

func TestScoreClamped(t *testing.T) {
	s := Score(Factors{Severity: "CRITICAL", AssetCriticality: 5, Exposure: 3, Exploitability: 1, Confidence: 1})
	if s > 100 {
		t.Fatalf("skor 100 ile sınırlı olmalı, %d", s)
	}
	z := Score(Factors{Severity: "UNKNOWN"})
	if z != 0 {
		t.Fatalf("bilinmeyen önem 0 taban vermeli, %d", z)
	}
}

func TestAggregateSaturates(t *testing.T) {
	if Aggregate(nil) != 0 {
		t.Fatal("boş → 0")
	}
	single := Aggregate([]int{70})
	if single != 70 {
		t.Fatalf("tek bulgu kendisi olmalı, %d", single)
	}
	// En yüksek baskın; ekler azalan katkı yapar ve 100'ü aşmaz.
	many := Aggregate([]int{90, 80, 70, 60, 50})
	if many <= 90 || many > 100 {
		t.Fatalf("çok bulgu en yükseğin üstüne çıkmalı ama 100'ü aşmamalı, %d", many)
	}
	// Sıralamadan bağımsız (giriş sırası önemsiz).
	if Aggregate([]int{50, 90, 70}) != Aggregate([]int{90, 70, 50}) {
		t.Fatal("aggregate giriş sırasından bağımsız olmalı")
	}
}

func TestBand(t *testing.T) {
	cases := map[int]string{95: "CRITICAL", 70: "HIGH", 40: "MEDIUM", 20: "LOW", 5: "INFO"}
	for score, want := range cases {
		if got := Band(score); got != want {
			t.Errorf("Band(%d)=%q beklenen %q", score, got, want)
		}
	}
}

func TestAssetFactorRange(t *testing.T) {
	if assetFactor(1) != 0.6 || assetFactor(3) != 1.0 || assetFactor(5) != 1.4 {
		t.Fatalf("assetFactor eşlemesi yanlış: %v %v %v", assetFactor(1), assetFactor(3), assetFactor(5))
	}
	if assetFactor(0) != 1.0 || assetFactor(99) != 1.4 {
		t.Fatal("assetFactor sınır durumları yanlış")
	}
}

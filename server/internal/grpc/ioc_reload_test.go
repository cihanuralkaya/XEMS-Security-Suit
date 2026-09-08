package grpc

import (
	"strings"
	"testing"

	"xems.corp/suite/server/internal/detect"
	"xems.corp/suite/server/internal/ioc"
)

func loadIoC(t *testing.T, s string) *ioc.Set {
	t.Helper()
	set, err := ioc.Load(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// SetIoCSet, ingest yolunun okuduğu göstergeleri CANLI (sunucu yeniden
// başlatılmadan) değiştirmeli — IoC hot-reload semantiği. Atomik Load/Store
// sayesinde eşzamanlı ingest ile yarışsız.
func TestIoCSetHotSwap(t *testing.T) {
	h := &AgentHandler{}

	// Başlangıçta küme yok: atomik Load nil döner, Size() nil-güvenli (0).
	if h.iocSet.Load().Size() != 0 {
		t.Fatal("başlangıçta IoC kümesi boş olmalı")
	}

	// İlk küme yüklenir: 1.2.3.4 eşleşmeli.
	h.SetIoCSet(loadIoC(t, "1.2.3.4 c2-a"))
	if _, _, ok := h.iocSet.Load().Match(map[string]any{"ip": "1.2.3.4"}, ""); !ok {
		t.Fatal("ilk kümede 1.2.3.4 eşleşmeliydi")
	}

	// Hot-swap: yeni küme yalnız 5.6.7.8 içerir. Yeni gösterge eşleşmeli, ESKİ
	// gösterge (1.2.3.4) artık eşleşmemeli — canlı güncelleme yürürlükte.
	h.SetIoCSet(loadIoC(t, "5.6.7.8 c2-b"))
	cur := h.iocSet.Load()
	if _, _, ok := cur.Match(map[string]any{"ip": "5.6.7.8"}, ""); !ok {
		t.Fatal("hot-swap sonrası 5.6.7.8 eşleşmeliydi")
	}
	if _, _, ok := cur.Match(map[string]any{"ip": "1.2.3.4"}, ""); ok {
		t.Fatal("hot-swap sonrası eski gösterge (1.2.3.4) EŞLEŞMEMELİYDİ")
	}
}

// SetDetector, ingest yolunun kullandığı tespit motorunu CANLI (yeniden
// başlatmadan) değiştirmeli — detektör hot-reload semantiği. Atomik Load/Store
// sayesinde eşzamanlı değerlendirme ile yarışsız.
func TestDetectorHotSwap(t *testing.T) {
	h := &AgentHandler{}
	h.SetDetector(nil) // yerleşik varsayılan kurallar (Store içerir)
	if def := len(h.detector.Load().Rules()); def == 0 {
		t.Fatal("varsayılan kural seti boş olmamalı")
	}
	// Tek özel kurallı motora hot-swap: ingest artık yalnız bunu görmeli.
	custom := detect.NewEngine([]detect.Rule{{ID: "X-HOT", Name: "hot", Severity: "HIGH"}})
	h.SetDetector(custom)
	rules := h.detector.Load().Rules()
	if len(rules) != 1 || rules[0].ID != "X-HOT" {
		t.Fatalf("hot-swap sonrası tek özel kural (X-HOT) beklendi: %+v", rules)
	}
}

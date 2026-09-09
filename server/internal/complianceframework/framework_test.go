package complianceframework

import "testing"

func fwScore(rep Report, fw string) (int, bool) {
	for _, f := range rep.Frameworks {
		if f.Framework == fw {
			return f.ScorePct, true
		}
	}
	return 0, false
}

func TestEvaluateFullData(t *testing.T) {
	rep := Evaluate(map[string]float64{
		"disk_encryption": 0.9, // %90 cihazda disk şifreli
		"firewall":        0.8, // %80 cihazda fw açık
	})
	// Her çerçeve iki kontrolü de eşler → ortalama (%90+%80)/2 = %85.
	for _, fw := range []string{CIS, NIST, ISO, KVKK} {
		sc, ok := fwScore(rep, fw)
		if !ok {
			t.Fatalf("%s çerçevesi eksik", fw)
		}
		if sc != 85 {
			t.Fatalf("%s skoru yüzde-85 beklenirdi, %d", fw, sc)
		}
	}
	if len(rep.Controls) != 2 {
		t.Fatalf("2 kontrol beklenirdi, %d", len(rep.Controls))
	}
}

func TestEvaluateMissingControlNotPenalized(t *testing.T) {
	// Yalnız disk verisi var; firewall bilinmiyor → çerçeve yalnız diskten hesaplanır.
	rep := Evaluate(map[string]float64{"disk_encryption": 0.6})
	sc, _ := fwScore(rep, CIS)
	if sc != 60 {
		t.Fatalf("bilinmeyen kontrol hariç yüzde-60 beklenirdi, %d", sc)
	}
	// firewall kontrolü değerlendirilmemiş olarak işaretlenmeli.
	for _, c := range rep.Controls {
		if c.Control == "firewall" && c.Evaluated {
			t.Fatal("firewall verisi yokken evaluated=false olmalı")
		}
	}
}

func TestEvaluateNoData(t *testing.T) {
	rep := Evaluate(map[string]float64{})
	// Veri yoksa çerçeveler 100 (bilinen ihlal yok) döner.
	sc, _ := fwScore(rep, ISO)
	if sc != 100 {
		t.Fatalf("veri yokken yüzde-100 beklenirdi, %d", sc)
	}
}

func TestPctRounding(t *testing.T) {
	if pct(0.855) != 86 || pct(0) != 0 || pct(1.5) != 100 || pct(-1) != 0 {
		t.Fatalf("pct yuvarlama/sınırlama yanlış")
	}
}

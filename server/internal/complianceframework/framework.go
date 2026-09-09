// Package complianceframework, XEMS güvenlik-duruşu kontrollerini tanınmış uyum
// çerçevelerine (CIS, NIST CSF, ISO 27001, KVKK) eşler ve filo duruşundan çerçeve
// başına uyum yüzdesi hesaplar. Böylece "ISO 27001 %88, NIST %84, CIS %91, KVKK %93"
// gibi denetçi-dostu bir görünüm üretilir. Eşleme SAF ve testlidir.
package complianceframework

import "sort"

// Çerçeve adları.
const (
	CIS  = "CIS Controls v8"
	NIST = "NIST CSF"
	ISO  = "ISO 27001:2022"
	KVKK = "KVKK"
)

// ControlMap, bir XEMS kontrolünün çerçeve karşılıklarıdır.
type ControlMap struct {
	Control string            // ör. "disk_encryption"
	Title   string            // insan-okunur başlık
	Refs    map[string]string // çerçeve → kontrol referansı
}

// Crosswalk, XEMS kontrollerinin çerçeve eşlemesidir. Yeni güvenilir kontrol
// eklendikçe (agent compliance baseline'a paralel) genişletilir.
var Crosswalk = []ControlMap{
	{
		Control: "disk_encryption", Title: "Sistem diski şifrelemesi",
		Refs: map[string]string{
			CIS: "3.11", NIST: "PR.DS-1", ISO: "A.8.24", KVKK: "md.12 (veri güvenliği)",
		},
	},
	{
		Control: "firewall", Title: "Ana bilgisayar güvenlik duvarı",
		Refs: map[string]string{
			CIS: "4.5", NIST: "PR.AC-5", ISO: "A.8.20", KVKK: "md.12 (veri güvenliği)",
		},
	},
}

// ControlScore, tek bir kontrolün filo-geneli uyum oranıdır.
type ControlScore struct {
	Control   string `json:"control"`
	Title     string `json:"title"`
	PassPct   int    `json:"pass_pct"`  // uyumlu cihaz yüzdesi (0-100)
	Evaluated bool   `json:"evaluated"` // veri var mı
}

// FrameworkScore, tek bir çerçevenin uyum özetidir.
type FrameworkScore struct {
	Framework string   `json:"framework"`
	ScorePct  int      `json:"score_pct"` // eşlenen kontrollerin ort. uyum yüzdesi
	Controls  []string `json:"controls"`  // "başlık: ref" listesi
}

// Report, çerçeve + kontrol skorlarının birleşik görünümüdür.
type Report struct {
	Frameworks []FrameworkScore `json:"frameworks"`
	Controls   []ControlScore   `json:"controls"`
}

// Evaluate, her kontrolün filo-geneli uyum oranından (0..1) çerçeve skorlarını
// hesaplar. passRatio'da bulunmayan (veri yok) kontroller çerçeve ortalamasına
// DAHİL EDİLMEZ (bilinmeyen cezalandırılmaz). SAF fonksiyon.
func Evaluate(passRatio map[string]float64) Report {
	var rep Report

	// Kontrol skorları (kararlı sıra).
	for _, cm := range Crosswalk {
		cs := ControlScore{Control: cm.Control, Title: cm.Title}
		if r, ok := passRatio[cm.Control]; ok {
			cs.PassPct = pct(r)
			cs.Evaluated = true
		}
		rep.Controls = append(rep.Controls, cs)
	}

	// Çerçeve → o çerçeveye eşlenen kontrollerin oran toplamı + sayısı.
	type acc struct {
		sum   float64
		n     int
		ctrls []string
	}
	byFw := map[string]*acc{}
	fwOrder := []string{CIS, NIST, ISO, KVKK}
	for _, cm := range Crosswalk {
		for fw, ref := range cm.Refs {
			a := byFw[fw]
			if a == nil {
				a = &acc{}
				byFw[fw] = a
			}
			a.ctrls = append(a.ctrls, cm.Title+": "+ref)
			if r, ok := passRatio[cm.Control]; ok {
				a.sum += r
				a.n++
			}
		}
	}
	for _, fw := range fwOrder {
		a := byFw[fw]
		if a == nil {
			continue
		}
		sort.Strings(a.ctrls)
		score := 100 // değerlendirilebilir kontrol yoksa (veri yok) 100 kabul
		if a.n > 0 {
			score = pct(a.sum / float64(a.n))
		}
		rep.Frameworks = append(rep.Frameworks, FrameworkScore{
			Framework: fw, ScorePct: score, Controls: a.ctrls,
		})
	}
	return rep
}

func pct(ratio float64) int {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	return int(ratio*100 + 0.5)
}

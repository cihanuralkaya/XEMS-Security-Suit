package report

import (
	"fmt"
	"sort"
	"strings"
)

// report_ext.go — GELİŞMİŞ RAPORLAMA (§33): rapor TÜRLERİ (executive/technical/incident)
// ve yeni MARKDOWN biçimi. Markdown, e-posta/wiki/PDF-dönüşümü için taşınabilir bir
// metin biçimidir (harici PDF kütüphanesi gerektirmeden). HTML/CSV/JSON korunur.

// Kind, rapor türüdür — içerik vurgusunu belirler.
type Kind string

const (
	// KindExecutive, yönetici özeti: KPI'lar + risk + öne çıkanlar; teknik ayrıntı yok.
	KindExecutive Kind = "executive"
	// KindTechnical, tam teknik rapor: tüm sayaçlar + olay tablosu + dağılımlar.
	KindTechnical Kind = "technical"
	// KindIncident, olay-odaklı: yalnız öne çıkan olaylar (incident) ve tehdit etkinliği.
	KindIncident Kind = "incident"
)

// Title, tür için varsayılan başlığı döner.
func (k Kind) Title() string {
	switch k {
	case KindExecutive:
		return "Yönetici Güvenlik Özeti"
	case KindIncident:
		return "Olay (Incident) Raporu"
	default:
		return "Teknik Güvenlik Raporu"
	}
}

// RenderMarkdown, verilen türe göre bir Markdown raporu üretir. Executive kısa ve
// KPI/risk odaklı; technical tam; incident olay-odaklıdır.
func RenderMarkdown(d Data, kind Kind) string {
	if d.Title == "" {
		d.Title = kind.Title()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", d.Title)
	fmt.Fprintf(&b, "> Üretildi: %s · XEMS Security Suite", d.GeneratedAt.Format("2006-01-02 15:04 MST"))
	if d.TenantID != "" {
		fmt.Fprintf(&b, " · kiracı: %s", d.TenantID)
	}
	b.WriteString("\n\n")

	// Filo KPI'ları (incident türü hariç tümünde).
	if kind != KindIncident {
		b.WriteString("## Filo durumu\n\n")
		b.WriteString("| Metrik | Değer |\n|---|---:|\n")
		fmt.Fprintf(&b, "| Toplam cihaz | %d |\n", d.DevicesTotal)
		fmt.Fprintf(&b, "| Çevrimiçi | %d |\n", d.DevicesOnline)
		fmt.Fprintf(&b, "| Çevrimdışı | %d |\n", d.DevicesOffline)
		fmt.Fprintf(&b, "| Karantina | %d |\n", d.DevicesQuarantined)
		fmt.Fprintf(&b, "| Uyumsuz | %d (%%%s) |\n\n", d.NonCompliant, pctStr(d.NonCompliant, d.DevicesTotal))
	}

	// Tehdit etkinliği (tümünde).
	b.WriteString("## Tehdit etkinliği\n\n")
	b.WriteString("| Metrik | Değer |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Tespit | %d |\n", d.Detections)
	fmt.Fprintf(&b, "| Alarm | %d |\n", d.AlertsRaised)
	fmt.Fprintf(&b, "| Bastırılan (korelasyon) | %d |\n", d.AlertsSuppressed)
	fmt.Fprintf(&b, "| IoC eşleşme | %d |\n\n", d.IocHits)

	// Önem dağılımı (technical).
	if kind == KindTechnical && len(d.EventsBySeverity) > 0 {
		b.WriteString("## Önem dağılımı\n\n| Önem | Adet |\n|---|---:|\n")
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if n, ok := d.EventsBySeverity[sev]; ok {
				fmt.Fprintf(&b, "| %s | %d |\n", sev, n)
			}
		}
		b.WriteString("\n")
	}

	// Öne çıkan olaylar (executive: ilk 5; technical/incident: tümü).
	if len(d.TopIncidents) > 0 {
		b.WriteString("## Öne çıkan olaylar (incident)\n\n")
		b.WriteString("| Cihaz | Kural | Önem | Tekrar | Son görülme |\n|---|---|---|---:|---|\n")
		incs := d.TopIncidents
		if kind == KindExecutive && len(incs) > 5 {
			incs = incs[:5]
		}
		for _, in := range incs {
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n",
				in.DeviceID, in.RuleID, in.Severity, in.Count, in.LastSeen.Format("2006-01-02 15:04"))
		}
		b.WriteString("\n")
	}

	// Executive: kısa değerlendirme cümlesi.
	if kind == KindExecutive {
		fmt.Fprintf(&b, "## Değerlendirme\n\n%s\n", d.Summary())
	}
	return b.String()
}

// TopOSByCount, cihaz-OS dağılımını adede göre azalan sıralı (deterministik) döner —
// rapor/dağılım tabloları için yardımcı.
func TopOSByCount(m map[string]int) []struct {
	OS    string
	Count int
} {
	out := make([]struct {
		OS    string
		Count int
	}, 0, len(m))
	for k, v := range m {
		out = append(out, struct {
			OS    string
			Count int
		}{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].OS < out[j].OS
	})
	return out
}

func pctStr(n, total int) string {
	if total == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", n*100/total)
}

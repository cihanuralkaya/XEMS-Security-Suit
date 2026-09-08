// Package report, güvenlik-duruş raporu üretir (uyum, olay özeti, tespit/alarm
// sayaçları, filo envanteri) — kurumsal/denetim/KVKK kanıtı için dışa aktarılabilir
// nokta-zaman görünümü. adminread/metrics toplamlarından bağımsız Go html/template
// ile HTML ve CSV üretir (dış bağımlılık yok).
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Incident, rapordaki özet bir korelasyon olayıdır.
type Incident struct {
	DeviceID string
	RuleID   string
	Severity string
	Count    int
	LastSeen time.Time
}

// Data, raporun girdisidir (çağıran adminread/metrics'ten doldurur).
type Data struct {
	GeneratedAt        time.Time
	Title              string
	DevicesTotal       int
	DevicesOnline      int
	DevicesOffline     int
	DevicesQuarantined int
	NonCompliant       int
	EventsBySeverity   map[string]int
	DevicesByOS        map[string]int
	TopIncidents       []Incident
	Detections         int64
	AlertsRaised       int64
	AlertsSuppressed   int64
	IocHits            int64
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"pct": func(n, total int) string {
		if total == 0 {
			return "0"
		}
		return strconv.Itoa(n * 100 / total)
	},
	"ts": func(t time.Time) string { return t.Format("2006-01-02 15:04 MST") },
}).Parse(`<!doctype html><html lang="tr"><head><meta charset="utf-8">
<title>{{.Title}}</title><style>
body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a2332;margin:24px;background:#fff}
h1{font-size:20px;margin:0 0 4px} .sub{color:#667;margin:0 0 18px;font-size:12px}
.grid{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0}
.kpi{border:1px solid #dde;border-radius:8px;padding:10px 14px;min-width:120px}
.kpi .n{font-size:22px;font-weight:700} .kpi .l{font-size:11px;color:#667}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eef} th{color:#667}
h2{font-size:15px;margin:18px 0 4px;border-bottom:2px solid #f0f2f5;padding-bottom:4px}
.crit{color:#c0202f;font-weight:700}
</style></head><body>
<h1>{{.Title}}</h1><p class="sub">Üretildi: {{ts .GeneratedAt}} · XEMS Security Suite</p>
<div class="grid">
  <div class="kpi"><div class="n">{{.DevicesTotal}}</div><div class="l">Toplam cihaz</div></div>
  <div class="kpi"><div class="n">{{.DevicesOnline}}</div><div class="l">Çevrimiçi</div></div>
  <div class="kpi"><div class="n">{{.DevicesOffline}}</div><div class="l">Çevrimdışı</div></div>
  <div class="kpi"><div class="n">{{.DevicesQuarantined}}</div><div class="l">Karantina</div></div>
  <div class="kpi"><div class="n {{if .NonCompliant}}crit{{end}}">{{.NonCompliant}}</div><div class="l">Uyumsuz (%{{pct .NonCompliant .DevicesTotal}})</div></div>
</div>
<h2>Tehdit etkinliği</h2>
<div class="grid">
  <div class="kpi"><div class="n">{{.Detections}}</div><div class="l">Tespit</div></div>
  <div class="kpi"><div class="n">{{.AlertsRaised}}</div><div class="l">Alarm</div></div>
  <div class="kpi"><div class="n">{{.AlertsSuppressed}}</div><div class="l">Bastırılan (korelasyon)</div></div>
  <div class="kpi"><div class="n">{{.IocHits}}</div><div class="l">IoC eşleşme</div></div>
</div>
{{if .TopIncidents}}<h2>Öne çıkan olaylar (incident)</h2>
<table><thead><tr><th>Cihaz</th><th>Kural</th><th>Önem</th><th>Tekrar</th><th>Son görülme</th></tr></thead><tbody>
{{range .TopIncidents}}<tr><td>{{.DeviceID}}</td><td>{{.RuleID}}</td><td>{{.Severity}}</td><td>{{.Count}}</td><td>{{ts .LastSeen}}</td></tr>{{end}}
</tbody></table>{{end}}
</body></html>`))

// RenderHTML, duruş raporunu kendi kendine yeten bir HTML sayfası olarak üretir.
func RenderHTML(d Data) (string, error) {
	if d.Title == "" {
		d.Title = "Güvenlik Duruş Raporu"
	}
	if d.GeneratedAt.IsZero() {
		d.GeneratedAt = time.Now()
	}
	var b bytes.Buffer
	if err := htmlTmpl.Execute(&b, d); err != nil {
		return "", err
	}
	return b.String(), nil
}

// RenderCSV, temel KPI'ları CSV olarak üretir (tablo/pivot dışa aktarımı).
func RenderCSV(d Data) string {
	var b strings.Builder
	b.WriteString("metrik,deger\n")
	rows := [][2]string{
		{"uretildi", d.GeneratedAt.Format(time.RFC3339)},
		{"cihaz_toplam", strconv.Itoa(d.DevicesTotal)},
		{"cihaz_cevrimici", strconv.Itoa(d.DevicesOnline)},
		{"cihaz_cevrimdisi", strconv.Itoa(d.DevicesOffline)},
		{"cihaz_karantina", strconv.Itoa(d.DevicesQuarantined)},
		{"uyumsuz", strconv.Itoa(d.NonCompliant)},
		{"tespit", strconv.FormatInt(d.Detections, 10)},
		{"alarm", strconv.FormatInt(d.AlertsRaised, 10)},
		{"alarm_bastirilan", strconv.FormatInt(d.AlertsSuppressed, 10)},
		{"ioc_eslesme", strconv.FormatInt(d.IocHits, 10)},
	}
	for _, r := range rows {
		b.WriteString(csvField(r[0]) + "," + csvField(r[1]) + "\n")
	}
	// Önem dağılımı (deterministik sıra).
	sevs := make([]string, 0, len(d.EventsBySeverity))
	for k := range d.EventsBySeverity {
		sevs = append(sevs, k)
	}
	sort.Strings(sevs)
	for _, s := range sevs {
		b.WriteString(csvField("onem_"+strings.ToLower(s)) + "," + strconv.Itoa(d.EventsBySeverity[s]) + "\n")
	}
	return b.String()
}

// csvField, gerekiyorsa alanı tırnaklar (virgül/tırnak/yeni-satır kaçışı).
func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// Summary, raporun tek satırlık metin özetidir (zamanlanmış görev logu / bildirim).
func (d Data) Summary() string {
	return fmt.Sprintf("cihaz=%d çevrimiçi=%d uyumsuz=%d tespit=%d alarm=%d(bastırılan %d) ioc=%d",
		d.DevicesTotal, d.DevicesOnline, d.NonCompliant, d.Detections, d.AlertsRaised, d.AlertsSuppressed, d.IocHits)
}

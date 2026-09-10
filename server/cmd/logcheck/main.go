// Command logcheck, bir log örneğini XEMS'in GERÇEK alım normalize edicilerinden
// geçirir ve elde edilen olay kayıtlarını yazar — böylece operatörler log-shipper
// çıktılarını canlıya bağlamadan ÖNCE XEMS'in nasıl ayrıştırdığını doğrulayabilir.
// Yönlendirme /api/ingest ile aynıdır (CEF/LEEF/syslog satır-başına; winlog/JSON
// gövde). Ağ, kimlik doğrulama ya da sunucu gerektirmez — tamamen çevrimdışı.
//
//	# metin (CEF/LEEF/syslog satırları) — stdin ya da -file
//	echo 'CEF:0|V|P|1|s|Malware|9|src=1.2.3.4' | go run ./server/cmd/logcheck
//	go run ./server/cmd/logcheck -file firewall.log
//
//	# JSON: XEMS yerel şeması ya da Windows olay günlüğü
//	cat winlog.json | go run ./server/cmd/logcheck -winlog
//	cat events.json | go run ./server/cmd/logcheck -json
//
// Her satır bir normalize edilmiş kayıttır (device_id, category, severity, occurred_at,
// message). Çıkış kodu: normalize edilebilir kayıt yoksa 1, aksi halde 0.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"xems.corp/suite/server/internal/logingest"
)

func main() {
	file := flag.String("file", "", "okunacak log dosyası (boş → stdin)")
	asJSON := flag.Bool("json", false, "gövdeyi XEMS yerel JSON şeması olarak ayrıştır")
	asWinlog := flag.Bool("winlog", false, "gövdeyi Windows olay günlüğü JSON'u olarak ayrıştır")
	flag.Parse()

	var data []byte
	var err error
	if *file != "" {
		data, err = os.ReadFile(*file)
	} else {
		data, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "logcheck: girdi okunamadı: %v\n", err)
		os.Exit(2)
	}
	now := time.Now()

	var recs []logingest.Record
	switch {
	case *asWinlog:
		recs, err = logingest.NormalizeWinEvent(data, now)
	case *asJSON:
		recs, err = logingest.NormalizeJSON(data, now)
	default:
		// Otomatik: JSON gövdesi mi (winlog imli mi), yoksa satır-başına metin mi?
		trimmed := strings.TrimSpace(string(data))
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			if isWinlog(trimmed) {
				recs, err = logingest.NormalizeWinEvent(data, now)
			} else {
				recs, err = logingest.NormalizeJSON(data, now)
			}
		} else {
			recs = normalizeLines(trimmed, now)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "logcheck: ayrıştırma hatası: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	for _, r := range recs {
		_ = enc.Encode(map[string]any{
			"device_id":   r.DeviceID,
			"category":    r.Event.Category,
			"severity":    r.Event.Severity,
			"occurred_at": r.Event.OccurredAt.UTC().Format(time.RFC3339),
			"message":     r.Event.Message,
			"details":     r.Event.Details,
		})
	}
	fmt.Fprintf(os.Stderr, "logcheck: %d kayıt normalize edildi\n", len(recs))
	if len(recs) == 0 {
		os.Exit(1)
	}
}

// isWinlog, JSON gövdesinin Windows olay şekli olup olmadığını sezer (handleIngest ile
// aynı imler).
func isWinlog(s string) bool {
	if len(s) > 4096 {
		s = s[:4096]
	}
	for _, m := range []string{`"winlog"`, `"event_id"`, `"EventID"`, `"System"`} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// normalizeLines, metin gövdesini satır-başına (CEF/LEEF/syslog) normalize eder —
// /api/ingest ile aynı yönlendirme. Tanınmayan satırlar atlanır.
func normalizeLines(body string, now time.Time) []logingest.Record {
	var out []logingest.Record
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec logingest.Record
		var e error
		switch {
		case strings.Contains(line, "LEEF:"):
			rec, e = logingest.NormalizeLEEF(line, now)
		case strings.Contains(line, "CEF:"):
			rec, e = logingest.NormalizeCEF(line, now)
		case strings.HasPrefix(strings.TrimSpace(line), "<"):
			rec, e = logingest.NormalizeSyslog(line, now)
		default:
			rec, e = logingest.NormalizeCEF(line, now)
		}
		if e == nil {
			out = append(out, rec)
		}
	}
	return out
}

// Package logingest, HARİCİ kaynaklardan (güvenlik duvarı, bulut, kimlik sağlayıcı,
// başka SIEM) gelen logları XEMS'in ortak olay modeline (model.Event) normalize
// eder. Böylece XEMS yalnız uç-nokta ajan telemetrisini değil, harici logları da
// tek bir korelasyon/tespit/hunt yüzeyinde toplayabilir (SIEM alım yolu).
//
// İki giriş biçimi desteklenir: yapılandırılmış JSON ve CEF (ArcSight). Tanınmayan
// kategori/önem güvenli varsayılana (SYSTEM/INFO) düşürülür. Her harici kaynak,
// adından türetilen KARARLI bir cihaz kimliğine (UUIDv5) eşlenir — böylece aynı
// kaynak her zaman aynı "cihaz" altında toplanır.
package logingest

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"xems.corp/suite/server/internal/model"
)

// Record, normalize edilmiş tek bir alım kaydıdır (hedef cihaz + olay).
type Record struct {
	DeviceID string
	Event    model.Event
}

var validCategory = map[string]bool{
	"SYSTEM": true, "SECURITY": true, "NETWORK_DISCOVERY": true,
	"POLICY_VIOLATION": true, "AGENT_UPDATE": true, "PROCESS": true, "NETWORK_CONN": true,
}

var validSeverity = map[string]bool{
	"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

func normCategory(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if validCategory[s] {
		return s
	}
	return "SYSTEM"
}

func normSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if validSeverity[s] {
		return s
	}
	return "INFO"
}

// ingestNamespace, kaynak-adı → UUIDv5 türetmesi için sabit ad alanıdır.
var ingestNamespace = [16]byte{
	0x1e, 0x4b, 0x7a, 0x90, 0x3c, 0x5d, 0x4f, 0x21,
	0xa8, 0x0b, 0x9c, 0x77, 0x2d, 0x6e, 0x11, 0x33,
}

// SourceUUID, bir harici kaynak adından KARARLI bir UUIDv5 üretir (aynı ad →
// aynı cihaz kimliği). DB device_id UUID kolonuyla uyumludur.
func SourceUUID(source string) string {
	h := sha1.New()
	h.Write(ingestNamespace[:])
	h.Write([]byte(source))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // sürüm 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC4122 varyantı
	hexs := hex.EncodeToString(u[:])
	return hexs[0:8] + "-" + hexs[8:12] + "-" + hexs[12:16] + "-" + hexs[16:20] + "-" + hexs[20:32]
}

// logJSON, harici JSON log kaydının şemasıdır.
type logJSON struct {
	Source     string          `json:"source"`
	Category   string          `json:"category"`
	Severity   string          `json:"severity"`
	Message    string          `json:"message"`
	OccurredAt string          `json:"occurred_at"` // RFC3339, opsiyonel
	Details    json.RawMessage `json:"details"`     // opsiyonel nesne
}

// NormalizeJSON, bir JSON dizisini (veya tek nesneyi) normalize edilmiş kayıtlara
// çevirir. source ve message zorunludur; geçersiz kayıtlar hata döndürür.
func NormalizeJSON(data []byte, now time.Time) ([]Record, error) {
	trimmed := strings.TrimSpace(string(data))
	var raws []logJSON
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &raws); err != nil {
			return nil, fmt.Errorf("logingest: JSON dizi çözülemedi: %w", err)
		}
	} else {
		var one logJSON
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, fmt.Errorf("logingest: JSON çözülemedi: %w", err)
		}
		raws = []logJSON{one}
	}
	out := make([]Record, 0, len(raws))
	for i, r := range raws {
		if strings.TrimSpace(r.Source) == "" {
			return nil, fmt.Errorf("logingest: kayıt #%d source zorunlu", i)
		}
		if strings.TrimSpace(r.Message) == "" {
			return nil, fmt.Errorf("logingest: kayıt #%d message zorunlu", i)
		}
		occurred := now
		if r.OccurredAt != "" {
			if t, err := time.Parse(time.RFC3339, r.OccurredAt); err == nil {
				occurred = t
			}
		}
		details := ""
		if len(r.Details) > 0 && string(r.Details) != "null" {
			details = string(r.Details)
		}
		out = append(out, Record{
			DeviceID: SourceUUID(r.Source),
			Event: model.Event{
				Category:   normCategory(r.Category),
				Severity:   normSeverity(r.Severity),
				Message:    "[" + r.Source + "] " + r.Message,
				OccurredAt: occurred,
				Details:    details,
			},
		})
	}
	return out, nil
}

// NormalizeCEF, tek bir CEF satırını normalize eder:
//
//	CEF:Version|Vendor|Product|Ver|SigID|Name|Severity|Extensions
//
// Kaynak "Vendor/Product", mesaj "Name", önem CEF 0-10 → INFO..CRITICAL.
func NormalizeCEF(line string, now time.Time) (Record, error) {
	idx := strings.Index(line, "CEF:")
	if idx < 0 {
		return Record{}, fmt.Errorf("logingest: CEF öneki yok")
	}
	body := line[idx+4:]
	parts := strings.SplitN(body, "|", 8)
	if len(parts) < 7 {
		return Record{}, fmt.Errorf("logingest: CEF alanları eksik (%d)", len(parts))
	}
	vendor, product, name, sev := parts[1], parts[2], parts[5], parts[6]
	source := strings.TrimSpace(vendor + "/" + product)
	details := ""
	if len(parts) == 8 {
		details = strings.TrimSpace(parts[7])
	}
	rec := Record{
		DeviceID: SourceUUID(source),
		Event: model.Event{
			Category:   "SECURITY",
			Severity:   cefSeverity(sev),
			Message:    "[" + source + "] " + strings.TrimSpace(name),
			OccurredAt: now,
		},
	}
	if details != "" {
		// Ham CEF uzantısını yapılandırılmış Details'e sar (arama/görünürlük).
		b, _ := json.Marshal(map[string]string{"cef_extension": details})
		rec.Event.Details = string(b)
	}
	return rec, nil
}

// NormalizeLEEF, bir LEEF (QRadar) satırını olay kaydına çevirir. Biçim:
//
//	LEEF:Sürüm|Vendor|Product|Ver|EventID|<öznitelikler>
//
// Öznitelikler varsayılan SEKME (tab) ile ayrılmış key=value çiftleridir; LEEF 2.0
// isteğe bağlı bir ayraç alanı taşıyabilir (EventID'den sonra). sev/msg/cat gibi
// standart öznitelikler tanınır; kalanlar Details'e yazılır. SIEM alım simetrisi
// (giden SIEM zaten LEEF üretir).
func NormalizeLEEF(line string, now time.Time) (Record, error) {
	idx := strings.Index(line, "LEEF:")
	if idx < 0 {
		return Record{}, fmt.Errorf("logingest: LEEF öneki yok")
	}
	parts := strings.Split(line[idx+5:], "|")
	if len(parts) < 6 {
		return Record{}, fmt.Errorf("logingest: LEEF alanları eksik (%d)", len(parts))
	}
	version, vendor, product, eventID := parts[0], parts[1], parts[2], parts[4]
	attrs, delim := parts[5], "\t"
	// LEEF 2.0 opsiyonel ayraç alanı: EventID'den sonraki alan kv değilse ayraçtır.
	if strings.HasPrefix(version, "2.0") && len(parts) >= 7 && !strings.Contains(parts[5], "=") {
		delim = decodeLEEFDelim(parts[5])
		attrs = parts[6]
	}
	kv := parseLEEFAttrs(attrs, delim)
	source := strings.TrimSpace(vendor + "/" + product)
	name := kv["msg"]
	if name == "" {
		name = strings.TrimSpace(eventID)
	}
	sev := kv["sev"]
	if sev == "" {
		sev = kv["severity"]
	}
	rec := Record{
		DeviceID: SourceUUID(source),
		Event: model.Event{
			Category:   "SECURITY",
			Severity:   cefSeverity(sev), // LEEF sev de sayısal (CEF gibi) ya da metinsel olabilir
			Message:    "[" + source + "] " + strings.TrimSpace(name),
			OccurredAt: now,
		},
	}
	if len(kv) > 0 {
		b, _ := json.Marshal(kv)
		rec.Event.Details = string(b)
	}
	return rec, nil
}

// parseLEEFAttrs, ayraçla ayrılmış key=value öznitelik dizesini haritaya çevirir.
func parseLEEFAttrs(attrs, delim string) map[string]string {
	kv := map[string]string{}
	for _, tok := range strings.Split(attrs, delim) {
		if k, v, ok := strings.Cut(strings.TrimSpace(tok), "="); ok {
			k = strings.TrimSpace(k)
			if k != "" {
				kv[k] = strings.TrimSpace(v)
			}
		}
	}
	return kv
}

// decodeLEEFDelim, LEEF 2.0 ayraç alanını çözer: "xHH" (hex bayt) ya da literal karakter.
func decodeLEEFDelim(f string) string {
	if len(f) == 3 && (f[0] == 'x' || f[0] == 'X') {
		if n, err := strconv.ParseUint(f[1:], 16, 8); err == nil {
			return string([]byte{byte(n)})
		}
	}
	if f == "" {
		return "\t"
	}
	return f
}

// NormalizeSyslog, bir düz syslog satırını (RFC5424 veya RFC3164) olay kaydına
// çevirir. Log-shipper'lar (rsyslog omhttp, fluent-bit http) syslog'u HTTP üzerinden
// iletebildiğinden bu, CEF/LEEF dışı kaynakları da kapsar. PRAGMATİK ayrıştırma:
// <PRI>'dan önem çıkarılır; RFC5424'te hostname/app-name kaynak olur; kalan MSG'dir.
//
//	RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
//	RFC3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
func NormalizeSyslog(line string, now time.Time) (Record, error) {
	line = strings.TrimSpace(line)
	if len(line) < 3 || line[0] != '<' {
		return Record{}, fmt.Errorf("logingest: syslog <PRI> öneki yok")
	}
	end := strings.IndexByte(line, '>')
	if end < 2 || end > 4 { // <PRI> en fazla 3 basamak
		return Record{}, fmt.Errorf("logingest: syslog <PRI> geçersiz")
	}
	pri, err := strconv.Atoi(line[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return Record{}, fmt.Errorf("logingest: syslog PRI geçersiz")
	}
	rest := line[end+1:]
	sev := syslogSeverity(pri % 8)

	source, msg := "syslog", strings.TrimSpace(rest)
	fields := strings.Fields(rest)
	// RFC5424: ilk alan sürüm ("1"); HOSTNAME=fields[2], APP-NAME=fields[3].
	if len(fields) >= 5 && fields[0] == "1" {
		host := deNil(fields[2])
		app := deNil(fields[3])
		if host != "" {
			source = host
		} else if app != "" {
			source = app
		}
		// MSG: MSGID(+SD) sonrası; SD karmaşık olabilir → pragmatik: 6. alandan sonrası.
		if i := nthFieldIndex(rest, 6); i >= 0 {
			msg = strings.TrimSpace(rest[i:])
		}
	} else if len(fields) >= 5 {
		// RFC3164: "Mon DD HH:MM:SS HOST TAG: MSG" — HOST 4. alan (fields[3]).
		if h := fields[3]; h != "" {
			source = h
		}
	}
	if msg == "" {
		msg = "(boş syslog mesajı)"
	}
	return Record{
		DeviceID: SourceUUID(source),
		Event: model.Event{
			Category:   "SECURITY",
			Severity:   sev,
			Message:    "[" + source + "] " + msg,
			OccurredAt: now,
		},
	}, nil
}

// syslogSeverity, syslog önem kodunu (0-7) XEMS önem düzeyine eşler.
func syslogSeverity(s int) string {
	switch {
	case s <= 2: // emerg/alert/crit
		return "CRITICAL"
	case s == 3: // err
		return "HIGH"
	case s == 4: // warning
		return "MEDIUM"
	case s == 5: // notice
		return "LOW"
	default: // info/debug
		return "INFO"
	}
}

// deNil, syslog "-" (yok) değerini boş string'e çevirir.
func deNil(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// nthFieldIndex, boşlukla ayrılmış n. alanın (0-tabanlı) `s` içindeki başlangıç
// bayt indeksini döner; yoksa -1.
func nthFieldIndex(s string, n int) int {
	field, inField := 0, false
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			if !inField {
				if field == n {
					return i
				}
				field++
				inField = true
			}
		} else {
			inField = false
		}
	}
	return -1
}

// cefSeverity, CEF 0-10 önem ölçeğini XEMS önem düzeyine eşler.
func cefSeverity(s string) string {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return normSeverity(s) // metinsel önem (Low/High...) olabilir
	}
	switch {
	case n >= 9:
		return "CRITICAL"
	case n >= 7:
		return "HIGH"
	case n >= 4:
		return "MEDIUM"
	case n >= 1:
		return "LOW"
	default:
		return "INFO"
	}
}

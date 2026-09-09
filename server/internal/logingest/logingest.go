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

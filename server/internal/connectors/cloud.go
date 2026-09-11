// Package connectors, §45 connector çerçevesi üzerine SOMUT bağlayıcılar sağlar:
// XDR kaynakları (§29 — syslog/CEF/LEEF/JSON/WinEvent normalize) ve Cloud kaynakları
// (§30 — AWS CloudTrail / Azure Activity / GCP / M365 denetim logları). Tümü ÇEVRİMDIŞI
// çalışabilir: veri "puller" ile enjekte edilir (dosya/HTTP), böylece dış SDK/kimlik
// gerektirmez. Ham kayıtlar KANONİK model.Event'e (§5) normalize edilir.
package connectors

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xems.corp/suite/server/internal/logingest"
	"xems.corp/suite/server/internal/model"
)

// cloudAudit, farklı bulut sağlayıcılarının denetim-log alanlarının ortak (birleşik)
// gösterimidir. JSON etiketleri, AWS CloudTrail / Azure Activity / GCP / M365'in en
// yaygın alan adlarını (büyük/küçük harf çeşitleriyle) kapsar.
type cloudAudit struct {
	EventTime     string          `json:"eventTime"`
	TimeGenerated string          `json:"timeGenerated"`
	Timestamp     string          `json:"timestamp"`
	EventName     string          `json:"eventName"`
	OperationName any             `json:"operationName"` // Azure: string veya {value,localizedValue}
	EventType     string          `json:"eventType"`
	EventSource   string          `json:"eventSource"`
	SourceIP      string          `json:"sourceIPAddress"`
	CallerIP      string          `json:"callerIpAddress"`
	RequestID     string          `json:"requestID"`
	AwsRegion     string          `json:"awsRegion"`
	ErrorCode     string          `json:"errorCode"`
	ResultType    string          `json:"resultType"`
	UserIdentity  json.RawMessage `json:"userIdentity"`
	Caller        string          `json:"caller"`
}

// NormalizeCloudAudit, bir bulut denetim-log gövdesini (tek nesne YA DA nesne dizisi)
// kanonik olaylara çevirir. Kaynak "cloud", event_type olay adı, correlation_id
// requestID olur; başarısız konsol/oturum-açma olayları HIGH önem alır. Zaman;
// eventTime/timeGenerated/timestamp'ten (RFC3339) çözülür, yoksa now kullanılır.
func NormalizeCloudAudit(data []byte, provider string, now time.Time) ([]model.Event, error) {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, fmt.Errorf("connectors: boş bulut denetim gövdesi")
	}
	var raws []cloudAudit
	if data[0] == '[' {
		if err := json.Unmarshal(data, &raws); err != nil {
			return nil, fmt.Errorf("connectors: bulut denetim dizisi çözülemedi: %w", err)
		}
	} else {
		var one cloudAudit
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, fmt.Errorf("connectors: bulut denetim nesnesi çözülemedi: %w", err)
		}
		raws = []cloudAudit{one}
	}
	src := "cloud"
	if provider != "" {
		src = "cloud/" + provider
	}
	out := make([]model.Event, 0, len(raws))
	for _, r := range raws {
		name := r.eventName()
		ip := r.SourceIP
		if ip == "" {
			ip = r.CallerIP
		}
		actor := r.actor()
		msg := fmt.Sprintf("[%s] %s", src, name)
		if actor != "" {
			msg += " (" + actor + ")"
		}
		if ip != "" {
			msg += " ip=" + ip
		}
		details := map[string]string{"provider": provider, "event_name": name}
		if ip != "" {
			details["src_ip"] = ip
		}
		if actor != "" {
			details["actor"] = actor
		}
		if r.RequestID != "" {
			details["request_id"] = r.RequestID
		}
		det, _ := json.Marshal(details)
		ev := model.Event{
			Category:      "SECURITY",
			Severity:      r.severity(),
			Message:       msg,
			OccurredAt:    r.when(now),
			Source:        src,
			EventType:     name,
			CorrelationID: cloudCorrelation(r.RequestID),
			Details:       string(det),
		}
		ev.DeviceID = logingest.SourceUUID(src)
		out = append(out, ev)
	}
	return out, nil
}

func (r cloudAudit) eventName() string {
	switch {
	case r.EventName != "":
		return r.EventName
	case r.EventType != "":
		return r.EventType
	}
	switch v := r.OperationName.(type) {
	case string:
		if v != "" {
			return v
		}
	case map[string]any:
		if s, ok := v["value"].(string); ok && s != "" {
			return s
		}
	}
	return "cloud-event"
}

func (r cloudAudit) actor() string {
	if r.Caller != "" {
		return r.Caller
	}
	if len(r.UserIdentity) > 0 {
		var ui map[string]any
		if json.Unmarshal(r.UserIdentity, &ui) == nil {
			for _, k := range []string{"arn", "userName", "principalId", "accountId"} {
				if s, ok := ui[k].(string); ok && s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// severity, başarısız kimlik-doğrulama/yetki olaylarını yükseltir.
func (r cloudAudit) severity() string {
	name := strings.ToLower(r.eventName())
	failed := r.ErrorCode != "" || strings.EqualFold(r.ResultType, "failure")
	if failed && (strings.Contains(name, "login") || strings.Contains(name, "signin") ||
		strings.Contains(name, "consolelogin") || strings.Contains(name, "authorization")) {
		return "HIGH"
	}
	if failed {
		return "MEDIUM"
	}
	return "INFO"
}

func (r cloudAudit) when(now time.Time) time.Time {
	for _, s := range []string{r.EventTime, r.TimeGenerated, r.Timestamp} {
		if s == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC()
		}
	}
	return now.UTC()
}

func cloudCorrelation(reqID string) string {
	if reqID == "" {
		return ""
	}
	return "cloud_" + reqID
}

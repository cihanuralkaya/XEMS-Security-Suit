package adminread

import (
	"context"
	"time"

	"xems.corp/suite/server/internal/detect"
	"xems.corp/suite/server/internal/model"
)

// Event Replay (§19): yeni/aday bir tespit kuralını GEÇMİŞ olaylara uygular. Böylece
// SOC, bir kuralı üretime almadan önce "bu kural son 7/30/90 günde kaç olayı
// yakalardı?" sorusunu yanıtlayabilir. Salt-okuma: depoyu DEĞİŞTİRMEZ.

const (
	// replayScanCap, tek bir replay çalışmasında taranacak azami olay sayısıdır
	// (kaynak koruması). f.Limit daha küçükse o kullanılır.
	replayScanCap = 50000
	// maxReplayMatches, yanıtta döndürülen azami eşleşme örneğidir; kalanları by_rule
	// sayar (Truncated=true). Büyük payload'ları önler.
	maxReplayMatches = 500
)

// ReplayMatch, geçmiş bir olayın bir kuralla eşleşmesidir.
type ReplayMatch struct {
	EventID    string    `json:"event_id"`
	DeviceID   string    `json:"device_id,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
	RuleID     string    `json:"rule_id"`
	RuleName   string    `json:"rule_name"`
	Severity   string    `json:"severity"`
}

// ReplayReport, bir replay çalışmasının özetidir.
type ReplayReport struct {
	Scanned   int            `json:"scanned"`   // taranan geçmiş olay sayısı
	Matched   int            `json:"matched"`   // toplam eşleşme (bir olay birden çok kurala uyabilir)
	ByRule    map[string]int `json:"by_rule"`   // kural kimliği → eşleşme sayısı
	Matches   []ReplayMatch  `json:"matches"`   // örnek eşleşmeler (en fazla maxReplayMatches)
	Truncated bool           `json:"truncated"` // örnek listesi kırpıldı mı
}

// ReplayDetections, verilen kuralları zaman-pencereli (EventFilter) geçmiş olaylara
// uygular ve eşleşme raporu döner. Aday kuralların DURUMU (draft/retired) YOK SAYILIR —
// replay'in amacı henüz üretimde olmayan bir kuralı test etmektir; bu yüzden kurallar
// değerlendirmeden önce etkinleştirilir.
func (s *Service) ReplayDetections(ctx context.Context, f EventFilter, rules []detect.Rule) (ReplayReport, error) {
	eng := detect.NewEngine(activateForReplay(rules))
	if f.Limit <= 0 || f.Limit > replayScanCap {
		f.Limit = replayScanCap
	}
	rows, err := s.store.QueryEvents(ctx, f)
	if err != nil {
		return ReplayReport{}, err
	}
	rep := ReplayReport{ByRule: map[string]int{}}
	for _, r := range rows {
		rep.Scanned++
		ev := model.Event{
			EventID:    r.ID,
			DeviceID:   r.DeviceID,
			Category:   r.Category,
			Severity:   r.Severity,
			Message:    r.Message,
			OccurredAt: r.OccurredAt,
			Details:    string(r.Details),
		}
		for _, d := range eng.Evaluate(ev) {
			rep.Matched++
			rep.ByRule[d.RuleID]++
			if len(rep.Matches) < maxReplayMatches {
				rep.Matches = append(rep.Matches, ReplayMatch{
					EventID:    r.ID,
					DeviceID:   r.DeviceID,
					OccurredAt: r.OccurredAt,
					RuleID:     d.RuleID,
					RuleName:   d.RuleName,
					Severity:   d.Severity,
				})
			} else {
				rep.Truncated = true
			}
		}
	}
	return rep, nil
}

// activateForReplay, kuralların bir kopyasını DURUM alanı temizlenmiş (etkin) döner.
// Böylece draft/retired aday kurallar da replay'de değerlendirilir. Orijinali değiştirmez.
func activateForReplay(rules []detect.Rule) []detect.Rule {
	if len(rules) == 0 {
		return nil // NewEngine varsayılan kural setini kullanır
	}
	out := make([]detect.Rule, len(rules))
	copy(out, rules)
	for i := range out {
		out[i].Status = "active"
	}
	return out
}

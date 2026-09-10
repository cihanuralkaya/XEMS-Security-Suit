package adminread

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Bu dosya, bir cihazın olaylarını tek bir SALDIRI HİKÂYESİ (attack story) —
// kill-chain aşamalarına göre sıralanmış anlatı — olarak birleştirir. Amaç, SOC
// analistinin yüzlerce olayı elle ilişkilendirmesini önlemektir. Sınıflandırma
// SAF ve testlidir.

// AttackStep, saldırı hikâyesindeki tek bir adımdır.
type AttackStep struct {
	At        time.Time `json:"at"`
	Stage     string    `json:"stage"`      // kill-chain aşaması
	StageRank int       `json:"stage_rank"` // aşamanın kill-chain sırası (görselleştirme)
	Severity  string    `json:"severity"`
	Category  string    `json:"category"`
	Message   string    `json:"message"`
}

// AttackStoryDTO, bir cihazın saldırı hikâyesidir.
type AttackStoryDTO struct {
	DeviceID    string       `json:"device_id"`
	Steps       []AttackStep `json:"steps"`
	Stages      []string     `json:"stages"`       // hikâyede görülen benzersiz aşamalar (sırayla)
	MaxSeverity string       `json:"max_severity"` // hikâyedeki en yüksek önem
}

// killChain, aşama → sıra (rank). Düşük rank önce gelir (erken kill-chain).
var killChain = map[string]int{
	"Initial Access":    1,
	"Execution":         2,
	"Persistence":       3,
	"Defense Evasion":   4,
	"Discovery":         5,
	"Command & Control": 6,
	"Exfiltration":      7,
	"Impact":            8,
	"Detection":         9, // sınıflandırılamayan güvenlik olayı
}

// classifyStage, bir olayı (kategori + mesaj) bir kill-chain aşamasına eşler.
func classifyStage(category, message string) (string, int) {
	m := strings.ToLower(message)
	contains := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(m, s) {
				return true
			}
		}
		return false
	}
	switch {
	case contains("dlp", "hassas veri", "veri sızıntısı"):
		return stage("Exfiltration")
	case contains("dga", "ioc eşleşmesi", "beacon", "c2", "periyodik", "dns tünelleme", "dns tunnel"):
		return stage("Command & Control")
	case contains("yanal hareket", "lateral"):
		return stage("Discovery")
	case contains("kurcalama", "tamper", "öz-tasdik", "self-attest", "imza geçersiz", "devre dışı"):
		return stage("Defense Evasion")
	case contains("wipe", "karantina", "quarantine", "fidye", "ransom"):
		return stage("Impact")
	}
	switch strings.ToUpper(category) {
	case "PROCESS":
		return stage("Execution")
	case "POLICY_VIOLATION":
		return stage("Persistence")
	case "NETWORK_DISCOVERY":
		return stage("Discovery")
	case "NETWORK_CONN":
		return stage("Command & Control")
	case "SECURITY":
		return stage("Detection")
	default:
		return stage("Detection")
	}
}

func stage(name string) (string, int) { return name, killChain[name] }

// BuildAttackStory, bir cihazın olaylarını zaman sıralı bir saldırı hikâyesine
// çevirir. Yalnız güvenlik-anlamlı olaylar (SYSTEM/AGENT_UPDATE hariç) dahil edilir.
// SAF fonksiyon (test edilebilir).
func BuildAttackStory(deviceID string, events []EventDTO) AttackStoryDTO {
	story := AttackStoryDTO{DeviceID: deviceID}
	seenStage := map[string]bool{}
	maxRank := 0
	for _, e := range events {
		cat := strings.ToUpper(e.Category)
		if cat == "SYSTEM" || cat == "AGENT_UPDATE" {
			continue // operasyonel gürültü — hikâyeye dahil değil
		}
		st, rank := classifyStage(e.Category, e.Message)
		story.Steps = append(story.Steps, AttackStep{
			At: e.OccurredAt, Stage: st, StageRank: rank,
			Severity: e.Severity, Category: e.Category, Message: e.Message,
		})
		if sevRankValue(e.Severity) > maxRank {
			maxRank = sevRankValue(e.Severity)
			story.MaxSeverity = strings.ToUpper(e.Severity)
		}
		if !seenStage[st] {
			seenStage[st] = true
		}
	}
	// Zamana göre sırala (kronolojik anlatı).
	sort.SliceStable(story.Steps, func(i, j int) bool {
		return story.Steps[i].At.Before(story.Steps[j].At)
	})
	// Benzersiz aşamaları kill-chain sırasına göre listele (görselleştirme rozeti).
	var stages []string
	for name := range seenStage {
		stages = append(stages, name)
	}
	sort.Slice(stages, func(i, j int) bool { return killChain[stages[i]] < killChain[stages[j]] })
	story.Stages = stages
	return story
}

// sevRankValue, önem düzeyini karşılaştırılabilir sayıya çevirir (yerel yardımcı).
func sevRankValue(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// DeviceAttackStory, bir cihazın son olaylarından saldırı hikâyesini oluşturur.
func (s *Service) DeviceAttackStory(ctx context.Context, deviceID string, limit int) (AttackStoryDTO, error) {
	events, err := s.Events(ctx, deviceID, "", "", limit)
	if err != nil {
		return AttackStoryDTO{}, err
	}
	return BuildAttackStory(deviceID, events), nil
}

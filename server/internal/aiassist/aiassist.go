// Package aiassist, SOC için SALT ÖNERİ üreten, sağlayıcıdan bağımsız bir
// yapay zekâ yardımcı katmanıdır (yol haritası §27). Bu katman YÜKSEK ETKİLİ
// eylemleri ASLA kendisi gerçekleştirmez: uyarı/olay özetleme, yanlış pozitif
// analizi, MITRE eşlemesi, iyileştirme önerisi gibi öneriler üretir ve bunları
// güvenlik akışından geçirir.
//
// Zorunlu güvenlik akışı (insan döngüde): AI Önerisi → Politika Denetimi →
// İnsan Onayı → SOAR → Eylem. Bu paketteki hiçbir ProposedAction kendiliğinden
// çalışmaz; yalnızca hem politika geçişi hem de açık insan onayı sağlandığında
// "uygulanabilir" kabul edilir. Eylemi SOAR/yürütme katmanı yapar, bu paket DEĞİL.
//
// Paket sağlayıcıdan bağımsızdır (LLM üreticisine bağımlılık yoktur) ve hiçbir ağ
// erişimi olmayan, deterministik, çevrimdışı bir varsayılan sağlayıcı (LocalProvider)
// içerir. Yalnızca standart kütüphaneye bağlıdır; gen/ veya db paketlerini kullanmaz.
package aiassist

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// Task, yardımcıdan istenen analiz türünü belirtir (sabit küme).
type Task string

// Desteklenen görev türleri.
const (
	TaskAlertSummary          Task = "alert_summary"
	TaskIncidentSummary       Task = "incident_summary"
	TaskFalsePositiveAnalysis Task = "false_positive_analysis"
	TaskMitreMapping          Task = "mitre_mapping"
	TaskRemediationSuggestion Task = "remediation_suggestion"
	TaskRootCause             Task = "root_cause"
	TaskExecutiveReport       Task = "executive_report"
	TaskQueryGeneration       Task = "query_generation"
	TaskAttackStory           Task = "attack_story"
)

// Request, sağlayıcıya verilen analiz isteğidir. Input serbest metin (ham uyarı,
// olay açıklaması, sorgu niyeti), Context ise yapılandırılmış ek bağlamdır.
type Request struct {
	Task    Task              `json:"task"`
	Input   string            `json:"input"`
	Context map[string]string `json:"context,omitempty"`
}

// ProposedAction, yardımcının ÖNERDİĞİ tek bir eylemdir. Bu yalnızca bir
// öneridir; hiçbir koşulda kendiliğinden çalışmaz. Yürütme için politika
// denetimi ve insan onayı (bkz. Gate) zorunludur.
type ProposedAction struct {
	Kind      string `json:"kind"`      // ör. "quarantine", "isolate", "create_case"
	Target    string `json:"target"`    // ör. host kimliği, dosya karması
	Rationale string `json:"rationale"` // önerinin gerekçesi
}

// Recommendation, bir sağlayıcının ürettiği öneri bütünüdür. Actions alanındaki
// her öğe SALT ÖNERİDİR; uygulanabilirliği yalnızca Gate üzerinden belirlenir.
type Recommendation struct {
	Task        Task             `json:"task"`
	Summary     string           `json:"summary"`
	Suggestions []string         `json:"suggestions,omitempty"`
	Confidence  float64          `json:"confidence"` // 0..1
	Actions     []ProposedAction `json:"actions,omitempty"`
}

// Provider, yapay zekâ arka ucunu soyutlayan sağlayıcıdan bağımsız arayüzdür.
// Gerçekleştirimler yerel/deterministik (LocalProvider) veya dış bir LLM köprüsü
// olabilir; çağıran kod sağlayıcı ayrıntısından habersizdir.
type Provider interface {
	// Analyze, verilen isteği analiz eder ve bir öneri döndürür. Hiçbir eylem
	// yürütmez; yalnızca Recommendation üretir.
	Analyze(ctx context.Context, req Request) (Recommendation, error)
}

// ErrEmptyInput, boş girdi için analiz istendiğinde döndürülür.
var ErrEmptyInput = errors.New("aiassist: boş girdi")

// clamp, bir değeri [0,1] aralığına sıkıştırır.
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// LocalProvider, ağ erişimi olmayan, deterministik, kural/sezgi tabanlı
// varsayılan sağlayıcıdır. Anahtar kelime sayımı, MITRE eşlemesi ve basit
// yanlış pozitif sezgileriyle çalışır; aynı girdi için her zaman aynı çıktıyı
// üretir. Bu, sağlayıcı dikişinin sıfır dış bağımlılıkla çalıştığını kanıtlar.
type LocalProvider struct{}

// NewLocalProvider, yeni bir LocalProvider oluşturur.
func NewLocalProvider() *LocalProvider { return &LocalProvider{} }

// mitreKeywords, belirgin anahtar kelimeleri ATT&CK teknik kimliklerine eşler.
// Statik ve denetlenebilirdir; dış bağımlılık gerektirmez.
var mitreKeywords = []struct {
	key  string
	id   string
	name string
}{
	{"powershell", "T1059", "Command and Scripting Interpreter"},
	{"cmd.exe", "T1059", "Command and Scripting Interpreter"},
	{"script", "T1059", "Command and Scripting Interpreter"},
	{"phishing", "T1566", "Phishing"},
	{"macro", "T1204", "User Execution"},
	{"mimikatz", "T1003", "OS Credential Dumping"},
	{"lsass", "T1003", "OS Credential Dumping"},
	{"brute", "T1110", "Brute Force"},
	{"scheduled task", "T1053", "Scheduled Task/Job"},
	{"schtasks", "T1053", "Scheduled Task/Job"},
	{"registry run", "T1547", "Boot or Logon Autostart Execution"},
	{"autostart", "T1547", "Boot or Logon Autostart Execution"},
	{"process injection", "T1055", "Process Injection"},
	{"injection", "T1055", "Process Injection"},
	{"exfiltration", "T1048", "Exfiltration Over Alternative Protocol"},
	{"beacon", "T1071", "Application Layer Protocol"},
	{"ransom", "T1486", "Data Encrypted for Impact"},
	{"encrypt", "T1486", "Data Encrypted for Impact"},
	{"disable defender", "T1562", "Impair Defenses"},
	{"impair", "T1562", "Impair Defenses"},
}

// fpSignals, bir uyarının yanlış pozitif olma olasılığını artıran ipuçlarıdır.
var fpSignals = []string{"test", "scan", "qa ", "staging", "known good", "whitelist", "allowlist", "benign", "maintenance", "deneme"}

// Analyze, isteği yerel sezgilerle analiz eder. Ağ erişimi yoktur.
func (p *LocalProvider) Analyze(ctx context.Context, req Request) (Recommendation, error) {
	if strings.TrimSpace(req.Input) == "" {
		return Recommendation{}, ErrEmptyInput
	}
	if err := ctx.Err(); err != nil {
		return Recommendation{}, err
	}
	lower := strings.ToLower(req.Input)

	switch req.Task {
	case TaskMitreMapping:
		return p.analyzeMitre(req, lower), nil
	case TaskFalsePositiveAnalysis:
		return p.analyzeFalsePositive(req, lower), nil
	case TaskRemediationSuggestion:
		return p.analyzeRemediation(req, lower), nil
	default:
		// AlertSummary, IncidentSummary, RootCause, ExecutiveReport,
		// QueryGeneration, AttackStory için deterministik özet üretilir.
		return p.analyzeSummary(req, lower), nil
	}
}

// matchMitre, metindeki anahtar kelimelere göre benzersiz teknik kimlikleri
// deterministik sırayla döndürür.
func matchMitre(lower string) []ProposedAction {
	seen := map[string]bool{}
	var out []ProposedAction
	for _, m := range mitreKeywords {
		if strings.Contains(lower, m.key) && !seen[m.id] {
			seen[m.id] = true
			out = append(out, ProposedAction{
				Kind:      "mitre_tag",
				Target:    m.id,
				Rationale: m.name + " (anahtar kelime: " + m.key + ")",
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// analyzeMitre, metni ATT&CK tekniklerine eşler.
func (p *LocalProvider) analyzeMitre(req Request, lower string) Recommendation {
	tags := matchMitre(lower)
	ids := make([]string, 0, len(tags))
	for _, t := range tags {
		ids = append(ids, t.Target)
	}
	conf := 0.2
	if len(ids) > 0 {
		conf = clamp01(0.5 + 0.15*float64(len(ids)))
	}
	summary := "Eşlenen teknik bulunamadı."
	if len(ids) > 0 {
		summary = "Eşlenen ATT&CK teknikleri: " + strings.Join(ids, ", ") + "."
	}
	return Recommendation{
		Task:        TaskMitreMapping,
		Summary:     summary,
		Suggestions: ids,
		Confidence:  conf,
		Actions:     tags,
	}
}

// analyzeFalsePositive, basit sezgilerle yanlış pozitif olasılığını değerlendirir.
func (p *LocalProvider) analyzeFalsePositive(req Request, lower string) Recommendation {
	var hits []string
	for _, s := range fpSignals {
		if strings.Contains(lower, s) {
			hits = append(hits, strings.TrimSpace(s))
		}
	}
	likelyFP := len(hits) > 0
	conf := clamp01(0.3 + 0.2*float64(len(hits)))
	var summary string
	var actions []ProposedAction
	if likelyFP {
		summary = "Muhtemel yanlış pozitif; tespit edilen sinyaller: " + strings.Join(hits, ", ") + "."
		actions = []ProposedAction{{
			Kind:      "create_case",
			Target:    "triage",
			Rationale: "Yanlış pozitif doğrulaması için insan incelemesi önerilir (otomatik kapatma YOK).",
		}}
	} else {
		summary = "Yanlış pozitif sinyali bulunamadı; gerçek pozitif gibi değerlendirilmeli."
		conf = clamp01(0.4)
		actions = []ProposedAction{{
			Kind:      "create_case",
			Target:    "investigation",
			Rationale: "Olası gerçek tehdit için vaka açılması önerilir.",
		}}
	}
	return Recommendation{
		Task:        TaskFalsePositiveAnalysis,
		Summary:     summary,
		Suggestions: hits,
		Confidence:  conf,
		Actions:     actions,
	}
}

// analyzeRemediation, eşlenen tekniklere göre iyileştirme eylemleri önerir.
func (p *LocalProvider) analyzeRemediation(req Request, lower string) Recommendation {
	var actions []ProposedAction
	var suggestions []string
	host := req.Context["host"]
	if host == "" {
		host = "etkilenen_varlik"
	}
	if strings.Contains(lower, "ransom") || strings.Contains(lower, "encrypt") {
		actions = append(actions, ProposedAction{Kind: "isolate", Target: host, Rationale: "Fidye yazılımı yayılımını durdurmak için ağdan izolasyon önerisi."})
		suggestions = append(suggestions, "Varlığı ağdan izole et")
	}
	if strings.Contains(lower, "mimikatz") || strings.Contains(lower, "lsass") {
		actions = append(actions, ProposedAction{Kind: "reset_credentials", Target: req.Context["account"], Rationale: "Kimlik bilgisi dökümü şüphesi; parola sıfırlama önerisi."})
		suggestions = append(suggestions, "Etkilenen hesapların parolalarını sıfırla")
	}
	if strings.Contains(lower, "malware") || strings.Contains(lower, "trojan") || strings.Contains(lower, "injection") {
		actions = append(actions, ProposedAction{Kind: "quarantine", Target: req.Context["file"], Rationale: "Zararlı örnek şüphesi; dosya karantinası önerisi."})
		suggestions = append(suggestions, "Şüpheli dosyayı karantinaya al")
	}
	if len(actions) == 0 {
		actions = append(actions, ProposedAction{Kind: "create_case", Target: "investigation", Rationale: "Belirgin bir iyileştirme deseni yok; manuel inceleme önerisi."})
		suggestions = append(suggestions, "Manuel inceleme için vaka aç")
	}
	conf := clamp01(0.35 + 0.15*float64(len(actions)))
	return Recommendation{
		Task:        TaskRemediationSuggestion,
		Summary:     "Önerilen iyileştirme adımları (yalnızca öneri, insan onayı gerekir).",
		Suggestions: suggestions,
		Confidence:  conf,
		Actions:     actions,
	}
}

// topKeywords, metindeki en sık geçen anlamlı kelimeleri deterministik sırayla döndürür.
func topKeywords(lower string, n int) []string {
	fields := strings.FieldsFunc(lower, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	counts := map[string]int{}
	for _, f := range fields {
		if len(f) < 4 || stopWords[f] {
			continue
		}
		counts[f]++
	}
	type kv struct {
		k string
		c int
	}
	var kvs []kv
	for k, c := range counts {
		kvs = append(kvs, kv{k, c})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].c != kvs[j].c {
			return kvs[i].c > kvs[j].c
		}
		return kvs[i].k < kvs[j].k
	})
	out := make([]string, 0, n)
	for i := 0; i < len(kvs) && i < n; i++ {
		out = append(out, kvs[i].k)
	}
	return out
}

// stopWords, özetlemede yoksayılan yaygın kelimelerdir.
var stopWords = map[string]bool{
	"this": true, "that": true, "with": true, "from": true, "have": true,
	"were": true, "been": true, "where": true, "which": true, "için": true,
	"olarak": true, "olan": true, "ile": true,
}

// analyzeSummary, genel görevler için deterministik bir özet üretir.
func (p *LocalProvider) analyzeSummary(req Request, lower string) Recommendation {
	kws := topKeywords(lower, 5)
	mitre := matchMitre(lower)
	ids := make([]string, 0, len(mitre))
	for _, m := range mitre {
		ids = append(ids, m.Target)
	}
	var b strings.Builder
	b.WriteString("Özet (")
	b.WriteString(string(req.Task))
	b.WriteString("): ")
	if len(kws) > 0 {
		b.WriteString("öne çıkan terimler [" + strings.Join(kws, ", ") + "]")
	} else {
		b.WriteString("belirgin terim yok")
	}
	if len(ids) > 0 {
		b.WriteString("; olası teknikler [" + strings.Join(ids, ", ") + "]")
	}
	b.WriteString(".")

	conf := clamp01(0.3 + 0.08*float64(len(kws)) + 0.1*float64(len(ids)))
	return Recommendation{
		Task:        req.Task,
		Summary:     b.String(),
		Suggestions: kws,
		Confidence:  conf,
		// Özet görevleri eylem önermez; yalnızca bilgilendiricidir.
		Actions: nil,
	}
}

// State, bir önerinin güvenlik akışındaki durumudur.
type State string

// Karar durumları.
const (
	StatePendingApproval State = "pending_approval" // onay bekliyor
	StateApproved        State = "approved"         // insan onayladı
	StateRejected        State = "rejected"         // insan reddetti
	StateBlocked         State = "blocked"          // politika engelledi
)

// Decision, bir önerinin güvenlik akışındaki değerlendirmesidir. Eylemlerin
// uygulanabilir olması için HEM politika geçişi HEM de açık insan onayı gerekir.
// Decision hiçbir eylemi kendisi yürütmez; yalnızca uygunluğu bildirir.
type Decision struct {
	State      State          `json:"state"`
	PolicyOK   bool           `json:"policy_ok"`
	ApprovedBy string         `json:"approved_by,omitempty"`
	RejectedBy string         `json:"rejected_by,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	DecidedAt  time.Time      `json:"decided_at,omitempty"`
	rec        Recommendation // değerlendirilen öneri
}

// Recommendation, kararın ilişkili olduğu öneriyi döndürür.
func (d *Decision) Recommendation() Recommendation { return d.rec }

// Actionable, eylemlerin yürütülmesine izin verilip verilmediğini bildirir.
// Yalnızca politika geçtiğinde VE insan onayladığında true döner. Bu metot
// hiçbir eylemi çalıştırmaz; yürütme kararını SOAR katmanına bırakır.
func (d *Decision) Actionable() bool {
	return d.State == StateApproved && d.PolicyOK
}

// ActionableActions, yalnızca Actionable() true ise önerilen eylemleri,
// aksi halde nil döndürür. Bu, yürütme katmanının güvenli erişim noktasıdır.
func (d *Decision) ActionableActions() []ProposedAction {
	if !d.Actionable() {
		return nil
	}
	return d.rec.Actions
}

// Gate, güvenlik akışını (politika + insan onayı) uygulayan kapıdır. Bir
// öneriyi değerlendirir ve eylemlerin ilerleyip ilerleyemeyeceğini belirler;
// ancak eylemi ASLA kendisi gerçekleştirmez. Onaylayan kişinin kimliğini kaydeder.
type Gate struct{}

// NewGate, yeni bir Gate oluşturur.
func NewGate() *Gate { return &Gate{} }

// Review, bir öneriyi politika sonucuyla değerlendirir. Politika başarısızsa
// karar doğrudan Blocked olur; aksi halde insan onayı beklenerek
// PendingApproval döner. Döndürülen Decision, Approve/Reject ile ilerletilir.
func (g *Gate) Review(rec Recommendation, policyOK bool) *Decision {
	d := &Decision{rec: rec, PolicyOK: policyOK}
	if !policyOK {
		d.State = StateBlocked
		d.Reason = "politika denetimi başarısız"
		d.DecidedAt = time.Now().UTC()
		return d
	}
	d.State = StatePendingApproval
	return d
}

// ErrNotPending, onay bekleme durumunda olmayan bir karar ilerletilmeye
// çalışıldığında döndürülür.
var ErrNotPending = errors.New("aiassist: karar onay bekleme durumunda değil")

// Approve, bir insan onaylayıcısı adına kararı onaylar. Yalnızca PendingApproval
// durumundaki kararlar onaylanabilir. Politika engeli varsa onay geçersizdir.
func (d *Decision) Approve(by string) error {
	if d.State != StatePendingApproval {
		return ErrNotPending
	}
	if strings.TrimSpace(by) == "" {
		return errors.New("aiassist: onaylayan kimliği boş olamaz")
	}
	d.State = StateApproved
	d.ApprovedBy = by
	d.DecidedAt = time.Now().UTC()
	return nil
}

// Reject, bir insan adına kararı reddeder; gerekçeyi kaydeder. Yalnızca
// PendingApproval durumundaki kararlar reddedilebilir.
func (d *Decision) Reject(by, reason string) error {
	if d.State != StatePendingApproval {
		return ErrNotPending
	}
	if strings.TrimSpace(by) == "" {
		return errors.New("aiassist: reddeden kimliği boş olamaz")
	}
	d.State = StateRejected
	d.RejectedBy = by
	d.Reason = reason
	d.DecidedAt = time.Now().UTC()
	return nil
}

// Assistant, bir Provider ile bir Gate'i birleştirir. Öneri üretir ve onu
// güvenlik akışına sokar; insan döngüde olmadan hiçbir eylem yürütülmez.
type Assistant struct {
	provider Provider
	gate     *Gate
}

// NewAssistant, verilen sağlayıcı ve kapı ile bir Assistant oluşturur. gate nil
// ise varsayılan bir Gate kullanılır.
func NewAssistant(p Provider, g *Gate) *Assistant {
	if g == nil {
		g = NewGate()
	}
	return &Assistant{provider: p, gate: g}
}

// Recommend, isteği sağlayıcıya analiz ettirir ve öneriyi döndürür. Yalnızca
// öneri üretimidir; bu aşamada hiçbir eylem değerlendirilmez veya yürütülmez.
func (a *Assistant) Recommend(ctx context.Context, req Request) (Recommendation, error) {
	return a.provider.Analyze(ctx, req)
}

// Review, bir öneriyi güvenlik kapısından geçirir ve PendingApproval (veya
// politika başarısızsa Blocked) durumunda bir karar döndürür.
func (a *Assistant) Review(rec Recommendation, policyOK bool) *Decision {
	return a.gate.Review(rec, policyOK)
}

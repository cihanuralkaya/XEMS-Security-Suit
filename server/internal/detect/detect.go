// Package detect, sunucu-taraflı tespit kural motorudur (Sigma-benzeri, hafif).
// Ajanın ürettiği ham olayları merkezi, ADLANDIRILMIŞ tespit kurallarına eşler:
// her kural bir kategori/mesaj örüntüsüne bakar, normalize edilmiş bir önem düzeyi
// ve MITRE ATT&CK tekniği atar. Böylece tespit içeriği ajan yeniden dağıtılmadan
// merkezden yönetilir ve SOC "hangi tespitlerin devrede olduğunu" görebilir.
//
// Bağımlılıksız (yalnız stdlib + mitre + model).
package detect

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"xems.corp/suite/server/internal/mitre"
	"xems.corp/suite/server/internal/model"
)

// Rule, bir tespit kuralıdır. Tüm belirtilen koşullar AND'lenir:
//   - Category boşsa her kategori eşleşir.
//   - Contains: TÜM parçalar (küçük/büyük harf duyarsız) mesajda geçmeli.
//   - MessageRegex (v2): mesaj bu regex'e uymalı (küçük/büyük harf duyarsız).
//   - Fields (v2): olayın Details JSON'unda her alan, belirtilen alt-dizeyi
//     (küçük/büyük harf duyarsız) içermeli — ör. {"disk_encryption":"off"}.
//   - MinSeverity (v2): olayın önem düzeyi en az bu olmalı (INFO<..<CRITICAL).
type Rule struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Category     string            `json:"category,omitempty"`
	Contains     []string          `json:"contains,omitempty"`
	MessageRegex string            `json:"message_regex,omitempty"`
	Fields       map[string]string `json:"fields,omitempty"`
	MinSeverity  string            `json:"min_severity,omitempty"`
	Severity     string            `json:"severity"` // kuralın atadığı normalize önem düzeyi
	Technique    mitre.Technique   `json:"technique"`
}

// Detection, eşleşen bir kuralın ürettiği tespittir.
type Detection struct {
	RuleID    string          `json:"rule_id"`
	RuleName  string          `json:"rule_name"`
	Severity  string          `json:"severity"`
	Technique mitre.Technique `json:"technique"`
}

// sevRank, önem düzeylerini sıralar (eşik karşılaştırması için).
var sevRank = map[string]int{"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

// compiledRule, bir kuralı ön-derlenmiş regex'iyle birlikte tutar.
type compiledRule struct {
	rule Rule
	re   *regexp.Regexp // MessageRegex derlenmiş; yoksa nil
}

// matches, derlenmiş kuralın verilen olaya uyup uymadığını söyler.
func (c compiledRule) matches(ev model.Event) bool {
	r := c.rule
	if r.Category != "" && r.Category != ev.Category {
		return false
	}
	if r.MinSeverity != "" && sevRank[ev.Severity] < sevRank[r.MinSeverity] {
		return false
	}
	msg := strings.ToLower(ev.Message)
	for _, sub := range r.Contains {
		if !strings.Contains(msg, strings.ToLower(sub)) {
			return false
		}
	}
	if c.re != nil && !c.re.MatchString(ev.Message) {
		return false
	}
	if len(r.Fields) > 0 {
		var d map[string]any
		if ev.Details == "" || json.Unmarshal([]byte(ev.Details), &d) != nil {
			return false
		}
		for k, want := range r.Fields {
			v, ok := d[k]
			if !ok {
				return false
			}
			if !strings.Contains(strings.ToLower(fmt.Sprintf("%v", v)), strings.ToLower(want)) {
				return false
			}
		}
	}
	return true
}

// Engine, sıralı bir kural listesini değerlendirir.
type Engine struct {
	rules []compiledRule
}

// NewEngine, verilen kurallarla motor kurar. Kural verilmezse yerleşik varsayılan
// kural seti kullanılır. Geçersiz MessageRegex taşıyan kural, regex koşulu
// olmadan yüklenir (savunmacı; operatör kuralları LoadRules'ta önceden doğrulanır).
func NewEngine(rules []Rule) *Engine {
	if len(rules) == 0 {
		rules = DefaultRules()
	}
	cr := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		c := compiledRule{rule: r}
		if r.MessageRegex != "" {
			if re, err := regexp.Compile("(?i)" + r.MessageRegex); err == nil {
				c.re = re
			}
		}
		cr = append(cr, c)
	}
	return &Engine{rules: cr}
}

// Evaluate, olaya uyan tüm tespitleri (sıralı) döner. Eşleşme yoksa nil.
func (e *Engine) Evaluate(ev model.Event) []Detection {
	var out []Detection
	for _, c := range e.rules {
		if c.matches(ev) {
			r := c.rule
			out = append(out, Detection{RuleID: r.ID, RuleName: r.Name, Severity: r.Severity, Technique: r.Technique})
		}
	}
	return out
}

// Rules, motorun kurallarını (katalog/görünürlük için) döner.
func (e *Engine) Rules() []Rule {
	cp := make([]Rule, len(e.rules))
	for i, c := range e.rules {
		cp[i] = c.rule
	}
	return cp
}

// LoadRules, operatör-tanımlı özel tespit kurallarını JSON dizisinden ayrıştırır.
// Her kural en az id/name/severity taşımalıdır (aksi halde hata). Böylece SOC,
// koda dokunmadan kuruma özgü tespit içeriği ekleyebilir.
func LoadRules(r io.Reader) ([]Rule, error) {
	var rules []Rule
	if err := json.NewDecoder(r).Decode(&rules); err != nil {
		return nil, fmt.Errorf("detect: kural JSON ayrıştırılamadı: %w", err)
	}
	for i, rr := range rules {
		if rr.ID == "" || rr.Name == "" || rr.Severity == "" {
			return nil, fmt.Errorf("detect: kural[%d] eksik alan (id/name/severity zorunlu)", i)
		}
		if rr.MessageRegex != "" {
			if _, err := regexp.Compile(rr.MessageRegex); err != nil {
				return nil, fmt.Errorf("detect: kural[%d] (%s) message_regex geçersiz: %w", i, rr.ID, err)
			}
		}
		if rr.MinSeverity != "" && sevRank[rr.MinSeverity] == 0 {
			return nil, fmt.Errorf("detect: kural[%d] (%s) geçersiz min_severity %q", i, rr.ID, rr.MinSeverity)
		}
	}
	return rules, nil
}

// LoadRulesFile, bir dosyadan özel kural seti yükler.
func LoadRulesFile(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadRules(f)
}

// WithDefaults, yerleşik kurallara özel kuralları ekler (yerleşikler önce
// değerlendirilir, özel kurallar sonra).
func WithDefaults(extra []Rule) []Rule {
	return append(DefaultRules(), extra...)
}

// MITRE ATT&CK teknikleri (mitre paketiyle tutarlı).
var (
	tImpairDefenses = mitre.Technique{ID: "T1562", Name: "Impair Defenses", Tactic: "Defense Evasion"}
	tScripting      = mitre.Technique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution"}
	tSupplyChain    = mitre.Technique{ID: "T1195", Name: "Supply Chain Compromise", Tactic: "Initial Access"}
	tUserExecution  = mitre.Technique{ID: "T1204", Name: "User Execution", Tactic: "Execution"}
	tProcInjection  = mitre.Technique{ID: "T1055", Name: "Process Injection", Tactic: "Defense Evasion"}
	tNetworkDiscov  = mitre.Technique{ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery"}
)

// DefaultRules, yerleşik tespit kural setidir. Ajanın gerçekte ürettiği olay
// kategorileri/mesajlarına dayanır.
func DefaultRules() []Rule {
	return []Rule{
		{ID: "XEMS-0001", Name: "Ajan kurcalama girişimi", Category: "SECURITY",
			Contains: []string{"kurcalama"}, Severity: "CRITICAL", Technique: tImpairDefenses},
		{ID: "XEMS-0002", Name: "İmzasız/sahte script reddedildi", Category: "SECURITY",
			Contains: []string{"script"}, Severity: "HIGH", Technique: tScripting},
		{ID: "XEMS-0003", Name: "Sahte/bozuk OTA güncelleme reddedildi", Category: "SECURITY",
			Contains: []string{"güncelleme"}, Severity: "HIGH", Technique: tSupplyChain},
		{ID: "XEMS-0004", Name: "Davranışsal anomali", Category: "SECURITY",
			Contains: []string{"anomali"}, Severity: "HIGH", Technique: tProcInjection},
		{ID: "XEMS-0005", Name: "Yasaklı süreç yürütmesi", Category: "POLICY_VIOLATION",
			Severity: "HIGH", Technique: tUserExecution},
		{ID: "XEMS-0006", Name: "Ağ hizmet keşfi", Category: "NETWORK_DISCOVERY",
			Severity: "LOW", Technique: tNetworkDiscov},
		// v2: PROCESS telemetrisi üzerinde regex-tabanlı şüpheli-araç tespiti
		// (saldırgan araçları / yaşam-alanı-dışı ikili kullanımı).
		{ID: "XEMS-0007", Name: "Şüpheli süreç/araç yürütmesi", Category: "PROCESS",
			MessageRegex: `mimikatz|psexec|\bnc\.exe|\bncat|powershell.*(-enc|-encodedcommand)|certutil.*-urlcache|rundll32.*javascript|regsvr32.*scrobj`,
			Severity:     "HIGH", Technique: tScripting},
	}
}

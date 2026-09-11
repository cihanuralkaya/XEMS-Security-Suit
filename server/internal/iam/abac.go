// Package iam, kurumsal kimlik entegrasyonu (Enterprise Identity) katmanını
// sağlar: RBAC + MFA'yı tamamlayan ABAC (öznitelik-tabanlı erişim denetimi),
// harici bir kütüphane olmadan OIDC ID-token doğrulaması, SCIM 2.0 User şema
// alt kümesi ve SAML entegrasyon dikişi. Tüm ilkel işlemler yalnız standart
// kütüphaneyle gerçeklenir; deterministik ve yan-etkisizdir (yol haritası §35).
package iam

import (
	"sort"
	"strings"
	"sync"
)

// Attributes, bir özne veya kaynağın öznitelik kümesidir (örn. "role",
// "tenant", "clearance"). Anahtarlar ad-alanı önekiyle ("subject.", "resource.")
// sorgulanır; bu yapı önekleri İÇERMEZ, önek değerlendirme sırasında eklenir.
type Attributes map[string]string

// Request, tek bir erişim kararı için gereken girdilerdir: özne öznitelikleri,
// kaynak öznitelikleri ve yapılmak istenen eylem ("action").
type Request struct {
	Subject  Attributes `json:"subject"`
	Resource Attributes `json:"resource"`
	Action   string     `json:"action"`
}

// Condition, bir politikanın tek bir eşleşme koşuludur. Key ad-alanlı bir
// anahtardır ("subject.role", "resource.tenant"); Op karşılaştırma işlecidir;
// Value beklenen değerdir. "in" işleci için Value virgülle ayrılmış bir
// listedir ("admin,auditor").
type Condition struct {
	Key   string `json:"key"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// Effect, bir politikanın eşleştiğinde verdiği karardır.
type Effect string

const (
	// EffectAllow, eşleşen politikanın erişime izin verdiğini belirtir.
	EffectAllow Effect = "allow"
	// EffectDeny, eşleşen politikanın erişimi reddettiğini belirtir.
	EffectDeny Effect = "deny"
)

// Desteklenen karşılaştırma işleçleri.
const (
	// OpEq, değerlerin tam eşitliğini test eder.
	OpEq = "eq"
	// OpNe, değerlerin eşit olmadığını test eder.
	OpNe = "ne"
	// OpIn, özniteliğin virgülle ayrılmış küme içinde olup olmadığını test eder.
	OpIn = "in"
	// OpContains, özniteliğin Value'yu alt-dizi olarak içerdiğini test eder.
	OpContains = "contains"
	// OpPrefix, özniteliğin Value ile başladığını test eder.
	OpPrefix = "prefix"
)

// Policy, bir etki (allow/deny) ile o etkinin uygulanması için hepsi birden
// sağlanması gereken koşul kümesidir (mantıksal AND). Match boşsa politika her
// isteğe eşleşir (catch-all).
type Policy struct {
	ID     string      `json:"id"`
	Effect Effect      `json:"effect"`
	Match  []Condition `json:"match"`
}

// Engine, bir politika kümesini tutan ve erişim kararı veren ABAC motorudur.
// Eşzamanlı kullanım için güvenlidir.
type Engine struct {
	mu       sync.RWMutex
	policies []Policy
}

// NewEngine, verilen politikalarla bir motor oluşturur. policies kopyalanır;
// çağıranın dilimini sonradan değiştirmesi motoru etkilemez.
func NewEngine(policies []Policy) *Engine {
	cp := make([]Policy, len(policies))
	copy(cp, policies)
	return &Engine{policies: cp}
}

// AddPolicy, motora çalışma zamanında bir politika ekler.
func (e *Engine) AddPolicy(p Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = append(e.policies, p)
}

// Evaluate, bir isteği deny-overrides (reddetme önceliklidir) stratejisiyle
// değerlendirir: eşleşen herhangi bir deny varsa erişim reddedilir ve o
// politikanın ID'si döner; yoksa eşleşen ilk allow izin verir; hiçbiri
// eşleşmezse varsayılan olarak reddedilir (fail-closed). Dönüş deterministiktir:
// politikalar tanımlanma sırasında taranır, eşleşen deny'ler arasından en
// küçük ID seçilir.
func (e *Engine) Evaluate(req Request) (allowed bool, matchedPolicy string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var denyIDs []string
	var firstAllow string
	for _, p := range e.policies {
		if !matchPolicy(p, req) {
			continue
		}
		switch p.Effect {
		case EffectDeny:
			denyIDs = append(denyIDs, p.ID)
		case EffectAllow:
			if firstAllow == "" {
				firstAllow = p.ID
			}
		}
	}
	if len(denyIDs) > 0 {
		sort.Strings(denyIDs)
		return false, denyIDs[0]
	}
	if firstAllow != "" {
		return true, firstAllow
	}
	return false, ""
}

// matchPolicy, politikanın tüm koşullarının istek için sağlanıp sağlanmadığını
// döndürür (boş koşul kümesi her zaman eşleşir).
func matchPolicy(p Policy, req Request) bool {
	for _, c := range p.Match {
		if !matchCondition(c, req) {
			return false
		}
	}
	return true
}

// lookup, ad-alanlı bir anahtarı ("subject.role" / "resource.tenant") ilgili
// öznitelik kümesinden çözer. Önek yoksa veya bilinmeyense (false) döner.
func lookup(req Request, key string) (string, bool) {
	if rest, ok := strings.CutPrefix(key, "subject."); ok {
		v, present := req.Subject[rest]
		return v, present
	}
	if rest, ok := strings.CutPrefix(key, "resource."); ok {
		v, present := req.Resource[rest]
		return v, present
	}
	return "", false
}

// matchCondition, tek bir koşulu değerlendirir. Anahtar öznitelik kümesinde
// yoksa koşul — ne/eq dahil — sağlanmamış kabul edilir (fail-closed; eksik bir
// özniteliğin "ne" ile dolaylı izin üretmesini engeller).
func matchCondition(c Condition, req Request) bool {
	actual, present := lookup(req, c.Key)
	if !present {
		return false
	}
	switch c.Op {
	case OpEq:
		return actual == c.Value
	case OpNe:
		return actual != c.Value
	case OpIn:
		for _, item := range strings.Split(c.Value, ",") {
			if actual == strings.TrimSpace(item) {
				return true
			}
		}
		return false
	case OpContains:
		return strings.Contains(actual, c.Value)
	case OpPrefix:
		return strings.HasPrefix(actual, c.Value)
	default:
		// Bilinmeyen işleç: fail-closed.
		return false
	}
}

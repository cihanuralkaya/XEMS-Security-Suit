// Package scope, MERKEZİ ve BYPASS-EDİLEMEZ Scope / Rules-of-Engagement (ROE)
// guardrail motorudur (roadmap §4). Yüksek-etkili her operasyon — WIPE, LOCK,
// RESTART, QUARANTINE, uzak komut, policy-enforcement, aktif tarama — hedefe
// uygulanmadan ÖNCE bu motordan geçmelidir. Böylece scope kontrolü yalnız API
// katmanında değil, komut/worker/agent/SOAR yollarının hepsinde tek noktada
// uygulanır.
//
// Tasarım ilkeleri:
//   - FAIL-CLOSED: eşleşen bir izin (allow) kuralı yoksa yüksek-etkili aksiyon
//     REDDEDİLİR. Yanlış yapılandırma "her şeye izin ver" anlamına gelmez.
//   - EXCLUDED ÖNCELİKLİDİR: hariç-tutulan bir hedef, allow eşleşse bile reddedilir
//     (ör. "production.example.com" asla taranmaz/wipe edilmez).
//   - ACTION-GATED ROE: destructive/exploitation gibi sınıflar ayrıca açıkça
//     etkinleştirilmeden çalışmaz (varsayılan kapalı).
//   - SAF ve TESTLİ: dış bağımlılık yok; net.IP/CIDR dışında yalnız stdlib.
package scope

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// Action, korunması gereken bir operasyon türüdür.
type Action string

const (
	ActionPassiveScan   Action = "passive_scan"
	ActionActiveScan    Action = "active_scan"
	ActionExploitation  Action = "exploitation"
	ActionRemoteCommand Action = "remote_command"
	ActionPolicyEnforce Action = "policy_enforce"
	ActionQuarantine    Action = "quarantine"
	ActionRestart       Action = "restart"
	ActionLock          Action = "lock"
	ActionWipe          Action = "wipe"
)

// Impact, bir aksiyonun etki sınıfıdır (ROE seviyeleri).
type Impact int

const (
	Passive     Impact = iota // salt gözlem
	Active                    // hedefe dokunan tarama
	Remote                    // uzak komut yürütme
	HighImpact                // kilitleme/yeniden başlatma/karantina/policy
	Destructive               // geri döndürülemez (WIPE, exploitation)
)

func (i Impact) String() string {
	switch i {
	case Passive:
		return "PASSIVE"
	case Active:
		return "ACTIVE"
	case Remote:
		return "REMOTE_ACTION"
	case HighImpact:
		return "HIGH_IMPACT"
	case Destructive:
		return "DESTRUCTIVE"
	default:
		return "UNKNOWN"
	}
}

// impactOf, her aksiyonu bir etki sınıfına eşler.
var impactOf = map[Action]Impact{
	ActionPassiveScan:   Passive,
	ActionActiveScan:    Active,
	ActionExploitation:  Destructive,
	ActionRemoteCommand: Remote,
	ActionPolicyEnforce: HighImpact,
	ActionQuarantine:    HighImpact,
	ActionRestart:       HighImpact,
	ActionLock:          HighImpact,
	ActionWipe:          Destructive,
}

// ImpactOf, aksiyonun etki sınıfını döndürür (bilinmeyen aksiyon = Destructive,
// yani en katı sınıf — fail-closed).
func ImpactOf(a Action) Impact {
	if imp, ok := impactOf[a]; ok {
		return imp
	}
	return Destructive
}

// Target, üzerinde işlem yapılacak varlıktır. Alanlar bilindiği kadarıyla doldurulur;
// boş alanlar ilgili seçici tarafından yok sayılır.
type Target struct {
	Tenant      string
	Environment string // "production" | "staging" | ...
	DeviceID    string
	Host        string
	Domain      string
	Service     string
	IP          net.IP
	Port        int
}

// Selector, bir hedef kümesini tanımlar. Boş bir alan "bu boyutta kısıt yok" demektir.
type Selector struct {
	Domains      []string // "*.example.com" (soneki eşleşme) veya tam alan adı
	Networks     []string // CIDR: "10.0.0.0/16", "2001:db8::/32"
	Hosts        []string // tam host adı (küçük harfe duyarsız)
	Devices      []string // cihaz kimliği (tam)
	Tenants      []string // kiracı kimliği (tam)
	Environments []string // ortam adı (tam, küçük harfe duyarsız)
	Ports        []int
}

// Policy, tek bir kiracı (ya da global) için scope + ROE kurallarıdır.
type Policy struct {
	Allowed  Selector
	Excluded Selector
	// Actions, aksiyon-bazlı ROE anahtarlarıdır. Bir aksiyon burada YOKSA:
	// Passive/Active/Remote/HighImpact için "allow eşleşmesine bak"; Destructive
	// için VARSAYILAN KAPALI (açıkça true olmalı).
	Actions map[Action]bool
	// RateLimitRPS, bu scope için önerilen saniyedeki istek limitidir (0 = sınırsız);
	// motor bunu taşır, uygulaması çağırana (ratelimit paketi) bırakılır.
	RateLimitRPS float64
}

// Decision, bir yetkilendirme sonucudur.
type Decision struct {
	Allowed bool
	Impact  Impact
	Reason  string
}

// Engine, kiracı-bazlı Policy'leri tutar ve yetkilendirme kararı verir.
// Eşzamanlı erişime güvenlidir.
type Engine struct {
	mu        sync.RWMutex
	global    *Policy
	perTenant map[string]*Policy
}

// New, isteğe bağlı bir global (tüm kiracılara uygulanan taban) policy ile motor kurar.
func New(global *Policy) *Engine {
	return &Engine{global: global, perTenant: map[string]*Policy{}}
}

// SetTenantPolicy, bir kiracıya özel policy atar (nil = kaldır).
func (e *Engine) SetTenantPolicy(tenant string, p *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p == nil {
		delete(e.perTenant, tenant)
		return
	}
	e.perTenant[tenant] = p
}

// policyFor, kiracının policy'sini (yoksa global'i) döndürür.
func (e *Engine) policyFor(tenant string) *Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if p, ok := e.perTenant[tenant]; ok {
		return p
	}
	return e.global
}

// Authorize, hedef+aksiyon için kararı döndürür. FAIL-CLOSED: policy yoksa yalnız
// Passive'e izin verilir; yüksek-etkili aksiyonlar reddedilir.
func (e *Engine) Authorize(t Target, a Action) Decision {
	imp := ImpactOf(a)
	p := e.policyFor(t.Tenant)

	if p == nil {
		if imp == Passive {
			return Decision{Allowed: true, Impact: imp, Reason: "policy yok; yalnız pasif izinli"}
		}
		return Decision{Allowed: false, Impact: imp,
			Reason: fmt.Sprintf("scope policy tanımsız — %s reddedildi (fail-closed)", imp)}
	}

	// 1) Excluded önceliklidir.
	if field, ok := matchSelector(p.Excluded, t); ok {
		return Decision{Allowed: false, Impact: imp,
			Reason: fmt.Sprintf("hedef hariç-tutma listesinde (%s)", field)}
	}

	// 2) Allowed eşleşmesi gereklidir (Passive dışında da fail-closed).
	if !allowedEmpty(p.Allowed) {
		if _, ok := matchSelector(p.Allowed, t); !ok {
			return Decision{Allowed: false, Impact: imp, Reason: "hedef izin verilen scope dışında"}
		}
	} else if imp > Passive {
		// Allowed hiç tanımlı değilse yüksek-etkili aksiyon reddedilir.
		return Decision{Allowed: false, Impact: imp,
			Reason: fmt.Sprintf("allow-scope boş — %s reddedildi (fail-closed)", imp)}
	}

	// 3) Action-gated ROE.
	if allow, set := p.Actions[a]; set {
		if !allow {
			return Decision{Allowed: false, Impact: imp,
				Reason: fmt.Sprintf("ROE: %q aksiyonu devre dışı", a)}
		}
	} else if imp == Destructive {
		return Decision{Allowed: false, Impact: imp,
			Reason: fmt.Sprintf("ROE: yıkıcı aksiyon %q açıkça etkinleştirilmemiş", a)}
	}

	return Decision{Allowed: true, Impact: imp, Reason: "scope+ROE onayladı"}
}

// allowedEmpty, allow seçicisinin hiçbir kısıt taşımadığını bildirir.
func allowedEmpty(s Selector) bool {
	return len(s.Domains) == 0 && len(s.Networks) == 0 && len(s.Hosts) == 0 &&
		len(s.Devices) == 0 && len(s.Tenants) == 0 && len(s.Environments) == 0 &&
		len(s.Ports) == 0
}

// matchSelector, hedefin seçiciyle eşleşip eşleşmediğini ve eşleşen boyutu döndürür.
// Herhangi bir boyutta eşleşme yeterlidir (OR semantiği).
func matchSelector(s Selector, t Target) (string, bool) {
	if t.Domain != "" {
		for _, d := range s.Domains {
			if domainMatch(d, t.Domain) {
				return "domain", true
			}
		}
	}
	if t.IP != nil {
		for _, c := range s.Networks {
			if cidrMatch(c, t.IP) {
				return "network", true
			}
		}
	}
	if t.Host != "" && containsFold(s.Hosts, t.Host) {
		return "host", true
	}
	if t.DeviceID != "" && contains(s.Devices, t.DeviceID) {
		return "device", true
	}
	if t.Tenant != "" && contains(s.Tenants, t.Tenant) {
		return "tenant", true
	}
	if t.Environment != "" && containsFold(s.Environments, t.Environment) {
		return "environment", true
	}
	if t.Port != 0 {
		for _, p := range s.Ports {
			if p == t.Port {
				return "port", true
			}
		}
	}
	return "", false
}

// domainMatch, "*.example.com" joker (soneki) eşleşmesini ve tam eşleşmeyi destekler.
// "*.example.com" hem "a.example.com" hem "example.com" ile eşleşir.
func domainMatch(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return false
}

// cidrMatch, IP'nin CIDR bloğunda olup olmadığını döndürür (geçersiz CIDR = eşleşmez).
func cidrMatch(cidr string, ip net.IP) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

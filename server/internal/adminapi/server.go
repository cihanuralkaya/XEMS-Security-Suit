// Package adminapi, admin domain servisini bir HTTP/JSON API olarak dışa açar.
//
// Kimlik doğrulama: /api/login parolayı (Argon2id) doğrular ve HMAC-imzalı,
// durumsuz bir oturum token'ı döner. Korumalı uçlar "Authorization: Bearer
// <token>" bekler. Yetki (RBAC) admin domain servisinde uygulanır.
package adminapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"xems.corp/suite/server/internal/admin"
	"xems.corp/suite/server/internal/adminread"
	"xems.corp/suite/server/internal/auditexport"
	"xems.corp/suite/server/internal/detect"
	"xems.corp/suite/server/internal/eventbus"
	"xems.corp/suite/server/internal/logingest"
	"xems.corp/suite/server/internal/metrics"
	"xems.corp/suite/server/internal/mitre"
	"xems.corp/suite/server/internal/model"
	"xems.corp/suite/server/internal/notify"
	"xems.corp/suite/server/internal/report"
	"xems.corp/suite/server/internal/security"
	"xems.corp/suite/server/internal/vuln"
)

//go:embed console.html
var consoleHTML []byte

// AuthStore, e-postadan yönetici kimliği + parola hash'i çözer.
type AuthStore interface {
	LookupAdmin(ctx context.Context, email string) (adminID, passwordHash string, err error)
}

// Server, admin HTTP API'sidir.
type Server struct {
	adminSvc     *admin.Service
	reader       *adminread.Service
	auth         AuthStore
	sessions     *security.SessionSigner
	ttl          time.Duration
	now          func() time.Time
	stream       *eventbus.Bus
	health       func(context.Context) error
	loginLim     *loginLimiter
	notice       string
	dummyHash    string // SEC-004: bilinmeyen e-postada sabit-zaman için sahte Argon2 hash
	sseConns     int64  // SEC-007: aktif SSE bağlantı sayısı (atomik)
	auditVerify  func(context.Context) error
	auditExpKey  ed25519.PrivateKey            // ayarlıysa /api/audit/export imzalı manifest üretir (#16)
	maintWindows func() []notify.Window        // ayarlıysa /api/maintenance bakım pencerelerini döner (#18)
	metricsToken string                        // ayarlıysa /metrics bu Bearer token ile açılır; boşsa uç kapalı
	ingestToken  string                        // ayarlıysa POST /api/ingest bu Bearer token ile açılır (#21)
	ingestSink   EventIngestor                 // harici log alımı için olay yazma yolu
	detector     atomic.Pointer[detect.Engine] // tespit kural kataloğu (görünürlük ucu; canlı hot-reload için atomik)
	vulnSet      *vuln.Set                     // zafiyet veri kümesi (nil = kapalı); envanterle eşleşir
	features     map[string]any                // dağıtım koruma-duruşu (opsiyonel özellik bayrakları)
}

// SetDetector, tespit kural motorunu bağlar (kural kataloğu ucu için). nil ise
// yerleşik varsayılan kurallar kullanılır.
func (s *Server) SetDetector(e *detect.Engine) {
	if e == nil {
		e = detect.NewEngine(nil)
	}
	s.detector.Store(e)
}

// SetFeatures, dağıtımın hangi opsiyonel korumalarının etkin olduğunu bildirir
// (main tarafından bir kez). /api/features ADMIN'e bu duruşu döner.
func (s *Server) SetFeatures(m map[string]any) { s.features = m }

// SetVulnSet, zafiyet veri kümesini (envanter eşleştirme) etkinleştirir. nil ise
// /api/vulnerabilities boş döner.
func (s *Server) SetVulnSet(v *vuln.Set) { s.vulnSet = v }

// EventIngestor, harici log alımının normalize edilmiş olayları yazdığı yoldur
// (ajan olay yazma yoluyla aynı: backend.SaveEvents).
type EventIngestor interface {
	SaveEvents(ctx context.Context, deviceID string, evs []model.Event) (uint64, error)
}

// SetIngest, POST /api/ingest harici log alım ucunu etkinleştirir: statik Bearer
// token (makine-makine) + olay yazma yolu. token boşsa uç kapalıdır (#21).
func (s *Server) SetIngest(sink EventIngestor, token string) {
	s.ingestSink, s.ingestToken = sink, token
}

// SetMetricsToken, Prometheus /metrics ucunu verilen statik Bearer token ile
// etkinleştirir. Boş bırakılırsa uç tamamen kapalıdır (cihaz sayıları gibi
// toplu veriyi kimliksiz sızdırmamak için güvenli varsayılan).
func (s *Server) SetMetricsToken(tok string) { s.metricsToken = tok }

// maxSSEConns, eşzamanlı SSE akış bağlantısı üst sınırıdır (SEC-007).
const maxSSEConns = 64

// defaultPrivacyNotice, KVKK aydınlatma metninin makul bir varsayılanıdır;
// kuruluma göre SetPrivacyNotice ile değiştirilebilir.
const defaultPrivacyNotice = "KVKK Aydınlatma: Bu cihaz kuruma aittir ve kurumsal " +
	"uç nokta güvenlik/yönetim (EDR/MDM) kapsamındadır. İş amaçlı kullanım " +
	"sırasında cihaz sağlık/güvenlik telemetrisi (çalışan süreçler, ağ keşfi, " +
	"güvenlik olayları) 6698 sayılı KVKK ve kurumsal politika uyarınca işlenir. " +
	"Veriler at-rest şifrelenir, erişim RBAC ile sınırlıdır ve saklama süresi " +
	"sonunda silinir. Veri sahibi erişim/silme talepleri için IT ile iletişime geçin."

// New oluşturur. Giriş ucu varsayılan olarak istemci başına 5 başarısız
// denemeden sonra 15 dk kilitlenir (kaba-kuvvet koruması).
func New(adminSvc *admin.Service, reader *adminread.Service, auth AuthStore, sessions *security.SessionSigner, ttl time.Duration) *Server {
	// SEC-004: bilinmeyen/pasif e-postada da Argon2 maliyeti ödensin diye rastgele
	// bir parolanın hash'i önceden hesaplanır (kullanıcı numaralandırmayı süre
	// bakımından sabitler). Hesaplanamazsa boş kalır (o durumda dallanma korunur).
	dummy := make([]byte, 16)
	_, _ = rand.Read(dummy)
	dummyHash, _ := security.HashPassword(string(dummy))
	s := &Server{
		adminSvc: adminSvc, reader: reader, auth: auth, sessions: sessions, ttl: ttl,
		now:       time.Now,
		loginLim:  newLoginLimiter(5, 15*time.Minute),
		notice:    defaultPrivacyNotice,
		dummyHash: dummyHash,
	}
	s.detector.Store(detect.NewEngine(nil)) // atomik alan literal'de saklanamaz; kurulumda varsayılan
	return s
}

// SetPrivacyNotice, KVKK aydınlatma metnini ayarlar (boş verilirse varsayılan
// korunur). Kurulum, kurumsal metni buradan geçebilir.
func (s *Server) SetPrivacyNotice(text string) {
	if text = strings.TrimSpace(text); text != "" {
		s.notice = text
	}
}

// SetLoginLimit, giriş kaba-kuvvet eşiğini ayarlar (test/yapılandırma için).
func (s *Server) SetLoginLimit(maxAttempts int, window time.Duration) {
	s.loginLim = newLoginLimiter(maxAttempts, window)
}

// SetStream, canlı SSE akışını (/api/stream) etkinleştirir. nil ise akış ucu
// 501 döner ve konsol yalnız periyodik yenilemeye düşer.
func (s *Server) SetStream(bus *eventbus.Bus) { s.stream = bus }

// SetHealthCheck, /readyz için depo sağlık kontrolünü bağlar (ör. db.Ping).
// Ayarlanmazsa /readyz yalnız süreç canlılığını (liveness gibi) döner.
func (s *Server) SetHealthCheck(fn func(context.Context) error) { s.health = fn }

// SetAuditVerifier, GET /api/audit/verify için denetim izi hash-zinciri
// doğrulayıcıyı bağlar (ör. backend.VerifyAuditChain).
func (s *Server) SetAuditVerifier(fn func(context.Context) error) { s.auditVerify = fn }

// SetAuditExportKey, GET /api/audit/export imzalı dışa aktarım için Ed25519 özel
// anahtarı bağlar (#16). nil/boşsa dışa aktarım imzasız (yalnız hash zinciri) olur.
func (s *Server) SetAuditExportKey(priv ed25519.PrivateKey) { s.auditExpKey = priv }

// SetMaintenanceProvider, GET /api/maintenance için bakım/bastırma pencerelerini
// sağlayan fonksiyonu bağlar (#18). nil ise uç boş liste döner.
func (s *Server) SetMaintenanceProvider(fn func() []notify.Window) { s.maintWindows = fn }

// Handler, yönlendirmeleri kayıtlı bir http.Handler döner.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Web yönetim konsolu (aynı köken — API çağrıları CORS'suz çalışır).
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		// SEC-008: script-src 'unsafe-inline' yerine per-request NONCE. Böylece
		// olası bir XSS'te enjekte edilen inline script çalışmaz (yalnız nonce'lu
		// tek script yüklenir). style-src 'unsafe-inline' kalır (inline style=
		// öznitelikleri; stil enjeksiyonu düşük risk). Konsol dış kaynak kullanmaz.
		nb := make([]byte, 16)
		_, _ = rand.Read(nb)
		nonce := base64.StdEncoding.EncodeToString(nb)
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(bytes.Replace(consoleHTML, []byte("__CSP_NONCE__"), []byte(nonce), 1))
	})
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/enrollment-tokens", s.authed(s.handleIssueToken))
	// Enrollment token yönetimi: listele (meta veri; ham token asla) + iptal.
	mux.HandleFunc("GET /api/enrollment-tokens", s.authed(s.handleListTokens))
	mux.HandleFunc("POST /api/enrollment-tokens/{id}/revoke", s.authed(s.handleRevokeToken))
	mux.HandleFunc("POST /api/devices/quarantine", s.authed(s.handleQuarantine))
	mux.HandleFunc("POST /api/devices/release", s.authed(s.handleRelease))
	mux.HandleFunc("POST /api/devices/collect-diagnostics", s.authed(s.handleCollectDiagnostics))
	mux.HandleFunc("POST /api/devices/revoke", s.authed(s.handleRevoke))
	mux.HandleFunc("GET /api/policies", s.authed(s.handleListPolicies))
	mux.HandleFunc("POST /api/policies", s.authed(s.handleCreatePolicy))
	mux.HandleFunc("POST /api/policies/assign", s.authed(s.handleAssignPolicy))
	// Kural editörü: politikaya kural ekle / kuralları listele (Go 1.22 {id}).
	mux.HandleFunc("POST /api/policies/{id}/rules", s.authed(s.handleAddRule))
	mux.HandleFunc("GET /api/policies/{id}/rules", s.authed(s.handleListRules))
	// Yönetici (admin) kullanıcı yönetimi (listeleme OPERATOR+; mutasyonlar ADMIN).
	mux.HandleFunc("GET /api/admins", s.authed(s.handleListAdmins))
	mux.HandleFunc("POST /api/admins", s.authed(s.handleCreateAdmin))
	mux.HandleFunc("POST /api/admins/{id}/role", s.authed(s.handleSetAdminRole))
	mux.HandleFunc("POST /api/admins/{id}/deactivate", s.authed(s.handleDeactivateAdmin))
	// MFA (2FA/TOTP) öz-yönetimi — her admin kendi hesabı için (VIEWER+).
	mux.HandleFunc("POST /api/mfa/enroll", s.authed(s.handleMFAEnroll))
	mux.HandleFunc("POST /api/mfa/activate", s.authed(s.handleMFAActivate))
	mux.HandleFunc("POST /api/mfa/disable", s.authed(s.handleMFADisable))
	// Okuma (görünürlük) uçları — herhangi bir kimlik doğrulanmış admin (VIEWER+).
	mux.HandleFunc("GET /api/devices", s.authed(s.handleListDevices))
	mux.HandleFunc("GET /api/devices/{id}", s.authed(s.handleDeviceDetail))
	mux.HandleFunc("GET /api/devices/{id}/export", s.authed(s.handleExportDevice))
	mux.HandleFunc("POST /api/devices/{id}/erase", s.authed(s.handleEraseDevice))
	mux.HandleFunc("POST /api/devices/{id}/tags", s.authed(s.handleSetDeviceTags))
	mux.HandleFunc("POST /api/devices/bulk", s.authed(s.handleBulkAction))
	mux.HandleFunc("GET /api/events", s.authed(s.handleListEvents))
	mux.HandleFunc("GET /api/summary", s.authed(s.handleSummary))
	mux.HandleFunc("GET /api/mitre/coverage", s.authed(s.handleMitreCoverage))
	mux.HandleFunc("GET /api/detections/rules", s.authed(s.handleDetectionRules))
	mux.HandleFunc("POST /api/detections/test", s.authed(s.handleTestDetection))
	mux.HandleFunc("POST /api/hunt", s.authed(s.handleHunt))
	mux.HandleFunc("GET /api/incidents", s.authed(s.handleIncidents))
	mux.HandleFunc("GET /api/incidents/{id}/timeline", s.authed(s.handleIncidentTimeline))
	mux.HandleFunc("GET /api/report", s.authed(s.handleReport))
	mux.HandleFunc("GET /api/coverage", s.authed(s.handleCoverage))
	mux.HandleFunc("GET /api/risk", s.authed(s.handleRisk))
	mux.HandleFunc("GET /api/compliance/frameworks", s.authed(s.handleFrameworks))
	mux.HandleFunc("GET /api/devices/{id}/attack-story", s.authed(s.handleAttackStory))
	mux.HandleFunc("GET /api/devices/{id}/graph", s.authed(s.handleEntityGraph))
	mux.HandleFunc("GET /api/metrics/trends", s.authed(s.handleMetricsTrends))
	mux.HandleFunc("GET /api/maintenance", s.authed(s.handleMaintenance))
	mux.HandleFunc("POST /api/hunt/saved", s.authed(s.handleSaveSearch))
	mux.HandleFunc("GET /api/hunt/saved", s.authed(s.handleListSavedSearches))
	mux.HandleFunc("DELETE /api/hunt/saved/{id}", s.authed(s.handleDeleteSavedSearch))
	mux.HandleFunc("GET /api/software", s.authed(s.handleSoftwareSearch))
	mux.HandleFunc("GET /api/vulnerabilities", s.authed(s.handleVulnerabilities))
	mux.HandleFunc("POST /api/events/{id}/ack", s.authed(s.handleAckEvent))
	mux.HandleFunc("POST /api/events/{id}/resolve", s.authed(s.handleResolveEvent))
	mux.HandleFunc("POST /api/events/{id}/case", s.authed(s.handleEventCase))
	mux.HandleFunc("POST /api/devices/{id}/collect-file", s.authed(s.handleCollectFile))
	mux.HandleFunc("POST /api/devices/{id}/lock", s.authed(s.handleLockDevice))
	mux.HandleFunc("POST /api/devices/{id}/restart", s.authed(s.handleRestartDevice))
	mux.HandleFunc("POST /api/devices/{id}/wipe", s.authed(s.handleWipeDevice))
	mux.HandleFunc("POST /api/devices/{id}/wipe/approve", s.authed(s.handleApproveWipe))
	mux.HandleFunc("POST /api/devices/{id}/wipe/cancel", s.authed(s.handleCancelWipe))
	mux.HandleFunc("GET /api/devices/pending-wipes", s.authed(s.handlePendingWipes))
	mux.HandleFunc("GET /api/devices/{id}/artifacts", s.authed(s.handleListArtifacts))
	mux.HandleFunc("GET /api/artifacts/{id}/download", s.authed(s.handleDownloadArtifact))
	mux.HandleFunc("GET /api/activity", s.authed(s.handleActivity))
	mux.HandleFunc("GET /api/features", s.authed(s.handleFeatures))
	mux.HandleFunc("GET /api/audit", s.authed(s.handleListAudit))
	mux.HandleFunc("GET /api/audit/verify", s.authed(s.handleVerifyAudit))
	mux.HandleFunc("GET /api/audit/export", s.authed(s.handleAuditExport))
	mux.HandleFunc("GET /api/stream", s.authed(s.handleStream))
	// Sağlık uçları (kimlik doğrulama YOK — orkestrasyon/LB/monitoring için).
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /api/notice", s.handleNotice)  // KVKK aydınlatma (public)
	mux.HandleFunc("GET /metrics", s.handleMetrics)    // Prometheus (statik token ile)
	mux.HandleFunc("POST /api/ingest", s.handleIngest) // harici log alımı (statik token ile, #21)
	return securityHeaders(mux)
}

// securityHeaders, tüm yanıtlara temel sertleştirme başlıkları ekler:
// MIME-sniffing kapalı, clickjacking (iframe) reddi, referrer sızıntısı yok.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// TLS-only sunucu: tarayıcıyı HTTPS'e kilitle (2 yıl). HTTP üzerinde
		// tarayıcı yok sayar.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		// Güçlü tarayıcı özelliklerini kapat (konsol hiçbirini kullanmaz).
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		// Hassas admin verisi önbelleğe alınmasın (SSE handler kendi no-cache'ini
		// sonradan yazar). CDN/proxy önbelleklemesini de engeller.
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// authed, Bearer oturum token'ını doğrulayıp adminID'yi handler'a geçirir.
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		id, ok := s.sessions.Verify(tok, s.now())
		if !ok {
			writeErr(w, http.StatusUnauthorized, "yetkisiz")
			return
		}
		// SEC-003: durumsuz token iptal edilemediğinden, her istekte yöneticinin
		// HÂLÂ aktif olduğu depodan teyit edilir. Pasifleştirilen/silinen yönetici
		// (rolü boş döner) token TTL'i dolmadan da anında engellenir — böylece
		// salt-okuma uçları da eski oturumla erişime kapanır.
		if err := s.adminSvc.EnsureRole(r.Context(), id, admin.RoleViewer); err != nil {
			writeErr(w, http.StatusUnauthorized, "oturum artık geçerli değil")
			return
		}
		h(w, r, id)
	}
}

// handleNotice, KVKK aydınlatma metnini döner (kimlik doğrulamasız — giriş
// öncesi konsolda gösterilir, şeffaflık gereği herkese açıktır).
func (s *Server) handleNotice(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"notice": s.notice})
}

// handleHealthz, süreç canlılığı (liveness): süreç yanıt veriyorsa 200.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"version":        metrics.Version(),
		"uptime_seconds": metrics.UptimeSeconds(),
	})
}

// handleReadyz, hazırlık (readiness): depo erişilebilirse 200, değilse 503.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.health != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.health(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "depo erişilemiyor"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Code     string `json:"code"` // MFA (TOTP) kodu — MFA etkin hesaplarda zorunlu
	}
	if !decode(w, r, &req) {
		return
	}
	// SEC-005: kaba-kuvvet sayacı IP+e-posta bileşimine bağlıdır. Böylece bir ters
	// vekil/LB arkasında (tüm istemciler aynı RemoteAddr) bir hesabın başarısız
	// denemeleri DİĞER yöneticileri kilitlemez (küresel-kilit DoS'u önlenir).
	key := clientIP(r) + "|" + strings.ToLower(strings.TrimSpace(req.Email))
	if ok, retry := s.loginLim.allowed(key); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "çok fazla başarısız deneme — sonra tekrar deneyin")
		return
	}

	adminID, hash, err := s.auth.LookupAdmin(r.Context(), req.Email)
	if err != nil || adminID == "" {
		// SEC-004: bilinmeyen/pasif e-postada da Argon2 maliyetini öde (sabit-zaman;
		// kullanıcı numaralandırma yan-kanalını kapatır). Sonuç yok sayılır.
		_, _ = security.VerifyPassword(s.dummyHash, req.Password)
		s.loginLim.recordFailure(key)
		metrics.IncLoginFailure()
		writeErr(w, http.StatusUnauthorized, "geçersiz kimlik bilgileri")
		return
	}
	ok, err := security.VerifyPassword(hash, req.Password)
	if err != nil || !ok {
		s.loginLim.recordFailure(key)
		metrics.IncLoginFailure()
		writeErr(w, http.StatusUnauthorized, "geçersiz kimlik bilgileri")
		return
	}
	// MFA (2FA): parola doğruysa ve hesapta MFA etkinse, ikinci faktör (TOTP) de
	// doğrulanmalı. Kod yoksa {mfa_required:true} ile 200 döneriz (token YOK) —
	// konsol bunu görüp kod ister; yanlış kod başarısız deneme sayar.
	if mfa, ok := s.auth.(MFAStore); ok {
		secret, enrolled, err := mfa.LookupMFA(r.Context(), adminID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "MFA durumu okunamadı")
			return
		}
		if enrolled {
			if strings.TrimSpace(req.Code) == "" {
				writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": true})
				return
			}
			if !security.VerifyTOTP(secret, req.Code, s.now()) {
				s.loginLim.recordFailure(key)
				metrics.IncLoginFailure()
				writeErr(w, http.StatusUnauthorized, "geçersiz doğrulama kodu")
				return
			}
		}
	}
	s.loginLim.recordSuccess(key)
	metrics.IncLoginSuccess()
	token := s.sessions.Sign(adminID, s.now().Add(s.ttl))
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// handleIngest, HARİCİ kaynaklardan (güvenlik duvarı, bulut, SIEM) gelen logları
// alır, XEMS olay modeline normalize eder ve olay yoluna yazar (#21 SIEM alımı).
// ingestToken ayarlı değilse uç KAPALIDIR (404). Ayarlıysa doğru Bearer token
// gerekir (sabit-zaman). Content-Type application/json → JSON dizi/nesne; aksi
// halde metin (satır başına CEF). Body üst sınırı 4 MiB.
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if s.ingestToken == "" || s.ingestSink == nil {
		http.NotFound(w, r)
		return
	}
	if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.ingestToken)) != 1 {
		writeErr(w, http.StatusUnauthorized, "geçersiz ingest token")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "gövde okunamadı")
		return
	}
	now := time.Now()
	var records []logingest.Record
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		records, err = logingest.NormalizeJSON(body, now)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		// Satır-başına CEF; tanınmayan satırlar atlanır.
		for _, line := range strings.Split(string(body), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if rec, e := logingest.NormalizeCEF(line, now); e == nil {
				records = append(records, rec)
			}
		}
	}
	if len(records) == 0 {
		writeErr(w, http.StatusBadRequest, "normalize edilebilir kayıt yok")
		return
	}
	// Kaynağa (device_id) göre grupla ve yaz.
	byDevice := map[string][]model.Event{}
	for _, rec := range records {
		byDevice[rec.DeviceID] = append(byDevice[rec.DeviceID], rec.Event)
	}
	accepted := 0
	for dev, evs := range byDevice {
		if _, err := s.ingestSink.SaveEvents(r.Context(), dev, evs); err != nil {
			writeErr(w, http.StatusInternalServerError, "olaylar yazılamadı")
			return
		}
		accepted += len(evs)
	}
	metrics.AddEventsIngested(accepted)
	writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted, "sources": len(byDevice)})
}

// handleMetrics, Prometheus metin-exposition'ını döner. metricsToken ayarlı
// değilse uç kapalıdır (404). Ayarlıysa doğru Bearer token gerekir (sabit-zaman
// karşılaştırma); cihaz sayıları özet okuyucudan, sayaçlar süreç-içinden gelir.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metricsToken == "" {
		http.NotFound(w, r)
		return
	}
	if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.metricsToken)) != 1 {
		writeErr(w, http.StatusUnauthorized, "geçersiz metrics token")
		return
	}
	sum, err := s.reader.Summary(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "özet okunamadı")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metrics.Write(w, metrics.Snapshot{
		DevicesTotal:       sum.DevicesTotal,
		DevicesOnline:      sum.DevicesOnline,
		DevicesOffline:     sum.DevicesOffline,
		DevicesQuarantined: sum.DevicesQuarantined,
		EventsBySeverity:   sum.EventsBySeverity,
		SSEConnections:     int(atomic.LoadInt64(&s.sseConns)),
	})
}

// MFAStore, MFA (TOTP) durumunu çözen isteğe bağlı arayüzdür. AuthStore bunu da
// karşılıyorsa login akışı ikinci faktörü zorlar; karşılamıyorsa MFA devre dışıdır
// (geriye dönük uyumluluk).
type MFAStore interface {
	LookupMFA(ctx context.Context, adminID string) (secret string, enrolled bool, err error)
}

// handleMFAEnroll, oturum sahibi için yeni bir TOTP sırrı üretir ve otpauth URI'si
// ile birlikte döner (authenticator uygulamasına eklenir). Etkin olması için
// activate gerekir.
func (s *Server) handleMFAEnroll(w http.ResponseWriter, r *http.Request, adminID string) {
	secret, uri, err := s.adminSvc.BeginMFAEnrollment(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_uri": uri})
}

// handleMFAActivate, girilen kodu doğrulayıp MFA'yı etkinleştirir.
func (s *Server) handleMFAActivate(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.ActivateMFA(r.Context(), adminID, req.Code)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enrolled": true})
}

// handleMFADisable, geçerli kod doğrulamasıyla MFA'yı kapatır.
func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.DisableMFA(r.Context(), adminID, req.Code)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enrolled": false})
}

// clientIP, istemci IP'sini RemoteAddr'dan çıkarır (port'suz). Not: X-Forwarded-For
// bilinçli olarak GÜVENİLMEZ (sahte olabilir); güvenilir bir ters vekil arkasında
// dağıtım, gerçek IP'yi RemoteAddr'da sunmalı ya da bu katman ona göre ayarlanmalı.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request, adminID string) {
	token, err := s.adminSvc.IssueEnrollmentToken(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"enrollment_token": token})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, adminID string) {
	// SEC-009: enrollment token meta verisi hassastır — OPERATOR+ gerekir.
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	tokens, err := s.reader.EnrollmentTokens(r.Context(), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.RevokeEnrollmentToken(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "token_revoked"})
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.QuarantineDevice(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "quarantine_queued"})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.ReleaseDevice(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "release_queued"})
}

func (s *Server) handleCollectDiagnostics(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.CollectDiagnostics(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "diagnostics_queued"})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.RevokeDevice(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, err := s.adminSvc.CreatePolicy(r.Context(), adminID, req.Name, req.Version)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"policy_id": id})
}

func (s *Server) handleAssignPolicy(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
		PolicyID string `json:"policy_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.AssignPolicy(r.Context(), adminID, req.DeviceID, req.PolicyID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request, adminID string) {
	policyID := r.PathValue("id")
	var req struct {
		Type       string  `json:"type"`
		Target     string  `json:"target"`
		Start      string  `json:"start"`
		End        string  `json:"end"`
		ActiveDays []int32 `json:"active_days"`
	}
	if !decode(w, r, &req) {
		return
	}
	in := admin.RuleInput{
		Type: req.Type, Target: req.Target, Start: req.Start, End: req.End, ActiveDays: req.ActiveDays,
	}
	if respondErr(w, s.adminSvc.AddPolicyRule(r.Context(), adminID, policyID, in)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rule_added"})
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request, adminID string) {
	rules, err := s.adminSvc.ListPolicyRules(r.Context(), adminID, r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleListAdmins(w http.ResponseWriter, r *http.Request, adminID string) {
	admins, err := s.adminSvc.ListAdmins(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"admins": admins})
}

func (s *Server) handleCreateAdmin(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	newID, err := s.adminSvc.CreateAdmin(r.Context(), adminID, req.Email, req.Password, admin.Role(req.Role))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"admin_id": newID})
}

func (s *Server) handleSetAdminRole(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.SetAdminRole(r.Context(), adminID, r.PathValue("id"), admin.Role(req.Role))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "role_updated"})
}

func (s *Server) handleDeactivateAdmin(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.DeactivateAdmin(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deactivated"})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request, _ string) {
	devices, err := s.reader.Devices(r.Context(), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	// Opsiyonel etiket filtresi (?tag=...): yalnız o etikete sahip cihazlar (filo
	// gruplama). Sunucu-tarafında filtreleme; büyük filolarda kısayol.
	if tag := strings.TrimSpace(r.URL.Query().Get("tag")); tag != "" {
		filtered := devices[:0]
		for _, d := range devices {
			for _, t := range d.Tags {
				if t == tag {
					filtered = append(filtered, d)
					break
				}
			}
		}
		devices = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

// handleBulkAction, bir etikete sahip TÜM cihazlara toplu eylem uygular (etiket-
// bazlı filo yönetimi). Gövde: {"tag":"prod","action":"quarantine|release|
// collect-diagnostics|assign-policy","policy_id":"..."}. Her cihaz için ilgili
// admin servis metodu çağrılır (RBAC + denetim izi servis içinde). matched=eşleşen
// cihaz, applied=başarıyla uygulanan sayısı döner.
func (s *Server) handleBulkAction(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Tag      string `json:"tag"`
		Action   string `json:"action"`
		PolicyID string `json:"policy_id"`
		DryRun   bool   `json:"dry_run"` // true: yalnız etkilenecek cihazları döndür, UYGULAMA
		Confirm  bool   `json:"confirm"` // büyük parti (> maxBulkDevices) için açık onay
	}
	if !decode(w, r, &req) {
		return
	}
	tag := strings.TrimSpace(req.Tag)
	if tag == "" {
		writeErr(w, http.StatusBadRequest, "tag gerekli")
		return
	}
	if req.Action == "assign-policy" && strings.TrimSpace(req.PolicyID) == "" {
		writeErr(w, http.StatusBadRequest, "assign-policy için policy_id gerekli")
		return
	}
	if req.Action != "assign-policy" && req.Action != "quarantine" &&
		req.Action != "release" && req.Action != "collect-diagnostics" {
		writeErr(w, http.StatusBadRequest, "geçersiz eylem")
		return
	}
	devices, err := s.reader.Devices(r.Context(), 0)
	if respondErr(w, err) {
		return
	}
	// Önce eşleşen cihazları topla (önizleme + parti sınırı için).
	type match struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
	}
	var matches []match
	for _, d := range devices {
		for _, t := range d.Tags {
			if t == tag {
				matches = append(matches, match{ID: d.ID, Hostname: d.Hostname})
				break
			}
		}
	}
	// KURU ÇALIŞTIRMA: hiçbir şey uygulanmaz; SOC önce etkiyi görür.
	if req.DryRun {
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "matched": len(matches), "devices": matches})
		return
	}
	// Parti sınırı: kazara filo-geneli yıkıcı eylemi önlemek için büyük partiler
	// açık onay ister.
	if len(matches) > maxBulkDevices && !req.Confirm {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "parti çok büyük (kazara filo-geneli eylem koruması)", "matched": len(matches),
			"max": maxBulkDevices, "hint": "confirm:true ile onaylayın veya etiketi daraltın",
		})
		return
	}
	applied := 0
	var firstErr error
	for _, m := range matches {
		var e error
		switch req.Action {
		case "assign-policy":
			e = s.adminSvc.AssignPolicy(r.Context(), adminID, m.ID, req.PolicyID)
		case "quarantine":
			e = s.adminSvc.QuarantineDevice(r.Context(), adminID, m.ID)
		case "release":
			e = s.adminSvc.ReleaseDevice(r.Context(), adminID, m.ID)
		case "collect-diagnostics":
			e = s.adminSvc.CollectDiagnostics(r.Context(), adminID, m.ID)
		}
		if e == nil {
			applied++
		} else if firstErr == nil {
			firstErr = e
		}
	}
	// RBAC reddi (ör. VIEWER) ilk denemede hata verir ve hiçbir cihaza uygulanmaz.
	if len(matches) > 0 && applied == 0 && firstErr != nil {
		respondErr(w, firstErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"matched": len(matches), "applied": applied})
}

// maxBulkDevices, açık onay olmadan toplu eylemin uygulanacağı üst sınırdır
// (kazara filo-geneli yıkıcı eylem koruması).
const maxBulkDevices = 500

// handleSetDeviceTags, cihazın etiketlerini ayarlar (OPERATOR+, servis içinde
// RBAC). Gövde: {"tags":["prod","finans"]}.
func (s *Server) handleSetDeviceTags(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Tags []string `json:"tags"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.SetDeviceTags(r.Context(), adminID, r.PathValue("id"), req.Tags)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tags": normalizeTagsForResponse(req.Tags)})
}

// normalizeTagsForResponse, yanıt için etiketleri kırpar/tekilleştirir (servis
// katmanıyla aynı normalize; yanıtta güncel hali göstermek için).
func normalizeTagsForResponse(tags []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func (s *Server) handleDeviceDetail(w http.ResponseWriter, r *http.Request, _ string) {
	detail, ok, err := s.reader.DeviceDetail(r.Context(), r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "cihaz bulunamadı")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_detail": detail})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request, _ string) {
	policies, err := s.reader.Policies(r.Context(), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
}

// handleExportDevice, KVKK ERİŞİM talebi: cihaz hakkındaki tüm veriyi tek JSON
// dosyası olarak indirir (ADMIN; AuthorizeExport RBAC + denetim yazar).
func (s *Server) handleExportDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	id := r.PathValue("id")
	if respondErr(w, s.adminSvc.AuthorizeExport(r.Context(), adminID, id)) {
		return
	}
	export, ok, err := s.reader.ExportDevice(r.Context(), id)
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "cihaz bulunamadı")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="kvkk-export-`+id+`.json"`)
	writeJSON(w, http.StatusOK, export)
}

// handleEraseDevice, KVKK SİLME talebi: cihazın davranışsal/telemetri verisini
// siler ve sertifikalarını iptal eder (ADMIN).
func (s *Server) handleEraseDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	report, err := s.adminSvc.EraseDevice(r.Context(), adminID, r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	events, err := s.reader.Events(r.Context(), q.Get("device_id"), q.Get("severity"), q.Get("category"), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request, _ string) {
	summary, err := s.reader.Summary(r.Context())
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary})
}

// handleMitreCoverage, sistemin eşleyebildiği MITRE ATT&CK teknikleri kataloğunu
// döner (kapsama matrisi). Konsol bunu ATT&CK kapsama görünümünde kullanır.
func (s *Server) handleMitreCoverage(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, map[string]any{"techniques": mitre.Catalog()})
}

// handleDetectionRules, devrede olan sunucu-taraflı tespit kurallarını (katalog)
// döner. Konsol bunu "hangi tespitler etkin" görünümünde kullanır.
func (s *Server) handleDetectionRules(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": s.detector.Load().Rules()})
}

// handleTestDetection, örnek bir olayı (kategori + mesaj) tespit motorundan
// geçirir ve hangi kuralların eşleştiğini döner (kuru çalıştırma / dry-run).
// SOC analistinin gerçek bir olay beklemeden tespit kapsamını doğrulaması
// içindir. Salt-okunur bir değerlendirmedir; hiçbir olay saklanmaz veya
// alarm üretilmez, bu yüzden herhangi bir kimliği doğrulanmış kullanıcı erişebilir.
func (s *Server) handleTestDetection(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		Category string `json:"category"`
		Message  string `json:"message"`
	}
	if !decode(w, r, &req) {
		return
	}
	matches := s.detector.Load().Evaluate(model.Event{Category: req.Category, Message: req.Message})
	writeJSON(w, http.StatusOK, map[string]any{
		"matches": matches,
		"matched": len(matches),
	})
}

// handleHunt, RETRO-HUNT / SIEM arama: geçmiş olaylar üzerinde çalışır. mode
// "rules" ise mevcut tespit motoru geçmiş olaylara UYGULANIR ("yeni kuralla eski
// olayları tarama" — bir gösterge sonradan öğrenildiğinde "zaten vurulduk mu?"),
// "query" ise zaman-pencereli + alan-filtreli arama sonuçlarını döner. Salt-okunur.
func (s *Server) handleHunt(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		Mode            string `json:"mode"` // "rules" | "query"
		DeviceID        string `json:"device_id"`
		Severity        string `json:"severity"`
		Category        string `json:"category"`
		MessageContains string `json:"message_contains"`
		Since           string `json:"since"` // RFC3339, opsiyonel
		Until           string `json:"until"`
		Limit           int    `json:"limit"`
	}
	if !decode(w, r, &req) {
		return
	}
	f := adminread.EventFilter{
		DeviceID: req.DeviceID, Severity: req.Severity, Category: req.Category,
		MessageContains: req.MessageContains, Limit: req.Limit,
	}
	if req.Since != "" {
		if t, err := time.Parse(time.RFC3339, req.Since); err == nil {
			f.Since = t
		}
	}
	if req.Until != "" {
		if t, err := time.Parse(time.RFC3339, req.Until); err == nil {
			f.Until = t
		}
	}
	events, err := s.reader.QueryEvents(r.Context(), f)
	if respondErr(w, err) {
		return
	}
	type hit struct {
		Event   adminread.EventDTO `json:"event"`
		Matched []string           `json:"matched,omitempty"`
	}
	hits := make([]hit, 0)
	if req.Mode == "rules" {
		eng := s.detector.Load()
		for _, e := range events {
			dets := eng.Evaluate(model.Event{
				Category: e.Category, Severity: e.Severity, Message: e.Message,
				Details: string(e.Details), OccurredAt: e.OccurredAt,
			})
			if len(dets) == 0 {
				continue
			}
			ids := make([]string, 0, len(dets))
			for _, d := range dets {
				ids = append(ids, d.RuleID)
			}
			hits = append(hits, hit{Event: e, Matched: ids})
		}
	} else { // "query" (varsayılan): filtrelenmiş olayları döndür
		for _, e := range events {
			hits = append(hits, hit{Event: e})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": req.Mode, "scanned": len(events), "hits": hits})
}

// buildReportData, güvenlik-duruş raporu verisini adminread + metrics'ten toplar.
func (s *Server) buildReportData(r *http.Request) (report.Data, error) {
	sum, err := s.reader.Summary(r.Context())
	if err != nil {
		return report.Data{}, err
	}
	incs, _ := s.reader.Incidents(r.Context(), 20)
	c := metrics.Counters()
	d := report.Data{
		GeneratedAt: s.now(), Title: "Güvenlik Duruş Raporu",
		DevicesTotal: sum.DevicesTotal, DevicesOnline: sum.DevicesOnline, DevicesOffline: sum.DevicesOffline,
		DevicesQuarantined: sum.DevicesQuarantined, NonCompliant: sum.NonCompliantDevices,
		EventsBySeverity: sum.EventsBySeverity, DevicesByOS: sum.DevicesByOS,
		Detections: c["detections"], AlertsRaised: c["alerts_raised"],
		AlertsSuppressed: c["alerts_suppressed"], IocHits: c["ioc_hits"],
	}
	for _, in := range incs {
		d.TopIncidents = append(d.TopIncidents, report.Incident{
			DeviceID: in.DeviceID, RuleID: in.RuleID, Severity: in.Severity, Count: in.Count, LastSeen: in.LastSeen,
		})
	}
	return d, nil
}

// handleReport, dışa aktarılabilir güvenlik-duruş raporu üretir (format=html
// varsayılan | csv). Salt-okunur; nokta-zaman görünümü (kurumsal/denetim/KVKK).
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, _ string) {
	d, err := s.buildReportData(r)
	if respondErr(w, err) {
		return
	}
	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="xems-report.csv"`)
		_, _ = w.Write([]byte(report.RenderCSV(d)))
		return
	case "json":
		// Makine-okunur rapor (otomasyon / zamanlanmış raporlama / SIEM).
		writeJSON(w, http.StatusOK, d)
		return
	}
	html, err := report.RenderHTML(d)
	if respondErr(w, err) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// handleEntityGraph, bir cihazın olaylarından cihaz-merkezli varlık grafiğini
// (süreç/alan adı/IP/dosya düğümleri) döner (IR investigation görselleştirmesi).
func (s *Server) handleEntityGraph(w http.ResponseWriter, r *http.Request, _ string) {
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		writeErr(w, http.StatusBadRequest, "cihaz kimliği zorunlu")
		return
	}
	g, err := s.reader.DeviceEntityGraph(r.Context(), id, intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// handleAttackStory, bir cihazın olaylarını kill-chain aşamalarına göre sıralanmış
// tek bir saldırı hikâyesi olarak döner (SOC investigation — yüzlerce olayı elle
// ilişkilendirmeye gerek kalmadan).
func (s *Server) handleAttackStory(w http.ResponseWriter, r *http.Request, _ string) {
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		writeErr(w, http.StatusBadRequest, "cihaz kimliği zorunlu")
		return
	}
	story, err := s.reader.DeviceAttackStory(r.Context(), id, intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, story)
}

// handleFrameworks, filo güvenlik-duruşunu uyum çerçevelerine (CIS/NIST/ISO/KVKK)
// eşleyen skor raporunu döner (denetçi görünürlüğü).
func (s *Server) handleFrameworks(w http.ResponseWriter, r *http.Request, _ string) {
	rep, err := s.reader.FrameworkCompliance(r.Context())
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleRisk, çok-faktörlü filo risk skorunu döner (#risk): açık incident'ler,
// uyum ihlalleri ve karantina durumundan cihaz + filo risk skoru hesaplar.
func (s *Server) handleRisk(w http.ResponseWriter, r *http.Request, _ string) {
	rk, err := s.reader.FleetRisk(r.Context())
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rk)
}

// handleCoverage, filo koruma-kapsamı + ajan sürüm-kayması ("kim korunuyor?").
func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request, _ string) {
	cov, err := s.reader.Coverage(r.Context())
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, cov)
}

// handleAuditExport, denetim izini KURCALAMA-KANITLI, taşınabilir bir hash-zinciri
// (JSONL) olarak dışa aktarır (#16). Anahtar bağlıysa (SetAuditExportKey) son
// satıra imzalı bir manifest eklenir. Denetçi/WORM arşiv bunu C2'DEN BAĞIMSIZ
// doğrulayabilir (tools/auditverify). OPERATOR+ gerekir (denetim izi hassas).
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	rows, err := s.reader.Audit(r.Context(), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	// Audit en yeniden eskiye döner; zincir KRONOLOJİK (eskiden yeniye) olmalı.
	entries := make([]auditexport.Entry, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		a := rows[i]
		entries = append(entries, auditexport.Entry{
			Admin: a.AdminEmail, Action: a.Action,
			TargetType: a.TargetType, TargetID: a.TargetID, CreatedAt: a.CreatedAt,
		})
	}
	data, err := auditexport.MarshalJSONL(auditexport.BuildChain(entries), s.auditExpKey)
	if respondErr(w, err) {
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-export.jsonl"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleSaveSearch, bir threat-hunting sorgusunu adla kalıcılaştırır (SIEM kayıtlı
// arama). Gövde: {"name": "...", "filter": {<hunt isteği>}}. filter ham JSON olarak
// saklanır; sonradan /api/hunt'a aynen gönderilebilir.
func (s *Server) handleSaveSearch(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Name   string          `json:"name"`
		Filter json.RawMessage `json:"filter"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "ad zorunlu")
		return
	}
	if len(req.Filter) == 0 || string(req.Filter) == "null" {
		writeErr(w, http.StatusBadRequest, "filter zorunlu")
		return
	}
	row, err := s.reader.SaveSearch(r.Context(), req.Name, string(req.Filter), adminID)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, row)
}

// handleListSavedSearches, kayıtlı aramaları listeler.
func (s *Server) handleListSavedSearches(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.reader.SavedSearches(r.Context())
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"searches": rows})
}

// handleDeleteSavedSearch, bir kayıtlı aramayı siler.
func (s *Server) handleDeleteSavedSearch(w http.ResponseWriter, r *http.Request, _ string) {
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		writeErr(w, http.StatusBadRequest, "kimlik zorunlu")
		return
	}
	if respondErr(w, s.reader.DeleteSavedSearch(r.Context(), id)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// handleMaintenance, yapılandırılmış bakım/bastırma pencerelerini döner (#18):
// her pencere için zaman aralığı, kapsam (cihaz/kategori), gerekçe ve şu an ETKİN
// olup olmadığı. Konsol "neden uyarı gelmiyor?" görünürlüğü.
func (s *Server) handleMaintenance(w http.ResponseWriter, r *http.Request, _ string) {
	type windowDTO struct {
		Start  time.Time `json:"start"`
		End    time.Time `json:"end"`
		Reason string    `json:"reason,omitempty"`
		Active bool      `json:"active"`
	}
	out := []windowDTO{}
	if s.maintWindows != nil {
		now := time.Now()
		for _, wd := range s.maintWindows() {
			out = append(out, windowDTO{
				Start: wd.Start, End: wd.End, Reason: wd.Reason, Active: wd.Active(now),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"windows": out})
}

// handleMetricsTrends, MTTD/MTTR metriklerini ve günlük trendini döner (SOC
// olgunluk göstergesi). ?days=N ile pencere ayarlanır (varsayılan 7, üst sınır 90).
func (s *Server) handleMetricsTrends(w http.ResponseWriter, r *http.Request, _ string) {
	days := intParam(r, "days")
	if days <= 0 {
		days = 7
	}
	if days > 90 {
		days = 90
	}
	tr, err := s.reader.DetectionResponseTrends(r.Context(), days)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, tr)
}

// handleIncidentTimeline, bir incident'i ve onu oluşturan cihazın penceredeki
// olaylarını kronolojik döner (IR araştırması). Bulunamazsa 404.
func (s *Server) handleIncidentTimeline(w http.ResponseWriter, r *http.Request, _ string) {
	id := r.PathValue("id")
	tl, ok, err := s.reader.IncidentTimeline(r.Context(), id)
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "incident bulunamadı")
		return
	}
	writeJSON(w, http.StatusOK, tl)
}

// handleIncidents, korelasyonla gruplanmış olayları (incident) listeler (salt-okunur).
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.reader.Incidents(r.Context(), 200)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": rows})
}

// handleLockDevice, uzaktan ekran kilitleme komutu kuyruğa ekler (OPERATOR+).
func (s *Server) handleLockDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.LockDevice(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "lock_queued"})
}

// handleRestartDevice, uzaktan yeniden başlatma komutu kuyruğa ekler (OPERATOR+).
func (s *Server) handleRestartDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.RestartDevice(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "restart_queued"})
}

// handleWipeDevice, uzaktan veri silme başlatır (ADMIN; yıkıcı + audit). Çift-kontrol
// AÇIKSA komut hemen kuyruğa GİRMEZ — WIPE talebi kaydedilir ve farklı bir ADMIN'in
// onayı beklenir (dört-göz). KAPALIYSA doğrudan kuyruğa alınır (eski davranış).
func (s *Server) handleWipeDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.adminSvc.WipeDualControl() {
		var req struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req) // gerekçe opsiyonel
		if respondErr(w, s.adminSvc.RequestWipe(r.Context(), adminID, r.PathValue("id"), req.Reason)) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "wipe_pending_approval"})
		return
	}
	if respondErr(w, s.adminSvc.WipeDevice(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "wipe_queued"})
}

// handleApproveWipe, bekleyen bir WIPE talebini onaylar ve komutu kuyruğa alır
// (ADMIN; onaylayan talep edenden FARKLI olmalı — dört-göz).
func (s *Server) handleApproveWipe(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.ApproveWipe(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "wipe_queued"})
}

// handleCancelWipe, bekleyen bir WIPE talebini iptal eder (ADMIN).
func (s *Server) handleCancelWipe(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.CancelWipe(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "wipe_cancelled"})
}

// handlePendingWipes, ikinci-onay bekleyen WIPE taleplerini listeler (çift-kontrol
// konsol görünümü; onay/iptal için).
func (s *Server) handlePendingWipes(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := s.reader.PendingWipes(r.Context())
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending_wipes": rows})
}

// handleCollectFile, bir cihazdan adli/IR dosya toplama komutu kuyruğa ekler
// (OPERATOR+). Ajan dosyayı okuyup yükler; sonuç /artifacts uçlarından görülür.
func (s *Server) handleCollectFile(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Path string `json:"path"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.CollectFile(r.Context(), adminID, r.PathValue("id"), req.Path)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "queued"})
}

// handleListArtifacts, bir cihazdan toplanan artefaktların meta listesini döner.
func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request, _ string) {
	arts, err := s.reader.Artifacts(r.Context(), r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"artifacts": arts})
}

// handleDownloadArtifact, tek bir artefaktın ham içeriğini indirir (attachment).
func (s *Server) handleDownloadArtifact(w http.ResponseWriter, r *http.Request, adminID string) {
	id := r.PathValue("id")
	c, ok, err := s.reader.ArtifactBytes(r.Context(), id)
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "artefakt bulunamadı")
		return
	}
	// Kanıt gözetim zinciri (chain-of-custody): delil erişimini denetim izine yaz
	// (hangi analist, hangi artefakt, ne zaman) — adli bütünlük.
	s.adminSvc.RecordAudit(r.Context(), adminID, "DOWNLOAD_ARTIFACT", "artifact", id)
	name := c.Path
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		name = "artifact.bin"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(c.Content)
}

// handleAckEvent, bir olayı ACKNOWLEDGED (inceleniyor) işaretler (OPERATOR+).
func (s *Server) handleAckEvent(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.AckEvent(r.Context(), adminID, r.PathValue("id"), "ACKNOWLEDGED")) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ACKNOWLEDGED"})
}

// handleResolveEvent, bir olayı RESOLVED (kapatıldı) işaretler (OPERATOR+).
func (s *Server) handleResolveEvent(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.AckEvent(r.Context(), adminID, r.PathValue("id"), "RESOLVED")) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "RESOLVED"})
}

// handleEventCase, bir olaya sorumlu (assignee) ve serbest-metin not atar —
// vaka/olay yönetimi (#9). OPERATOR+ yetkisi gerektirir.
func (s *Server) handleEventCase(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Assignee string `json:"assignee"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "geçersiz istek gövdesi"})
		return
	}
	if respondErr(w, s.adminSvc.UpdateEventCase(r.Context(), adminID, r.PathValue("id"), req.Assignee, req.Note)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"assignee": req.Assignee, "note": req.Note})
}

// handleVulnerabilities, her cihazın en son yazılım envanterini yüklü zafiyet
// veri kümesiyle eşleştirir ve zafiyetli cihazları (bulgularla) döner. Salt-
// okunur; herhangi bir kimliği doğrulanmış kullanıcı erişebilir.
func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request, _ string) {
	type deviceVulns struct {
		DeviceID string         `json:"device_id"`
		Hostname string         `json:"hostname"`
		Findings []vuln.Finding `json:"findings"`
	}
	out := []deviceVulns{}
	loaded := s.vulnSet.Size()
	if s.vulnSet != nil && loaded > 0 {
		byDev, err := s.reader.LatestSoftwareByDevice(r.Context())
		if respondErr(w, err) {
			return
		}
		devs, err := s.reader.Devices(r.Context(), 0)
		if respondErr(w, err) {
			return
		}
		hn := make(map[string]string, len(devs))
		for _, d := range devs {
			hn[d.ID] = d.Hostname
		}
		for id, sw := range byDev {
			if f := s.vulnSet.Match(sw); len(f) > 0 {
				out = append(out, deviceVulns{DeviceID: id, Hostname: hn[id], Findings: f})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dataset_size": loaded, "vulnerable_devices": len(out), "devices": out,
	})
}

// handleSoftwareSearch, filo-geneli yazılım araması yapar (?q=...): adı query'yi
// içeren paketi yüklü cihazları döner. Zafiyet müdahalesi ("X kurulu cihazlar").
// Salt-okunur; herhangi bir kimliği doğrulanmış kullanıcı erişebilir.
func (s *Server) handleSoftwareSearch(w http.ResponseWriter, r *http.Request, _ string) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeErr(w, http.StatusBadRequest, "q parametresi zorunlu")
		return
	}
	matches, err := s.reader.SoftwareSearch(r.Context(), q)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": q, "matches": matches, "device_count": len(matches)})
}

// handleActivity, süreç-içi tehdit/etkinlik sayaçlarını döner (konsol Genel Bakış
// etkinlik kartı). Süreç başından beri kümülatiftir (/metrics ile aynı kaynak).
func (s *Server) handleActivity(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"counters":       metrics.Counters(),
		"uptime_seconds": metrics.UptimeSeconds(),
	})
}

// handleFeatures, dağıtımın koruma-duruşunu döner (ADMIN): hangi opsiyonel
// korumalar etkin, kaç tespit kuralı yüklü, /metrics açık mı. Yapılandırma
// görünürlüğü hassas olduğundan ADMIN gerekir.
func (s *Server) handleFeatures(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	out := map[string]any{}
	for k, v := range s.features {
		out[k] = v
	}
	out["detection_rules"] = len(s.detector.Load().Rules())
	out["metrics_enabled"] = s.metricsToken != ""
	writeJSON(w, http.StatusOK, map[string]any{"features": out})
}

// handleStream, Server-Sent Events (SSE) ile canlı değişiklik bildirimleri iletir.
// Konsol bunu Authorization başlıklı fetch akışı ile tüketir (token URL'de YER
// ALMAZ). Bildirim yalnız bir "değişti" tetikleyicisidir; konsol tazeler.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, _ string) {
	if s.stream == nil {
		writeErr(w, http.StatusNotImplemented, "canlı akış devre dışı")
		return
	}
	// SEC-007: eşzamanlı SSE bağlantısı üst sınırı (kaynak tükenmesini önle).
	if n := atomic.AddInt64(&s.sseConns, 1); n > maxSSEConns {
		atomic.AddInt64(&s.sseConns, -1)
		w.Header().Set("Retry-After", "10")
		writeErr(w, http.StatusServiceUnavailable, "eşzamanlı akış sınırı aşıldı")
		return
	}
	defer atomic.AddInt64(&s.sseConns, -1)

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "akış desteklenmiyor")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ch, cancel := s.stream.Subscribe()
	defer cancel()
	fmt.Fprint(w, ": bağlandı\n\n")
	flusher.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n") // yorum satırı: bağlantıyı canlı tutar
			flusher.Flush()
		case n, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(n)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

// handleVerifyAudit, denetim izi hash-zincirinin bütünlüğünü doğrular (SEC C-1,
// ADMIN). Zincir sağlamsa 200 {valid:true}; kırıksa 200 {valid:false, error}.
func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	if s.auditVerify == nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": true, "note": "doğrulayıcı yapılandırılmadı"})
		return
	}
	if err := s.auditVerify(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request, adminID string) {
	// SEC-009: denetim izi hassastır — OPERATOR+ gerekir.
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	audit, err := s.reader.Audit(r.Context(), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": audit})
}

// --- yardımcılar ---

func intParam(r *http.Request, name string) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

// maxRequestBody, admin API JSON gövdeleri için üst sınırdır. Kimliği
// doğrulanmış bir kullanıcının bile devasa gövde göndererek bellek tüketmesini
// (DoS) önler; 1 MiB tüm meşru yükler (politika kuralları, kural testi vb.) için
// fazlasıyla yeterlidir.
const maxRequestBody = 1 << 20 // 1 MiB

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "istek gövdesi çok büyük")
			return false
		}
		writeErr(w, http.StatusBadRequest, "geçersiz JSON")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// respondErr, admin servis hatasını uygun HTTP durumuna çevirir. Hata varsa
// yanıtı yazar ve true döner.
func respondErr(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, admin.ErrForbidden) {
		writeErr(w, http.StatusForbidden, "yetki yetersiz")
		return true
	}
	if errors.Is(err, admin.ErrInvalidRule) {
		writeErr(w, http.StatusBadRequest, "geçersiz kural")
		return true
	}
	if errors.Is(err, admin.ErrInvalidInput) {
		writeErr(w, http.StatusBadRequest, "geçersiz girdi")
		return true
	}
	writeErr(w, http.StatusInternalServerError, "işlem başarısız")
	return true
}

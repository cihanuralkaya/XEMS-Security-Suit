// Command c2, XEMS Yönetim Sunucusunu (Command & Control) başlatır.
//
// Bağlanan bileşenler:
//   - EnrollmentService (tek yönlü TLS): token doğrulama + CSR imzalama (PKI)
//   - AgentService (mTLS): heartbeat (sunucu-saati çıpası), olay gönderimi
//   - PostgreSQL (pgx), alan şifreleme + HMAC blind index (ana anahtardan türetilir)
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	xgrpc "xems.corp/suite/server/internal/grpc"

	"xems.corp/suite/logx"
	"xems.corp/suite/server/internal/admin"
	"xems.corp/suite/server/internal/adminapi"
	"xems.corp/suite/server/internal/adminread"
	"xems.corp/suite/server/internal/beacon"
	"xems.corp/suite/server/internal/cluster"
	"xems.corp/suite/server/internal/config"
	"xems.corp/suite/server/internal/correlate"
	"xems.corp/suite/server/internal/db"
	"xems.corp/suite/server/internal/detect"
	"xems.corp/suite/server/internal/enroll"
	"xems.corp/suite/server/internal/eventbus"
	"xems.corp/suite/server/internal/ioc"
	"xems.corp/suite/server/internal/memstore"
	"xems.corp/suite/server/internal/metrics"
	"xems.corp/suite/server/internal/model"
	"xems.corp/suite/server/internal/notify"
	"xems.corp/suite/server/internal/policypush"
	"xems.corp/suite/server/internal/report"
	"xems.corp/suite/server/internal/response"
	"xems.corp/suite/server/internal/retention"
	"xems.corp/suite/server/internal/revocation"
	"xems.corp/suite/server/internal/security"
	"xems.corp/suite/server/internal/vuln"
)

// Backend, C2'nin ihtiyaç duyduğu tüm depolama arayüzlerinin birleşimidir;
// hem *db.Store (PostgreSQL) hem *memstore.Store (bellek-içi demo) karşılar.
type Backend interface {
	enroll.Store
	xgrpc.DeviceRegistry
	xgrpc.EventSink
	xgrpc.PolicyProvider
	xgrpc.UpdateProvider
	admin.Store
	adminread.Store
	xgrpc.ArtifactSink
	correlate.IncidentSink
	revocation.Source
	retention.Store
	adminapi.AuthStore

	// MarkStaleOffline, last_seen'i eşiğin gerisinde kalan ACTIVE cihazları
	// OFFLINE işaretler (bayat-OFFLINE görevi). Hem db hem memstore uygular.
	MarkStaleOffline(ctx context.Context, olderThan time.Time) (int, error)

	// Ping, depo sağlık kontrolü (/readyz). Hem db (pool.Ping) hem memstore (nil).
	Ping(ctx context.Context) error

	// VerifyAuditChain, denetim izi hash-zincirinin bütünlüğünü doğrular (SEC C-1).
	VerifyAuditChain(ctx context.Context) error
}

// openBackend, XEMS_DATABASE_URL varsa PostgreSQL, yoksa bellek-içi demo deposu
// açar. Demo modunda bir yönetici ve kurallı bir demo politikası tohumlanır ve
// giriş bilgileri loglanır.
func openBackend(ctx context.Context, cfg *config.Config) (Backend, error) {
	if cfg.DatabaseURL != "" {
		store, err := db.New(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, err
		}
		log.Println("depo: PostgreSQL")
		return store, nil
	}

	// SEC-006: XEMS_DATABASE_URL boşken SESSİZCE demo moduna düşme. Bellek-içi demo
	// (kalıcılık yok + tohumlanmış admin) yalnız AÇIK bir onayla (XEMS_DEMO=1)
	// çalışmalı; aksi halde üretimde yanlış-yapılandırma riski (env unutulması)
	// tohumlanmış admin ve loglanmış kimlikle açar. Bayrak yoksa hata ver.
	if os.Getenv("XEMS_DEMO") != "1" {
		return nil, fmt.Errorf("config: XEMS_DATABASE_URL zorunlu (bellek-içi demo için açıkça XEMS_DEMO=1 ayarlayın)")
	}

	ms := memstore.New()
	email := getenv("XEMS_DEMO_ADMIN_EMAIL", "admin@local")
	pass := os.Getenv("XEMS_DEMO_ADMIN_PASSWORD")
	generated := pass == ""
	if generated {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		pass = "demo-" + hex.EncodeToString(b)
	}
	hash, err := security.HashPassword(pass)
	if err != nil {
		return nil, err
	}
	ms.SeedAdmin(email, hash, admin.RoleAdmin)
	polID, polVer := ms.SeedDemoPolicy()

	log.Println("=======================================================")
	log.Println(" BELLEK-İÇİ DEMO MODU (XEMS_DEMO=1) — kalıcılık yok")
	// Parolayı YALNIZ otomatik üretildiyse logla (operatörün bilmesi için);
	// XEMS_DEMO_ADMIN_PASSWORD ile verildiyse loglamaya gerek yok (kimlik sızıntısı).
	if generated {
		log.Printf("  Konsol girişi  e-posta: %s   parola: %s (otomatik üretildi)", email, pass)
	} else {
		log.Printf("  Konsol girişi  e-posta: %s   (parola XEMS_DEMO_ADMIN_PASSWORD'den)", email)
	}
	log.Printf("  Demo politika  id: %s  (sürüm %s; 'xems-demo-blocked.exe' engeller)", polID, polVer)
	log.Println("=======================================================")
	return ms, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// splitCSVEnv, virgülle ayrılmış bir ortam değişkenini boşlukları kırpılmış,
// boşları atlanmış dilime çevirir.
func splitCSVEnv(k string) []string {
	raw := os.Getenv(k)
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// atoiEnv, bir ortam değişkenini pozitif tamsayı olarak okur (yoksa/geçersizse 0).
func atoiEnv(k string) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(k)))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// loadWindows, bir JSON bastırma penceresi dosyasını okuyup ayrıştırır.
func loadWindows(path string) ([]notify.Window, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return notify.ParseWindows(data)
}

// getdurEnv, süre biçimli bir ortam değişkenini okur (yoksa/geçersizse def).
func getdurEnv(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func main() {
	// Loglama biçimi: XEMS_LOG_FORMAT=json ise yapısal JSON (SIEM/log toplama);
	// aksi halde "[c2] " prefix'li standart metin.
	logx.Setup(os.Getenv("XEMS_LOG_FORMAT"), "[c2] ")

	if err := run(); err != nil {
		log.Fatalf("başlatma hatası: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Ana anahtardan amaç-ayrımlı alt anahtarlar türet (diske yazılmaz). Anahtar
	// rotasyonu (#9): eski ana anahtarlardan türetilen alan-şifreleme anahtarları
	// keyring'e çözme için eklenir — yeni veri yeni anahtarla şifrelenir, eski veri
	// eski anahtarla çözülmeye DEVAM eder (veri kaybı yok).
	oldFieldKeys := make([][]byte, 0, len(cfg.MasterKeysOld))
	for _, k := range cfg.MasterKeysOld {
		oldFieldKeys = append(oldFieldKeys, security.DeriveKey(k, security.LabelFieldEncryption))
	}
	cipher, err := security.NewFieldCipherRing(security.DeriveKey(cfg.MasterKey, security.LabelFieldEncryption), oldFieldKeys...)
	if err != nil {
		return err
	}
	if len(oldFieldKeys) > 0 {
		log.Printf("alan şifreleme: anahtar rotasyonu etkin (%d eski anahtar çözme halkasında)", len(oldFieldKeys))
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(cfg.MasterKey, security.LabelBlindIndex))

	// CA (istemci sertifikalarını imzalar) ve sunucu TLS materyali.
	caCertPEM, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		return err
	}
	caKeyPEM, err := os.ReadFile(cfg.CAKeyPath)
	if err != nil {
		return err
	}
	ca, err := security.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}
	serverCertPEM, err := os.ReadFile(cfg.ServerCertPath)
	if err != nil {
		return err
	}
	serverKeyPEM, err := os.ReadFile(cfg.ServerKeyPath)
	if err != nil {
		return err
	}

	// Depo seçimi: XEMS_DATABASE_URL varsa PostgreSQL, yoksa bellek-içi DEMO deposu.
	backend, err := openBackend(ctx, cfg)
	if err != nil {
		return err
	}
	// MFA (TOTP) sırlarının at-rest şifrelenmesi için DB deposuna alan şifreleyiciyi
	// bağla (memstore bellek-içi tutar, şifreleyiciye ihtiyaç duymaz).
	if store, ok := backend.(*db.Store); ok {
		store.SetFieldCipher(cipher)
	}

	// Servisler + handler'lar.
	enrollSvc := enroll.NewService(backend, ca, bidx, cipher, caCertPEM, cfg.ClientCertTTL)
	enrollHandler := xgrpc.NewEnrollmentHandler(enrollSvc)
	// Anlık politika push: admin atama → notifier → açık akış.
	notifier := policypush.New()
	agentHandler := xgrpc.NewAgentHandler(backend, backend, backend, backend, notifier)
	agentHandler.SetArtifactSink(backend) // adli/IR dosya toplama (#4)
	// Canlı konsol akışı (SSE): ajan olay/heartbeat → bus → admin /api/stream.
	liveBus := eventbus.New()
	agentHandler.SetAdminNotifier(liveBus)

	// Yatay ölçekleme (#10): XEMS_CLUSTER=1 ve PostgreSQL kullanılıyorsa, canlı
	// bildirimler düğümler arası Postgres LISTEN/NOTIFY ile fan-out edilir; böylece
	// yük dengeleyici arkasındaki HANGİ düğüme bağlı olursa olsun tüm adminler tüm
	// olayları görür. Tek-düğüm (veya memstore) modunda bellek-içi bus kullanılır.
	clusterOn := false
	if os.Getenv("XEMS_CLUSTER") == "1" {
		store, ok := backend.(*db.Store)
		if !ok {
			return fmt.Errorf("config: XEMS_CLUSTER=1 için PostgreSQL (XEMS_DATABASE_URL) zorunlu")
		}
		broker := cluster.New(ctx, store, liveBus, os.Getenv("XEMS_CLUSTER_CHANNEL"),
			func(m string) { log.Println("[cluster] " + m) })
		broker.SetMetrics(metrics.IncClusterPublished, metrics.IncClusterReceived, metrics.IncClusterFallback)
		liveBus.SetSink(broker.Publish) // yayınlar NOTIFY'a; dağıtım LISTEN'den
		go broker.Run(ctx)
		clusterOn = true
		log.Println("yatay ölçekleme: çok-düğüm canlı akış fan-out ETKİN (Postgres LISTEN/NOTIFY)")
	}

	// Sunucu-taraflı tespit motoru (tek kaynak): ingest'te değerlendirme + konsol
	// kural kataloğu ucu aynı motoru paylaşır. XEMS_DETECT_RULES_FILE ayarlıysa
	// operatör-tanımlı özel kurallar yerleşiklere EKLENİR (koda dokunmadan).
	detectRules := detect.DefaultRules()
	if rf := os.Getenv("XEMS_DETECT_RULES_FILE"); rf != "" {
		custom, err := detect.LoadRulesFile(rf)
		if err != nil {
			return fmt.Errorf("tespit kuralları yüklenemedi: %w", err)
		}
		detectRules = append(detectRules, custom...)
		log.Printf("tespit motoru: %d özel kural eklendi (toplam %d)", len(custom), len(detectRules))
	}
	detector := detect.NewEngine(detectRules)
	agentHandler.SetDetector(detector)
	// Olay korelasyonu (#2): aynı cihaz+kural penceresindeki tespitleri tek
	// incident'e katla ve yinelenen alarmları bastır (alarm-fırtınası). Pencere
	// XEMS_CORRELATION_WINDOW (varsayılan 10dk). Backend incident'leri kalıcılaştırır.
	corrWindow := 10 * time.Minute
	if d, err := time.ParseDuration(os.Getenv("XEMS_CORRELATION_WINDOW")); err == nil && d > 0 {
		corrWindow = d
	}
	agentHandler.SetCorrelator(correlate.New(corrWindow, backend))

	// Dış uyarı (SOC webhook): XEMS_ALERT_WEBHOOK_URL ayarlıysa yüksek önem düzeyli
	// olaylar bir HTTPS webhook'una gönderilir (Slack/Teams/genel). Eşik
	// XEMS_ALERT_MIN_SEVERITY (varsayılan HIGH).
	alertingOn, iocCount, autoRespOn, siemOn := false, 0, false, false
	var notifiers []notify.Notifier
	if hook := os.Getenv("XEMS_ALERT_WEBHOOK_URL"); hook != "" {
		alerter, err := notify.NewWebhookNotifier(hook, getenv("XEMS_ALERT_MIN_SEVERITY", "HIGH"), os.Getenv("XEMS_ALERT_FORMAT"))
		if err != nil {
			return err
		}
		// Yönlendirme (#15): XEMS_ALERT_CATEGORIES / XEMS_ALERT_TECHNIQUES ayarlıysa
		// webhook'a YALNIZ eşleşen uyarılar gider (kategori/ATT&CK tekniği süzgeci).
		cats := splitCSVEnv("XEMS_ALERT_CATEGORIES")
		techs := splitCSVEnv("XEMS_ALERT_TECHNIQUES")
		if len(cats) > 0 || len(techs) > 0 {
			notifiers = append(notifiers, notify.NewRouter(
				notify.NewRoute("webhook", getenv("XEMS_ALERT_MIN_SEVERITY", "HIGH"), cats, techs, alerter)))
			log.Printf("dış uyarı: webhook + yönlendirme etkin (kategori=%v teknik=%v)", cats, techs)
		} else {
			notifiers = append(notifiers, alerter)
			log.Println("dış uyarı: webhook etkin (yüksek önem düzeyli olaylar)")
		}
		alertingOn = true
	}
	// SIEM iletici (#8): XEMS_SIEM_ADDR ayarlıysa olaylar syslog+CEF/LEEF olarak
	// bir SIEM'e (ArcSight/QRadar/Splunk) iletilir. proto XEMS_SIEM_PROTO (udp|tcp),
	// biçim XEMS_SIEM_FORMAT (cef|leef), eşik XEMS_SIEM_MIN_SEVERITY.
	if siemAddr := os.Getenv("XEMS_SIEM_ADDR"); siemAddr != "" {
		sn, err := notify.NewSyslogNotifier(siemAddr, os.Getenv("XEMS_SIEM_PROTO"),
			os.Getenv("XEMS_SIEM_FORMAT"), getenv("XEMS_SIEM_MIN_SEVERITY", "HIGH"), os.Getenv("XEMS_BUILD_VERSION"))
		if err != nil {
			return err
		}
		notifiers = append(notifiers, sn)
		siemOn = true
		log.Printf("SIEM iletici etkin: %s (%s/%s)", siemAddr, getenv("XEMS_SIEM_PROTO", "udp"), getenv("XEMS_SIEM_FORMAT", "cef"))
	}
	// Bakım/bastırma pencereleri (#18): XEMS_SUPPRESS_FILE ayarlıysa planlı bakım
	// aralıklarında (opsiyonel cihaz/kategori kapsamı) uyarılar bastırılır. Canlı
	// hot-reload: XEMS_SUPPRESS_RELOAD_INTERVAL. Konsol için /api/maintenance.
	var suppressHolder *notify.WindowHolder
	if sf := os.Getenv("XEMS_SUPPRESS_FILE"); sf != "" {
		ws, err := loadWindows(sf)
		if err != nil {
			return fmt.Errorf("bastırma penceresi dosyası: %w", err)
		}
		suppressHolder = notify.NewWindowHolder(ws)
		log.Printf("bakım/bastırma pencereleri etkin: %d pencere", len(ws))
		if d := getdurEnv("XEMS_SUPPRESS_RELOAD_INTERVAL", 0); d > 0 {
			go func() {
				t := time.NewTicker(d)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						if ws, err := loadWindows(sf); err != nil {
							log.Printf("[suppress] yeniden yükleme başarısız: %v (eski küme korunuyor)", err)
						} else {
							suppressHolder.Set(ws)
						}
					}
				}
			}()
			log.Printf("bastırma pencereleri: canlı yeniden yükleme her %s", d)
		}
	}

	if len(notifiers) > 0 {
		var alerter notify.Notifier = notify.NewMulti(notifiers...)
		// Yükseltme (#15): XEMS_ALERT_ESCALATE_COUNT>0 ise aynı cihaz|kategori için
		// XEMS_ALERT_ESCALATE_WINDOW (varsayılan 10m) içinde bu kadar yüksek-önem
		// uyarı birikince bir kez CRITICAL "ESCALATED" uyarısı üretilir (on-call).
		if cnt := atoiEnv("XEMS_ALERT_ESCALATE_COUNT"); cnt > 0 {
			win := getdurEnv("XEMS_ALERT_ESCALATE_WINDOW", 10*time.Minute)
			alerter = notify.NewEscalator(alerter, getenv("XEMS_ALERT_ESCALATE_MIN_SEVERITY", "HIGH"), cnt, win, nil)
			log.Printf("uyarı yükseltme etkin: %d uyarı/%s → CRITICAL", cnt, win)
		}
		// Bastırma en DIŞTA sarar: bastırılan uyarılar korelasyon/yükseltmeyi beslemez.
		if suppressHolder != nil {
			alerter = notify.NewSuppressor(alerter, suppressHolder.Windows, metrics.IncAlertSuppressed, nil)
		}
		agentHandler.SetAlerter(alerter)
	}

	// Tehdit istihbaratı (IoC): XEMS_IOC_FILE ayarlıysa bilinen-kötü göstergeler
	// (IP/MAC/alan adı/hash/süreç) yüklenir; eşleşen olaylar KRİTİK uyarı üretir.
	if iocPath := os.Getenv("XEMS_IOC_FILE"); iocPath != "" {
		set, err := ioc.LoadFile(iocPath)
		if err != nil {
			return fmt.Errorf("IoC listesi yüklenemedi: %w", err)
		}
		agentHandler.SetIoCSet(set)
		iocCount = set.Size()
		log.Printf("tehdit istihbaratı: %d IoC göstergesi yüklendi", iocCount)

		// Canlı hot-reload: XEMS_IOC_RELOAD_INTERVAL ayarlıysa (ör. 5m) IoC dosyası
		// periyodik yeniden okunur ve göstergeler SUNUCU YENİDEN BAŞLATILMADAN
		// güncellenir (SOC yeni göstergeleri anında dağıtabilir). Okuma hatasında
		// eski küme korunur (best-effort). Boş/0/geçersiz = kapalı (mevcut davranış).
		if d, derr := time.ParseDuration(os.Getenv("XEMS_IOC_RELOAD_INTERVAL")); derr == nil && d > 0 {
			go func() {
				t := time.NewTicker(d)
				defer t.Stop()
				prev := set.Size()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
					}
					ns, e := ioc.LoadFile(iocPath)
					if e != nil {
						log.Printf("[ioc] yeniden yükleme başarısız (eski küme korunuyor): %v", e)
						continue
					}
					agentHandler.SetIoCSet(ns) // atomik hot-swap (ingest yoluyla yarışsız)
					if n := ns.Size(); n != prev {
						log.Printf("[ioc] göstergeler yeniden yüklendi: %d (önceki %d)", n, prev)
						prev = n
					}
				}
			}()
			log.Printf("tehdit istihbaratı: canlı yeniden yükleme her %s", d)
		}
	}

	// Otomatik müdahale (SOAR): XEMS_AUTO_RESPONSE=1 ise kritik güvenlik olayında
	// cihaz otomatik karantinaya alınır. Varsayılan KAPALI (karantina bozucudur).
	if os.Getenv("XEMS_AUTO_RESPONSE") == "1" {
		agentHandler.SetAutoResponder(response.New(backend))
		autoRespOn = true
		log.Println("otomatik müdahale: kritik olayda otomatik karantina ETKİN")
	}

	// Sertifika iptali: bellek-içi küme + depodan periyodik tazeleme.
	revCache := revocation.NewCache()
	go revocation.NewRefresher(backend, revCache, 60*time.Second,
		func(m string) { log.Println("[revocation] " + m) }).Run(ctx)

	tlsMat := xgrpc.TLSMaterial{
		ServerCertPEM: serverCertPEM,
		ServerKeyPEM:  serverKeyPEM,
		ClientCAPEM:   caCertPEM,
		Revocation:    revCache,
	}
	agentSrv, err := xgrpc.NewAgentServer(tlsMat, agentHandler)
	if err != nil {
		return err
	}
	enrollSrv, err := xgrpc.NewEnrollServer(tlsMat, enrollHandler)
	if err != nil {
		return err
	}

	// Admin HTTP API (TLS).
	adminSvc := admin.NewService(backend, bidx, cfg.EnrollTokenTTL)
	adminSvc.SetPublisher(notifier) // politika atamada anlık push
	// Çift-kontrol (dört-göz) WIPE: XEMS_WIPE_DUAL_CONTROL=1 ise WIPE bir ADMIN'in
	// talebi + FARKLI bir ADMIN'in onayını gerektirir (tek ele geçirilmiş ADMIN filo
	// silemez). Varsayılan KAPALI (tek-ADMIN doğrudan WIPE — eski davranış).
	wipeDual := os.Getenv("XEMS_WIPE_DUAL_CONTROL") == "1"
	adminSvc.SetWipeDualControl(wipeDual)
	if wipeDual {
		log.Println("çift-kontrol WIPE: iki farklı ADMIN onayı ETKİN")
	}
	readSvc := adminread.NewService(backend, cipher)
	sessions := security.NewSessionSigner(security.DeriveKey(cfg.MasterKey, security.LabelSessionToken))
	adminAPI := adminapi.New(adminSvc, readSvc, backend, sessions, cfg.AdminSessionTTL)
	adminAPI.SetStream(liveBus)                                    // canlı SSE akışı
	adminAPI.SetHealthCheck(backend.Ping)                          // /readyz depo sağlık kontrolü
	adminAPI.SetLoginLimit(cfg.LoginMaxAttempts, cfg.LoginLockout) // kaba-kuvvet koruması
	adminAPI.SetPrivacyNotice(os.Getenv("XEMS_PRIVACY_NOTICE"))    // KVKK aydınlatma (boşsa varsayılan)
	adminAPI.SetAuditVerifier(backend.VerifyAuditChain)            // denetim izi hash-zincir doğrulama
	if suppressHolder != nil {
		adminAPI.SetMaintenanceProvider(suppressHolder.Windows) // bakım pencereleri görünürlüğü (#18)
	}
	// İmzalı denetim dışa aktarımı (#16): XEMS_AUDIT_EXPORT_KEY (base64 Ed25519 özel
	// anahtar) ayarlıysa /api/audit/export imzalı manifest üretir; aksi halde imzasız
	// (yalnız hash zinciri). Anahtar geçersizse başlatma durur (yanlış yapılandırma).
	if kb := os.Getenv("XEMS_AUDIT_EXPORT_KEY"); kb != "" {
		raw, err := base64.StdEncoding.DecodeString(kb)
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return fmt.Errorf("XEMS_AUDIT_EXPORT_KEY geçersiz Ed25519 özel anahtar")
		}
		adminAPI.SetAuditExportKey(ed25519.PrivateKey(raw))
		log.Println("denetim dışa aktarımı: imzalı manifest etkin")
	}
	// Prometheus /metrics — yalnız XEMS_METRICS_TOKEN ayarlıysa açılır (statik Bearer
	// token). Ayarlı değilse uç kapalıdır (toplu veriyi kimliksiz sızdırmama).
	metrics.SetBuildVersion(os.Getenv("XEMS_BUILD_VERSION"))
	adminAPI.SetMetricsToken(os.Getenv("XEMS_METRICS_TOKEN"))
	adminAPI.SetDetector(detector) // tespit kural kataloğu (ingest ile aynı motor)

	// Tespit kuralları canlı hot-reload: XEMS_DETECT_RELOAD_INTERVAL ayarlıysa (ör.
	// 5m) ve özel kural dosyası varsa, dosya periyodik yeniden okunur ve motor
	// SUNUCU YENİDEN BAŞLATILMADAN güncellenir (SOC kural ince ayarını anında
	// dağıtır). Her iki tüketici de (ingest değerlendirmesi + konsol kataloğu)
	// atomik güncellenir. Okuma hatasında eski motor korunur (best-effort).
	if rf := os.Getenv("XEMS_DETECT_RULES_FILE"); rf != "" {
		if d, derr := time.ParseDuration(os.Getenv("XEMS_DETECT_RELOAD_INTERVAL")); derr == nil && d > 0 {
			startRules := len(detectRules)
			go func() {
				t := time.NewTicker(d)
				defer t.Stop()
				prev := startRules
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
					}
					custom, e := detect.LoadRulesFile(rf)
					if e != nil {
						log.Printf("[detect] kural yeniden yükleme başarısız (eski korunuyor): %v", e)
						continue
					}
					rules := append(detect.DefaultRules(), custom...)
					eng := detect.NewEngine(rules)
					agentHandler.SetDetector(eng) // atomik hot-swap (ingest yarışsız)
					adminAPI.SetDetector(eng)     // konsol kataloğu da güncel kalır
					if n := len(rules); n != prev {
						log.Printf("[detect] kurallar yeniden yüklendi: %d (önceki %d)", n, prev)
						prev = n
					}
				}
			}()
			log.Printf("tespit motoru: canlı yeniden yükleme her %s", d)
		}
	}
	// Zafiyet eşleştirme (#5): XEMS_VULN_FILE ayarlıysa CVE/KB veri kümesi yüklenir
	// ve yazılım envanteriyle eşleştirilir (/api/vulnerabilities).
	vulnCount := 0
	if vp := os.Getenv("XEMS_VULN_FILE"); vp != "" {
		vs, err := vuln.LoadFile(vp)
		if err != nil {
			return fmt.Errorf("zafiyet veri kümesi yüklenemedi: %w", err)
		}
		adminAPI.SetVulnSet(vs)
		vulnCount = vs.Size()
		log.Printf("zafiyet veri kümesi: %d kayıt yüklendi", vulnCount)
	}
	// Dağıtım koruma-duruşu (admin görünürlüğü: /api/features + konsol sistem kartı).
	adminAPI.SetFeatures(map[string]any{
		"alerting_enabled":      alertingOn,
		"siem_enabled":          siemOn,
		"vuln_dataset_size":     vulnCount,
		"alert_format":          getenv("XEMS_ALERT_FORMAT", "json"),
		"auto_response_enabled": autoRespOn,
		"ioc_indicators":        iocCount,
		"log_format":            getenv("XEMS_LOG_FORMAT", "text"),
		"persistence":           cfg.DatabaseURL != "",
		"cluster_enabled":       clusterOn,
		"wipe_dual_control":     wipeDual,
	})
	// Zaman aşımları: yavaş-istemci (slowloris) DoS'una karşı bağlantı ömrünü
	// sınırla. WriteTimeout KASITLI olarak ayarlanmadı — /api/stream (SSE)
	// uzun-ömürlü bir yanıttır ve WriteTimeout onu keserdi. ReadHeaderTimeout
	// başlık-yavaşlatma saldırısını, ReadTimeout yavaş-gövdeyi, IdleTimeout
	// boşta keep-alive bağlantılarını kapsar.
	httpSrv := &http.Server{
		Addr:              cfg.ListenAdmin,
		Handler:           adminAPI.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// KVKK saklama görevi: dolan event_logs partition'larını düşür, gelecek
	// ayları önceden oluştur (başlangıçta bir kez + günlük).
	retSvc := retention.NewService(backend, cfg.RetentionDays, 2, func(m string) { log.Println("[retention] " + m) })
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			if err := retSvc.Run(ctx, time.Now()); err != nil {
				log.Printf("saklama görevi hatası: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	// Zamanlanmış güvenlik-duruş raporu (#7): periyodik olarak (XEMS_REPORT_INTERVAL,
	// vars. 24s) filo/tehdit özetini üretip loglar (JSON loglama açıksa SIEM'e gider).
	// Tam rapor GET /api/report'tan (HTML/CSV) alınır.
	repInterval := 24 * time.Hour
	if d, err := time.ParseDuration(os.Getenv("XEMS_REPORT_INTERVAL")); err == nil && d > 0 {
		repInterval = d
	}
	go func() {
		t := time.NewTicker(repInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if sum, err := readSvc.Summary(ctx); err == nil {
				c := metrics.Counters()
				d := report.Data{
					DevicesTotal: sum.DevicesTotal, DevicesOnline: sum.DevicesOnline,
					DevicesQuarantined: sum.DevicesQuarantined, NonCompliant: sum.NonCompliantDevices,
					Detections: c["detections"], AlertsRaised: c["alerts_raised"],
					AlertsSuppressed: c["alerts_suppressed"], IocHits: c["ioc_hits"],
				}
				log.Printf("[report] zamanlanmış duruş: %s", d.Summary())
			}
		}
	}()

	// C2 beacon tespiti (#8): periyodik olarak netconn geçmişini analiz eder;
	// düzenli-aralıklı (düşük-jitter) (cihaz, uzak-IP) çiftlerini olası C2 beacon
	// olarak işaretler — bilinen IoC olmadan bilinmeyen C2'yi yakalar. Aynı çift
	// süreç ömrü boyunca bir kez uyarılır. XEMS_BEACON_DISABLE ile kapatılır.
	if os.Getenv("XEMS_BEACON_DISABLE") == "" {
		bInterval := 10 * time.Minute
		if d, err := time.ParseDuration(os.Getenv("XEMS_BEACON_INTERVAL")); err == nil && d > 0 {
			bInterval = d
		}
		bWindow := 2 * time.Hour
		if d, err := time.ParseDuration(os.Getenv("XEMS_BEACON_WINDOW")); err == nil && d > 0 {
			bWindow = d
		}
		alerted := map[string]bool{}
		go func() {
			t := time.NewTicker(bInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
				evs, err := readSvc.QueryEvents(ctx, adminread.EventFilter{
					Category: "NETWORK_CONN", Since: time.Now().Add(-bWindow), Limit: 20000,
				})
				if err != nil {
					continue
				}
				conns := make([]beacon.Conn, 0, len(evs))
				for _, e := range evs {
					var d struct {
						RemoteIP string `json:"remote_ip"`
					}
					if len(e.Details) > 0 {
						_ = json.Unmarshal(e.Details, &d)
					}
					if d.RemoteIP != "" {
						conns = append(conns, beacon.Conn{DeviceID: e.DeviceID, RemoteIP: d.RemoteIP, At: e.CreatedAt})
					}
				}
				for _, f := range beacon.Analyze(conns, 6, 0.25) {
					key := f.DeviceID + "|" + f.RemoteIP
					if alerted[key] {
						continue
					}
					alerted[key] = true
					ev := model.Event{
						Category: "SECURITY", Severity: "HIGH",
						Message: fmt.Sprintf("olası C2 beacon: %s (%d bağlantı, ~%s aralık, jitter %%%.0f)",
							f.RemoteIP, f.Count, f.MeanInterval.Round(time.Second), f.CoV*100),
						OccurredAt: time.Now(),
						Details: fmt.Sprintf(`{"beacon":true,"remote_ip":%q,"count":%d,"mean_interval_sec":%d,"cov":%.3f,"technique":"T1071"}`,
							f.RemoteIP, f.Count, int(f.MeanInterval.Seconds()), f.CoV),
					}
					if _, err := backend.SaveEvents(ctx, f.DeviceID, []model.Event{ev}); err == nil {
						liveBus.PublishEvent(f.DeviceID, ev.Severity, ev.Message)
						log.Printf("[beacon] cihaz %s: %s", f.DeviceID, ev.Message)
					}
				}
			}
		}()
		log.Printf("C2 beacon tespiti etkin (her %s, %s pencere)", bInterval, bWindow)
	}

	// Bayat-OFFLINE görevi: belirli süredir heartbeat göndermeyen ACTIVE
	// cihazları OFFLINE işaretle (durum sütunu ve özet sayaçları güvenilir
	// olsun). Eşik (~90 sn) heartbeat aralığının birkaç katıdır; her 1 dk taranır.
	const staleThreshold = 90 * time.Second
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			if n, err := backend.MarkStaleOffline(ctx, time.Now().Add(-staleThreshold)); err != nil {
				log.Printf("[status] bayat-OFFLINE görevi hatası: %v", err)
			} else if n > 0 {
				log.Printf("[status] %d cihaz OFFLINE işaretlendi", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	// Dinleyicileri eşzamanlı başlat.
	errCh := make(chan error, 3)
	go func() {
		log.Printf("AgentService (mTLS) dinliyor: %s", cfg.ListenAgent)
		errCh <- xgrpc.Serve(agentSrv, cfg.ListenAgent)
	}()
	go func() {
		log.Printf("EnrollmentService (TLS) dinliyor: %s", cfg.ListenEnroll)
		errCh <- xgrpc.Serve(enrollSrv, cfg.ListenEnroll)
	}()
	go func() {
		log.Printf("Admin API (TLS) dinliyor: %s", cfg.ListenAdmin)
		if err := httpSrv.ListenAndServeTLS(cfg.ServerCertPath, cfg.ServerKeyPath); err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("kapatma sinyali alındı, nazikçe durduruluyor...")
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	// Nazik kapanış (en fazla birkaç saniye).
	done := make(chan struct{})
	go func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = httpSrv.Shutdown(shutdownCtx)
		agentSrv.GracefulStop()
		enrollSrv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		agentSrv.Stop()
		enrollSrv.Stop()
	}
	return nil
}

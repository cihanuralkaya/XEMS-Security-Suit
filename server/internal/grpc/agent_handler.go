package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	xdrv1 "xdr.corp/suite/gen/xdr/v1"
	"xdr.corp/suite/server/internal/detect"
	"xdr.corp/suite/server/internal/ioc"
	"xdr.corp/suite/server/internal/metrics"
	"xdr.corp/suite/server/internal/mitre"
	"xdr.corp/suite/server/internal/model"
	"xdr.corp/suite/server/internal/notify"
	"xdr.corp/suite/server/internal/response"
	"xdr.corp/suite/server/internal/rollout"
)

// DeviceRegistry, cihaz durumu ve politika sürümü için sunucu-tarafı depolamadır.
type DeviceRegistry interface {
	// TouchHeartbeat, last_seen ve metrikleri günceller; cihazın SUNUCUDAKI
	// geçerli politika sürümünü döner.
	TouchHeartbeat(ctx context.Context, deviceID, agentVersion, osVersion string, at time.Time) (currentPolicyVersion string, err error)
	// PendingCommands, cihaz için bekleyen komutları döner (karantina vb.).
	PendingCommands(ctx context.Context, deviceID string) ([]*xdrv1.Command, error)
}

// EventSink, gelen olayları kalıcılaştırır ve kabul edilen son sırayı döner.
type EventSink interface {
	SaveEvents(ctx context.Context, deviceID string, evs []model.Event) (lastAccepted uint64, err error)
}

// PolicyProvider, cihaza atanmış geçerli politika paketini üretir.
type PolicyProvider interface {
	// CurrentPolicy, cihazın geçerli politika paketini döner. Cihaza politika
	// atanmamışsa (nil, nil) döner.
	CurrentPolicy(ctx context.Context, deviceID string) (*xdrv1.PolicyBundle, error)
}

// UpdateProvider, cihaz için geçerli OTA güncelleme manifestosunu döner.
type UpdateProvider interface {
	// LatestUpdate, platforma uygun en güncel sürümü döner. Güncelleme yoksa
	// (nil, nil). Dönen manifesto İMZALIDIR (imza DB'de saklanır).
	LatestUpdate(ctx context.Context, deviceID, currentAgentVersion, platform string) (*xdrv1.UpdateManifest, error)
}

// PolicyNotifier, açık politika akışlarını politika değişince uyandırır.
type PolicyNotifier interface {
	Subscribe(deviceID string) (<-chan struct{}, func())
}

// noopNotifier, notifier verilmediğinde kullanılır: hiç bildirim üretmez, akış
// yalnız ilk paketi gönderip istemci kapatana dek bekler.
type noopNotifier struct{}

func (noopNotifier) Subscribe(string) (<-chan struct{}, func()) {
	return make(chan struct{}), func() {}
}

// AdminNotifier, ajan-kaynaklı değişiklikleri admin konsoluna (SSE) iletmek için
// yayınlanır. nil verilmezse noop kullanılır; SSE bağımlılığı zorunlu değildir.
type AdminNotifier interface {
	PublishEvent(deviceID, severity, message string)
	PublishDevice(deviceID string)
}

// noopAdminNotifier, admin notifier verilmediğinde kullanılır.
type noopAdminNotifier struct{}

func (noopAdminNotifier) PublishEvent(string, string, string) {}
func (noopAdminNotifier) PublishDevice(string)                {}

// noopAlerter, dış uyarı yapılandırılmadığında kullanılır (hiçbir şey yapmaz).
type noopAlerter struct{}

func (noopAlerter) Notify(notify.Alert) {}

// AutoResponder, kritik olaylara otomatik müdahale eder (ör. karantina). nil ise
// noop kullanılır (otomatik müdahale kapalı).
type AutoResponder interface {
	AutoQuarantine(ctx context.Context, deviceID, reason string) error
}

// noopResponder, otomatik müdahale yapılandırılmadığında kullanılır.
type noopResponder struct{}

func (noopResponder) AutoQuarantine(context.Context, string, string) error { return nil }

// AgentHandler, AgentService gRPC sunucusunu uygular.
type AgentHandler struct {
	xdrv1.UnimplementedAgentServiceServer
	devices   DeviceRegistry
	events    EventSink
	policies  PolicyProvider
	updates   UpdateProvider
	notifier  PolicyNotifier
	admin     AdminNotifier
	alerter   notify.Notifier
	responder AutoResponder
	detector  atomic.Pointer[detect.Engine] // tespit motoru (canlı hot-reload için atomik)
	iocSet    atomic.Pointer[ioc.Set]       // tehdit istihbaratı göstergeleri (nil = kapalı; canlı hot-reload için atomik)
	artifacts ArtifactSink                  // adli/IR dosya toplama deposu
	now       func() time.Time
}

// ArtifactSink, ajanın topladığı dosya artefaktlarını saklar (adli/IR).
type ArtifactSink interface {
	SaveArtifact(ctx context.Context, deviceID, commandID, path, sha256 string, content []byte) (string, error)
}

type noopArtifactSink struct{}

func (noopArtifactSink) SaveArtifact(context.Context, string, string, string, string, []byte) (string, error) {
	return "", nil
}

// SetArtifactSink, dosya-toplama depolamasını etkinleştirir. Ayarlanmazsa
// yüklenen artefaktlar sessizce yok sayılır (noop).
func (h *AgentHandler) SetArtifactSink(a ArtifactSink) {
	if a == nil {
		a = noopArtifactSink{}
	}
	h.artifacts = a
}

// maxArtifactBytes, tek bir toplanan dosyanın üst sınırıdır (gRPC mesaj sınırı +
// depolama şişmesi koruması). Bundan büyük yüklemeler reddedilir.
const maxArtifactBytes = 3 << 20 // 3 MiB

// UploadArtifact, ajanın COLLECT_FILE komutuyla topladığı dosyayı saklar. Kimlik
// istemci sertifikasından; boyut ve SHA-256 doğrulanır.
func (h *AgentHandler) UploadArtifact(ctx context.Context, req *xdrv1.UploadArtifactRequest) (*xdrv1.UploadArtifactResponse, error) {
	deviceID, err := DeviceIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}
	content := req.GetContent()
	if len(content) == 0 {
		return nil, status.Error(codes.InvalidArgument, "boş içerik")
	}
	if len(content) > maxArtifactBytes {
		return nil, status.Errorf(codes.InvalidArgument, "dosya çok büyük (>%d bayt)", maxArtifactBytes)
	}
	sum := sha256.Sum256(content)
	if got := hex.EncodeToString(sum[:]); req.GetSha256() != "" && got != req.GetSha256() {
		return nil, status.Error(codes.InvalidArgument, "SHA-256 uyuşmuyor")
	}
	if _, err := h.artifacts.SaveArtifact(ctx, deviceID, req.GetCommandId(), req.GetPath(), hex.EncodeToString(sum[:]), content); err != nil {
		return nil, status.Error(codes.Internal, "artefakt kaydedilemedi")
	}
	return &xdrv1.UploadArtifactResponse{Ok: true}, nil
}

// SetIoCSet, tehdit istihbaratı (IoC) eşleştirmesini etkinleştirir/günceller. nil
// ise kapalı. Atomik saklama sayesinde ingest yolu eşzamanlı okurken canlı olarak
// (yeniden başlatmadan) güncellenebilir — hot-reload.
func (h *AgentHandler) SetIoCSet(s *ioc.Set) { h.iocSet.Store(s) }

// SetDetector, sunucu-taraflı tespit kural motorunu ayarlar/günceller. nil ise
// yerleşik varsayılan kural seti kullanılır. Atomik saklama sayesinde ingest
// yolu eşzamanlı değerlendirirken canlı (yeniden başlatmadan) güncellenebilir.
func (h *AgentHandler) SetDetector(e *detect.Engine) {
	if e == nil {
		e = detect.NewEngine(nil)
	}
	h.detector.Store(e)
}

// SetAlerter, yüksek önem düzeyli olaylarda dış uyarı (webhook) gönderimini
// etkinleştirir. nil ise noop kalır (uyarı gönderilmez).
func (h *AgentHandler) SetAlerter(a notify.Notifier) {
	if a == nil {
		a = noopAlerter{}
	}
	h.alerter = a
}

// SetAutoResponder, kritik olaylara otomatik müdahaleyi (karantina) etkinleştirir.
// nil ise noop kalır (otomatik müdahale kapalı — güvenli varsayılan).
func (h *AgentHandler) SetAutoResponder(r AutoResponder) {
	if r == nil {
		r = noopResponder{}
	}
	h.responder = r
}

// SetAdminNotifier, admin-tarafı SSE yayınını etkinleştirir. nil ise noop kalır.
func (h *AgentHandler) SetAdminNotifier(n AdminNotifier) {
	if n == nil {
		n = noopAdminNotifier{}
	}
	h.admin = n
}

// NewAgentHandler oluşturur. notifier nil ise anlık push devre dışıdır (akış
// yalnız ilk paketi gönderir ve istemci kapatana dek açık kalır).
func NewAgentHandler(devices DeviceRegistry, events EventSink, policies PolicyProvider, updates UpdateProvider, notifier PolicyNotifier) *AgentHandler {
	if notifier == nil {
		notifier = noopNotifier{}
	}
	h := &AgentHandler{devices: devices, events: events, policies: policies, updates: updates, notifier: notifier, admin: noopAdminNotifier{}, alerter: noopAlerter{}, responder: noopResponder{}, artifacts: noopArtifactSink{}, now: time.Now}
	h.detector.Store(detect.NewEngine(nil)) // atomik alan literal'de saklanamaz; kurulumda varsayılan
	return h
}

// Heartbeat, yaşam sinyalini işler. Yanıt SUNUCU SAATİNİ taşır — ajan, politika
// zaman pencerelerini bu çıpaya göre değerlendirir (inceleme #3).
func (h *AgentHandler) Heartbeat(ctx context.Context, req *xdrv1.HeartbeatRequest) (*xdrv1.HeartbeatResponse, error) {
	deviceID, err := DeviceIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}
	now := h.now()

	agentVersion, osVersion := "", ""
	if id := req.GetIdentity(); id != nil {
		agentVersion = id.GetAgentVersion()
		osVersion = id.GetOsVersion()
	}

	serverPolicyVersion, err := h.devices.TouchHeartbeat(ctx, deviceID, agentVersion, osVersion, now)
	if err != nil {
		return nil, status.Error(codes.Internal, "heartbeat kaydedilemedi")
	}
	h.admin.PublishDevice(deviceID) // konsola canlı: cihaz görüldü
	cmds, err := h.devices.PendingCommands(ctx, deviceID)
	if err != nil {
		return nil, status.Error(codes.Internal, "komutlar alınamadı")
	}

	return &xdrv1.HeartbeatResponse{
		ServerTime:            timestamppb.New(now),
		PolicyUpdateAvailable: serverPolicyVersion != "" && serverPolicyVersion != req.GetCurrentPolicyVersion(),
		PendingCommands:       cmds,
	}, nil
}

// ReportEvents, olay akışını alır (store-and-forward), kalıcılaştırır ve kabul
// edilen son sıra numarasını döner; ajan yalnız onaylananları tamponundan siler.
func (h *AgentHandler) ReportEvents(stream xdrv1.AgentService_ReportEventsServer) error {
	deviceID, err := DeviceIDFromContext(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}

	var lastAccepted uint64
	autoTriggered := false // akış başına en çok bir kez otomatik karantina
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&xdrv1.EventAck{LastAcceptedSequence: lastAccepted})
		}
		if err != nil {
			return err
		}
		domainEvents := make([]model.Event, 0, len(batch.GetEvents()))
		for _, e := range batch.GetEvents() {
			domainEvents = append(domainEvents, model.Event{
				Sequence:   e.GetSequence(),
				Category:   dbCategory(e.GetCategory()),
				Severity:   dbSeverity(e.GetSeverity()),
				Message:    e.GetMessage(),
				OccurredAt: e.GetOccurredAt().AsTime(),
				Details:    detailsJSON(e.GetDetails()),
			})
		}
		acc, err := h.events.SaveEvents(stream.Context(), deviceID, domainEvents)
		if err != nil {
			return status.Error(codes.Internal, "olaylar kaydedilemedi")
		}
		metrics.AddEventsIngested(len(domainEvents))
		for _, e := range domainEvents {
			h.admin.PublishEvent(deviceID, e.Severity, e.Message) // konsola canlı push
			// Sunucu-taraflı tespit: kural eşleşirse ADLANDIRILMIŞ, normalize önem
			// düzeyli + MITRE bağlamlı uyarı üret (ham olayın yerine geçer). Eşleşme
			// yoksa jenerik yol: ham önem düzeyi + MITRE sınıflandırması. Uyarı
			// best-effort; eşik/filtre notifier içinde. noop notifier'da maliyetsiz.
			if dets := h.detector.Load().Evaluate(e); len(dets) > 0 { // atomik Load: hot-reload ile yarışsız
				metrics.AddDetections(len(dets))
				for _, d := range dets {
					metrics.IncAlertRaised()
					h.alerter.Notify(notify.Alert{
						DeviceID:      deviceID,
						Category:      e.Category,
						Severity:      d.Severity,
						Message:       "[" + d.RuleName + "] " + e.Message,
						OccurredAt:    e.OccurredAt,
						TechniqueID:   d.Technique.ID,
						TechniqueName: d.Technique.Name,
						Tactic:        d.Technique.Tactic,
					})
				}
			} else {
				al := notify.Alert{
					DeviceID:   deviceID,
					Category:   e.Category,
					Severity:   e.Severity,
					Message:    e.Message,
					OccurredAt: e.OccurredAt,
				}
				if tq, ok := mitre.Classify(e.Category, e.Message); ok {
					al.TechniqueID, al.TechniqueName, al.Tactic = tq.ID, tq.Name, tq.Tactic
				}
				metrics.IncAlertRaised()
				h.alerter.Notify(al)
			}
			// Tehdit istihbaratı (IoC): olayın yapısal Details'i (ip/mac/process) veya
			// mesajı bilinen-kötü bir göstergeyle eşleşirse KRİTİK uyarı (yüksek-güven).
			// Atomik Load: eşzamanlı hot-reload (SetIoCSet) ile yarışsız.
			if iocSet := h.iocSet.Load(); iocSet.Size() > 0 {
				var dm map[string]any
				if e.Details != "" {
					_ = json.Unmarshal([]byte(e.Details), &dm)
				}
				if lbl, ind, ok := iocSet.Match(dm, e.Message); ok {
					metrics.IncIocHit()
					metrics.IncAlertRaised()
					h.alerter.Notify(notify.Alert{
						DeviceID:      deviceID,
						Category:      e.Category,
						Severity:      "CRITICAL",
						Message:       "IoC eşleşmesi [" + lbl + "] " + ind + ": " + e.Message,
						OccurredAt:    e.OccurredAt,
						TechniqueID:   "T1071",
						TechniqueName: "Application Layer Protocol",
						Tactic:        "Command and Control",
					})
				}
			}
		}
		// Otomatik müdahale (SOAR): kritik olay geldiyse cihazı otomatik karantinaya
		// al (akış başına bir kez; noop responder'da maliyetsiz). Hata olay-alımını
		// KESMEZ (best-effort; komut kuyruğu kalıcıdır).
		if !autoTriggered {
			if reason, ok := response.ShouldTrigger(domainEvents); ok {
				if err := h.responder.AutoQuarantine(stream.Context(), deviceID, reason); err == nil {
					autoTriggered = true
					metrics.IncAutoQuarantine()
					h.admin.PublishDevice(deviceID) // konsol durumu tazelesin
				}
			}
		}
		if acc > lastAccepted {
			lastAccepted = acc
		}
	}
}

// detailsJSON, proto Event.details (structpb.Struct) alanını kalıcılaştırılacak
// JSON metnine çevirir. Ayrıntı yoksa (nil) boş string döner; böylece db katmanı
// alanı NULL saklar. Serileştirme hatası olası değildir (structpb her zaman geçerli
// JSON üretir), yine de güvenli tarafta boş string döneriz.
func detailsJSON(d *structpb.Struct) string {
	if d == nil {
		return ""
	}
	b, err := protojson.Marshal(d)
	if err != nil {
		return ""
	}
	return string(b)
}

// dbCategory, proto enum'unu DB event_category ENUM'una eşler
// ("EVENT_CATEGORY_SECURITY" -> "SECURITY"). Belirsiz değer SYSTEM'e düşer.
func dbCategory(c xdrv1.EventCategory) string {
	s := strings.TrimPrefix(c.String(), "EVENT_CATEGORY_")
	if s == "" || s == "UNSPECIFIED" {
		return "SYSTEM"
	}
	return s
}

// dbSeverity, proto enum'unu DB severity ENUM'una eşler. Belirsiz değer INFO'ya düşer.
func dbSeverity(v xdrv1.Severity) string {
	s := strings.TrimPrefix(v.String(), "SEVERITY_")
	if s == "" || s == "UNSPECIFIED" {
		return "INFO"
	}
	return s
}

// StreamPolicies, UZUN-ÖMÜRLÜ bir akıştır: önce ajanın bildirdiği sürümden
// farklıysa güncel paketi gönderir, sonra açık kalıp politika değiştikçe (admin
// atama → Publish) yeni paketleri ANINDA iter. İstemci akışı kapatınca (ctx
// iptal) döngü sonlanır.
func (h *AgentHandler) StreamPolicies(req *xdrv1.PolicySubscribeRequest, stream xdrv1.AgentService_StreamPoliciesServer) error {
	deviceID, err := DeviceIDFromContext(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}
	notify, cancel := h.notifier.Subscribe(deviceID)
	defer cancel()
	return streamPolicyLoop(stream.Context(), deviceID, req.GetCurrentPolicyVersion(),
		h.policies, notify, stream.Send)
}

// streamPolicyLoop, transport'tan bağımsız push döngüsüdür (test edilebilir):
// güncel paketi (sürüm değiştiyse) gönderir, sonra her bildirimde tekrar dener.
func streamPolicyLoop(ctx context.Context, deviceID, currentVersion string,
	provider PolicyProvider, notify <-chan struct{}, send func(*xdrv1.PolicyBundle) error) error {

	lastVer := currentVersion
	sendIfNewer := func() error {
		b, err := provider.CurrentPolicy(ctx, deviceID)
		if err != nil {
			return status.Error(codes.Internal, "politika alınamadı")
		}
		if b == nil || b.GetPolicyVersion() == lastVer {
			return nil
		}
		if err := send(b); err != nil {
			return err
		}
		lastVer = b.GetPolicyVersion()
		return nil
	}

	if err := sendIfNewer(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil // istemci kapattı; akışı nazikçe bitir
		case <-notify:
			if err := sendIfNewer(); err != nil {
				return err
			}
		}
	}
}

// CheckUpdate, OTA güncelleme manifestosunu döner. Manifesto İMZALIDIR; ajan
// indirmeden önce imzayı gömülü public key ile doğrular (inceleme #4).
func (h *AgentHandler) CheckUpdate(ctx context.Context, req *xdrv1.UpdateCheckRequest) (*xdrv1.UpdateManifest, error) {
	deviceID, err := DeviceIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}
	id := req.GetIdentity()
	m, err := h.updates.LatestUpdate(ctx, deviceID, id.GetAgentVersion(), id.GetOsPlatform())
	if err != nil {
		return nil, status.Error(codes.Internal, "güncelleme sorgulanamadı")
	}
	if m == nil || !m.GetUpdateAvailable() {
		return &xdrv1.UpdateManifest{UpdateAvailable: false}, nil
	}
	// Kademeli dağıtım: cihaz bu sürümün rollout kohortunda değilse henüz sunma.
	if !rollout.InCohort(deviceID, m.GetTargetVersion(), int(m.GetRolloutPercent())) {
		return &xdrv1.UpdateManifest{UpdateAvailable: false}, nil
	}
	return m, nil
}

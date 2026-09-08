// Package memstore, C2'nin ihtiyaç duyduğu tüm depolama arayüzlerini bellek-içi
// karşılayan bir DEMO/TEST deposudur. PostgreSQL olmadan sistemi uçtan uca canlı
// çalıştırmak için kullanılır; KALICILIK YOKTUR (süreç kapanınca veri kaybolur).
//
// Üretimde db.Store kullanılır; memstore yalnız geliştirme/gösterim içindir.
package memstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	xemsv1 "xems.corp/suite/gen/xems/v1"
	"xems.corp/suite/server/internal/admin"
	"xems.corp/suite/server/internal/adminread"
	"xems.corp/suite/server/internal/enroll"
	"xems.corp/suite/server/internal/model"
	"xems.corp/suite/server/internal/security"
)

type device struct {
	id            string
	hostnameEnc   []byte
	macEnc        []byte
	osEnc         []byte
	macBidx       []byte
	osPlatform    string
	osVersion     string
	agentVersion  string
	status        string
	policyVersion string
	policyID      string
	lastSeen      time.Time
	tags          []string
}

type tokenInfo struct {
	id        string
	createdBy string
	expiresAt time.Time
	used      bool
	boundDev  string
	createdAt time.Time
}

type certRec struct {
	deviceID    string
	serial      string
	fingerprint []byte
	notBefore   time.Time
	notAfter    time.Time
	revoked     bool
}

// cmdRec, komut geçmişi kaydıdır. PendingCommands teslimde bekleyen kuyruğu
// temizlediğinden, geçmiş kaybolmasın diye ayrı tutulur.
type cmdRec struct {
	deviceID    string
	cmdType     string
	issuedBy    string
	createdAt   time.Time
	deliveredAt *time.Time
}

type policyRule struct {
	id, typ, target, start, end string
	activeDays                  []uint32
}

type policyRec struct {
	id, name, version string
	rules             []policyRule
}

type eventRec struct {
	id         string // KARARLI kimlik (kayıt anında atanır; her listelemede değişmez)
	deviceID   string
	category   string
	severity   string
	message    string
	occurredAt time.Time
	createdAt  time.Time
	details    string // serbest biçimli JSON metni ("" = ayrıntı yok)
}

type adminRec struct {
	id, email, passwordHash string
	role                    admin.Role
	active                  bool
	mfaSecret               string // TOTP sırrı (bellek-içi demo; db katmanı şifreler)
	mfaEnrolled             bool
}

type auditRec struct {
	id         int64
	adminEmail string
	action     string
	targetType string
	targetID   string
	createdAt  time.Time
	hash       []byte // zincir hash'i (kurcalama-kanıtı)
}

// Store, tüm C2 depolama arayüzlerini bellek-içi karşılar.
type Store struct {
	mu         sync.Mutex
	devices    map[string]*device           // deviceID -> device
	tokens     map[string]*tokenInfo        // tokenIndex(hex) -> token
	certs      []certRec                    // sertifikalar (iptal takibi)
	commands   map[string][]*xemsv1.Command // deviceID -> bekleyen komutlar
	cmdHistory []cmdRec                     // komut geçmişi (teslimde temizlenmez)
	policies   map[string]*policyRec        // policyID -> politika
	events     []eventRec                   // olay logları
	admins     map[string]*adminRec         // email -> admin
	adminsByID map[string]*adminRec         // id -> admin
	audit      []auditRec                   // denetim izi (en eskiden yeniye eklenir)
	auditSeq   int64                        // audit_log identity taklidi
	eventAcks  map[string]eventAckRec       // eventID -> triyaj durumu (alarm yaşam-döngüsü)
	artifacts  []artifactRec                // toplanan dosya artefaktları (adli/IR)
	pendWipes  map[string]pendingWipeRec    // deviceID -> bekleyen WIPE talebi (çift-kontrol)
	seq        int
}

// pendingWipeRec, ikinci-onay bekleyen bir WIPE talebidir (bellek-içi).
type pendingWipeRec struct {
	requestedBy string
	reason      string
	at          time.Time
}

// eventAckRec, bir olayın triyaj/vaka durumudur (bellek-içi).
type eventAckRec struct {
	status   string
	assignee string
	note     string
	adminID  string
	at       time.Time
}

// artifactRec, toplanan bir dosya artefaktıdır (bellek-içi).
type artifactRec struct {
	id, deviceID, commandID, path, sha256 string
	content                               []byte
	collectedAt                           time.Time
}

// New, boş bir bellek-içi depo oluşturur.
func New() *Store {
	return &Store{
		devices:    map[string]*device{},
		tokens:     map[string]*tokenInfo{},
		commands:   map[string][]*xemsv1.Command{},
		policies:   map[string]*policyRec{},
		admins:     map[string]*adminRec{},
		adminsByID: map[string]*adminRec{},
		eventAcks:  map[string]eventAckRec{},
	}
}

func randID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// --- Tohumlama (demo kurulum) ---

// SeedAdmin, bir yönetici ekler ve id'sini döner.
func (s *Store) SeedAdmin(email, passwordHash string, role admin.Role) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randID("admin-")
	rec := &adminRec{id: id, email: email, passwordHash: passwordHash, role: role, active: true}
	s.admins[email] = rec
	s.adminsByID[id] = rec
	return id
}

// SeedDemoPolicy, kural içeren bir demo politikası ekler (konsolda kural editörü
// olmadığından). Hedef zararsız bir sentinel'dir; gerçek bir süreci öldürmez.
func (s *Store) SeedDemoPolicy() (id, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = randID("pol-")
	version = "demo-1"
	s.policies[id] = &policyRec{
		id: id, name: "Demo Politika", version: version,
		rules: []policyRule{{
			id: "r1", typ: "APP_BLOCK_ALWAYS", target: "xems-demo-blocked.exe",
		}},
	}
	return id, version
}

// --- enroll.Store ---

func (s *Store) ConsumeEnrollmentToken(_ context.Context, tokenIndex []byte, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[hex.EncodeToString(tokenIndex)]
	if !ok || t.used || now.After(t.expiresAt) {
		return "", enroll.ErrInvalidToken
	}
	t.used = true
	return t.boundDev, nil
}

func (s *Store) UpsertEnrollingDevice(_ context.Context, in enroll.DeviceEnrollment) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := in.PreferredDeviceID
	if id == "" {
		// mac bidx eşleşen cihaz varsa onu güncelle (yeniden kayıt).
		for _, d := range s.devices {
			if len(d.macBidx) > 0 && string(d.macBidx) == string(in.MACBlindIndex) {
				id = d.id
				break
			}
		}
	}
	if id == "" {
		id = randID("dev-")
	}
	s.devices[id] = &device{
		id: id, hostnameEnc: in.HostnameEnc, macEnc: in.MACEnc, osEnc: in.OSInfoEnc,
		macBidx: in.MACBlindIndex, osPlatform: in.OSPlatform, agentVersion: in.AgentVersion,
		status: "ACTIVE", lastSeen: time.Now(),
	}
	return id, nil
}

func (s *Store) SaveCertificate(_ context.Context, c enroll.CertRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs = append(s.certs, certRec{
		deviceID: c.DeviceID, serial: c.Serial, fingerprint: c.Fingerprint,
		notBefore: c.NotBefore, notAfter: c.NotAfter,
	})
	return nil
}

// DeviceHasActiveCert, cihazın iptal edilmemiş en az bir sertifikası var mı (db
// ile aynı davranış: revoked=false). Yenileme iptal-bypass korumasında kullanılır.
func (s *Store) DeviceHasActiveCert(_ context.Context, deviceID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.certs {
		if c.deviceID == deviceID && !c.revoked {
			return true, nil
		}
	}
	return false, nil
}

// --- DeviceRegistry ---

func (s *Store) TouchHeartbeat(_ context.Context, deviceID, agentVersion, osVersion string, at time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok {
		return "", nil // demo: bilinmeyen cihazı sessiz geç
	}
	d.lastSeen = at
	if agentVersion != "" {
		d.agentVersion = agentVersion
	}
	if osVersion != "" {
		d.osVersion = osVersion
	}
	if d.status == "OFFLINE" {
		d.status = "ACTIVE"
	}
	return d.policyVersion, nil
}

// MarkStaleOffline, last_seen'i olderThan'dan eski olan ACTIVE cihazları
// OFFLINE işaretler ve etkilenen sayıyı döner (db.Store ile eşdeğer davranış).
func (s *Store) MarkStaleOffline(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, d := range s.devices {
		if d.status == "ACTIVE" && d.lastSeen.Before(olderThan) {
			d.status = "OFFLINE"
			n++
		}
	}
	return n, nil
}

// SetDeviceStatus, cihaz durumunu doğrudan ayarlar (admin aksiyonu yansıması).
// Bilinmeyen cihaz sessizce yok sayılır (db UPDATE'in 0 satır etkilemesi gibi).
func (s *Store) SetDeviceStatus(_ context.Context, deviceID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[deviceID]; ok {
		d.status = status
	}
	return nil
}

func (s *Store) PendingCommands(_ context.Context, deviceID string) ([]*xemsv1.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.commands[deviceID]
	s.commands[deviceID] = nil
	// Bekleyen komutlar teslim edildi: geçmişteki teslim edilmemiş kayıtları
	// işaretle (geçmiş listesi ayrı tutulur, temizlenmez).
	if len(out) > 0 {
		now := time.Now()
		for i := range s.cmdHistory {
			if s.cmdHistory[i].deviceID == deviceID && s.cmdHistory[i].deliveredAt == nil {
				t := now
				s.cmdHistory[i].deliveredAt = &t
			}
		}
	}
	return out, nil
}

// --- EventSink ---

func (s *Store) SaveEvents(_ context.Context, deviceID string, evs []model.Event) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var last uint64
	now := time.Now()
	for _, e := range evs {
		s.events = append(s.events, eventRec{
			id:       randID("evt-"), // kararlı kimlik (kayıt anında)
			deviceID: deviceID, category: e.Category, severity: e.Severity,
			message: e.Message, occurredAt: e.OccurredAt, createdAt: now,
			details: e.Details,
		})
		if e.Sequence > last {
			last = e.Sequence
		}
	}
	// Bellek şişmesini önlemek için son 5000 olayı tut.
	if len(s.events) > 5000 {
		s.events = s.events[len(s.events)-5000:]
	}
	return last, nil
}

// --- PolicyProvider ---

func (s *Store) CurrentPolicy(_ context.Context, deviceID string) (*xemsv1.PolicyBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok || d.policyID == "" {
		return nil, nil
	}
	p, ok := s.policies[d.policyID]
	if !ok {
		return nil, nil
	}
	var rules []*xemsv1.PolicyRule
	for _, r := range p.rules {
		rules = append(rules, &xemsv1.PolicyRule{
			RuleId: r.id, Type: ruleTypeToProto(r.typ), TargetValue: r.target,
			StartTime: r.start, EndTime: r.end, ActiveDays: r.activeDays,
		})
	}
	return &xemsv1.PolicyBundle{PolicyVersion: p.version, Rules: rules, IssuedAt: timestamppb.Now()}, nil
}

// --- UpdateProvider ---

func (s *Store) LatestUpdate(_ context.Context, _, _, _ string) (*xemsv1.UpdateManifest, error) {
	return nil, nil // demo: OTA sürümü yok
}

// --- admin.Store ---

func (s *Store) AdminRole(_ context.Context, adminID string) (admin.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.adminsByID[adminID]; ok {
		return a.role, nil
	}
	return admin.Role(""), nil
}

func (s *Store) SaveEnrollmentToken(_ context.Context, tokenIndex []byte, createdBy string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[hex.EncodeToString(tokenIndex)] = &tokenInfo{
		id: randID("etok-"), createdBy: createdBy, expiresAt: expiresAt, createdAt: time.Now(),
	}
	return nil
}

// RevokeEnrollmentToken, id ile token'ı bulup kullanılmış işaretler (used=true).
// Zaten kullanılmış/yok token için sessiz (no-op) — db davranışını taklit eder.
func (s *Store) RevokeEnrollmentToken(_ context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.id == tokenID && !t.used {
			t.used = true
			break
		}
	}
	return nil
}

func (s *Store) EnqueueCommand(_ context.Context, deviceID, cmdType, issuedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands[deviceID] = append(s.commands[deviceID], &xemsv1.Command{
		CommandId: randID("cmd-"), Type: commandTypeToProto(cmdType),
	})
	// Geçmişe de ekle (bekleyen kuyruk teslimde temizlense de geçmiş kalır).
	s.cmdHistory = append(s.cmdHistory, cmdRec{
		deviceID: deviceID, cmdType: cmdType, issuedBy: issuedBy, createdAt: time.Now(),
	})
	return nil
}

// EnqueueCommandParams, parametreli komut kuyruğa ekler (params → structpb).
func (s *Store) EnqueueCommandParams(_ context.Context, deviceID, cmdType, issuedBy string, params map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pb *structpb.Struct
	if len(params) > 0 {
		m := make(map[string]any, len(params))
		for k, v := range params {
			m[k] = v
		}
		pb, _ = structpb.NewStruct(m)
	}
	s.commands[deviceID] = append(s.commands[deviceID], &xemsv1.Command{
		CommandId: randID("cmd-"), Type: commandTypeToProto(cmdType), Params: pb,
	})
	s.cmdHistory = append(s.cmdHistory, cmdRec{
		deviceID: deviceID, cmdType: cmdType, issuedBy: issuedBy, createdAt: time.Now(),
	})
	return nil
}

func (s *Store) RevokeDeviceCerts(_ context.Context, deviceID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.certs {
		if s.certs[i].deviceID == deviceID {
			s.certs[i].revoked = true
		}
	}
	return nil
}

// Ping, bellek-içi depo her zaman sağlıklıdır (readiness).
func (s *Store) Ping(_ context.Context) error { return nil }

// EraseDeviceData, KVKK veri silme: cihazın olay logları + komut geçmişini siler,
// bekleyen komutları temizler ve sertifikalarını iptal eder. Denetim izi korunur.
func (s *Store) EraseDeviceData(_ context.Context, deviceID string) (int, int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keptEv := s.events[:0:0]
	evDel := 0
	for _, e := range s.events {
		if e.deviceID == deviceID {
			evDel++
		} else {
			keptEv = append(keptEv, e)
		}
	}
	s.events = keptEv

	keptCmd := s.cmdHistory[:0:0]
	cmdDel := 0
	for _, c := range s.cmdHistory {
		if c.deviceID == deviceID {
			cmdDel++
		} else {
			keptCmd = append(keptCmd, c)
		}
	}
	s.cmdHistory = keptCmd
	delete(s.commands, deviceID)

	certRev := 0
	for i := range s.certs {
		if s.certs[i].deviceID == deviceID && !s.certs[i].revoked {
			s.certs[i].revoked = true
			certRev++
		}
	}
	return evDel, cmdDel, certRev, nil
}

// WriteAudit, denetim izine bir kayıt ekler. Admin e-postası adminsByID'den
// çözülür (eşleşmezse boş kalır — db LEFT JOIN davranışını taklit eder).
func (s *Store) WriteAudit(_ context.Context, adminID, action, targetType, targetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var email string
	if a, ok := s.adminsByID[adminID]; ok {
		email = a.email
	}
	s.auditSeq++
	at := time.Now()
	var prev []byte
	if n := len(s.audit); n > 0 {
		prev = s.audit[n-1].hash
	}
	hash := security.AuditChainHash(prev, email, action, targetType, targetID, at.UnixNano())
	s.audit = append(s.audit, auditRec{
		id: s.auditSeq, adminEmail: email, action: action,
		targetType: targetType, targetID: targetID, createdAt: at, hash: hash,
	})
	return nil
}

// VerifyAuditChain, denetim izi hash-zincirinin bütünlüğünü doğrular: her kaydın
// saklanan hash'i, bir önceki hash + kayıt alanlarından yeniden hesaplananla
// eşleşmeli. Eşleşmezse ilk kırık kaydın id'siyle hata döner (SEC C-1).
func (s *Store) VerifyAuditChain(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var prev []byte
	for _, r := range s.audit {
		want := security.AuditChainHash(prev, r.adminEmail, r.action, r.targetType, r.targetID, r.createdAt.UnixNano())
		if !bytes.Equal(want, r.hash) {
			return fmt.Errorf("denetim izi zinciri kırık: kayıt id=%d", r.id)
		}
		prev = r.hash
	}
	return nil
}

func (s *Store) CreatePolicy(_ context.Context, name, version string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randID("pol-")
	s.policies[id] = &policyRec{id: id, name: name, version: version}
	return id, nil
}

func (s *Store) AssignPolicy(_ context.Context, deviceID, policyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok {
		return nil
	}
	if p, ok := s.policies[policyID]; ok {
		d.policyID = policyID
		d.policyVersion = p.version
	}
	return nil
}

func (s *Store) AddPolicyRule(_ context.Context, policyID string, in admin.RuleInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[policyID]
	if !ok {
		return nil
	}
	days := make([]uint32, 0, len(in.ActiveDays))
	for _, d := range in.ActiveDays {
		if d >= 0 {
			days = append(days, uint32(d))
		}
	}
	if len(days) == 0 {
		days = []uint32{1, 2, 3, 4, 5, 6, 0}
	}
	p.rules = append(p.rules, policyRule{
		id: randID("r-"), typ: in.Type, target: in.Target,
		start: in.Start, end: in.End, activeDays: days,
	})
	return nil
}

// BumpPolicyVersion, politikanın sürümünü yeni bir zaman-damgası etiketine
// yükseltir ve o politikaya atanmış cihazların policyVersion'ını da günceller
// (heartbeat eden ajanlar yeni sürümü görüp yeni paketi çeker).
func (s *Store) BumpPolicyVersion(_ context.Context, policyID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[policyID]
	if !ok {
		return "", nil
	}
	nv := time.Now().UTC().Format("20060102150405.000000000")
	p.version = nv
	for _, d := range s.devices {
		if d.policyID == policyID {
			d.policyVersion = nv
		}
	}
	return nv, nil
}

func (s *Store) DevicesForPolicy(_ context.Context, policyID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, d := range s.devices {
		if d.policyID == policyID {
			out = append(out, d.id)
		}
	}
	return out, nil
}

// ListPolicies, tüm politikaları kural + atanmış cihaz sayımlarıyla, ada göre
// sıralı döner (deterministik çıktı).
func (s *Store) ListPolicies(_ context.Context, limit int) ([]adminread.PolicyRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	assigned := map[string]int{}
	for _, d := range s.devices {
		if d.policyID != "" {
			assigned[d.policyID]++
		}
	}
	out := make([]adminread.PolicyRow, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, adminread.PolicyRow{
			ID: p.id, Name: p.name, Version: p.version,
			RuleCount: len(p.rules), DeviceCount: assigned[p.id],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) ListPolicyRules(_ context.Context, policyID string) ([]admin.RuleView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[policyID]
	if !ok {
		return nil, nil
	}
	var out []admin.RuleView
	for _, r := range p.rules {
		days := make([]int32, 0, len(r.activeDays))
		for _, d := range r.activeDays {
			days = append(days, int32(d))
		}
		out = append(out, admin.RuleView{
			ID: r.id, Type: r.typ, Target: r.target,
			Start: r.start, End: r.end, ActiveDays: days,
		})
	}
	return out, nil
}

// CreateAdmin, yeni bir yönetici ekler (aktif) ve id'sini döner.
func (s *Store) CreateAdmin(_ context.Context, email, passwordHash string, role admin.Role) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randID("admin-")
	rec := &adminRec{id: id, email: email, passwordHash: passwordHash, role: role, active: true}
	s.admins[email] = rec
	s.adminsByID[id] = rec
	return id, nil
}

func (s *Store) SetAdminRole(_ context.Context, id string, role admin.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.adminsByID[id]; ok {
		a.role = role
	}
	return nil
}

func (s *Store) DeactivateAdmin(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.adminsByID[id]; ok {
		a.active = false
	}
	return nil
}

// ListAdmins, yöneticileri e-postaya göre sıralı döner (parola hash'i olmadan).
func (s *Store) ListAdmins(_ context.Context) ([]admin.AdminInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]admin.AdminInfo, 0, len(s.adminsByID))
	for _, a := range s.adminsByID {
		out = append(out, admin.AdminInfo{ID: a.id, Email: a.email, Role: a.role, Active: a.active})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

// SetPendingMFASecret, yöneticinin TOTP sırrını saklar (henüz etkin değil).
func (s *Store) SetPendingMFASecret(_ context.Context, adminID, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.adminsByID[adminID]; ok {
		a.mfaSecret = secret
		a.mfaEnrolled = false
	}
	return nil
}

// LookupMFA, TOTP sırrını ve etkin durumunu döner.
func (s *Store) LookupMFA(_ context.Context, adminID string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.adminsByID[adminID]; ok {
		return a.mfaSecret, a.mfaEnrolled, nil
	}
	return "", false, nil
}

// ActivateMFA, bekleyen sırrı etkinleştirir.
func (s *Store) ActivateMFA(_ context.Context, adminID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.adminsByID[adminID]; ok && a.mfaSecret != "" {
		a.mfaEnrolled = true
	}
	return nil
}

// DisableMFA, sırrı temizler ve MFA'yı kapatır.
func (s *Store) DisableMFA(_ context.Context, adminID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.adminsByID[adminID]; ok {
		a.mfaSecret = ""
		a.mfaEnrolled = false
	}
	return nil
}

// --- adminread.Store ---

// Derleme-zamanı arayüz kontrolü.
var _ adminread.Store = (*Store)(nil)

func (s *Store) ListDevices(_ context.Context, limit int) ([]adminread.DeviceRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.DeviceRow
	for _, d := range s.devices {
		out = append(out, adminread.DeviceRow{
			ID: d.id, Status: d.status, AgentVersion: d.agentVersion, OSPlatform: d.osPlatform,
			LastSeen: d.lastSeen, HostnameEnc: d.hostnameEnc, MACEnc: d.macEnc, OSVersion: d.osVersion, Tags: append([]string(nil), d.tags...),
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) ListEvents(_ context.Context, deviceID, severity, category string, limit int) ([]adminread.EventRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.EventRow
	// En yeniden eskiye.
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if deviceID != "" && e.deviceID != deviceID {
			continue
		}
		if severity != "" && e.severity != severity {
			continue
		}
		if category != "" && e.category != category {
			continue
		}
		var details []byte
		if e.details != "" {
			details = []byte(e.details)
		}
		out = append(out, adminread.EventRow{
			ID: e.id, DeviceID: e.deviceID, Category: e.category, Severity: e.severity,
			Message: e.message, OccurredAt: e.occurredAt, CreatedAt: e.createdAt,
			Details: details,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) DeviceStatusCounts(_ context.Context) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, d := range s.devices {
		out[d.status]++
	}
	return out, nil
}

func (s *Store) EventSeverityCounts(_ context.Context, since time.Time) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, e := range s.events {
		if e.createdAt.Before(since) {
			continue
		}
		out[e.severity]++
	}
	return out, nil
}

func (s *Store) EventCategoryCounts(_ context.Context, since time.Time) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, e := range s.events {
		if e.createdAt.Before(since) {
			continue
		}
		out[e.category]++
	}
	return out, nil
}

// LatestComplianceByDevice, uyum verisi taşıyan her cihazın EN SON
// disk_encryption/firewall durumunu döner. Olaylar yeniden-eskiye gezilir;
// cihaz başına ilk görülen uyum-olayı en güncel kabul edilir.
func (s *Store) LatestComplianceByDevice(_ context.Context) (map[string]adminread.ComplianceStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]adminread.ComplianceStatus{}
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if e.deviceID == "" || e.details == "" {
			continue
		}
		if _, seen := out[e.deviceID]; seen {
			continue
		}
		var d struct {
			Enc string `json:"disk_encryption"`
			Fw  string `json:"firewall"`
		}
		if err := json.Unmarshal([]byte(e.details), &d); err != nil {
			continue
		}
		if d.Enc == "" && d.Fw == "" {
			continue // uyum-olayı değil
		}
		out[e.deviceID] = adminread.ComplianceStatus{Enc: d.Enc, Fw: d.Fw}
	}
	return out, nil
}

// SearchSoftware, her cihazın EN SON yazılım envanterinde query'yi (küçük/büyük
// harf duyarsız alt-dize) içeren paketleri arar. Olaylar yeniden-eskiye gezilir;
// cihaz başına ilk görülen envanter olayı geçerlidir.
func (s *Store) SearchSoftware(_ context.Context, query string) (map[string][]string, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	out := map[string][]string{}
	if q == "" {
		return out, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{} // cihaz başına yalnız en son envanter
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if e.deviceID == "" || e.details == "" || seen[e.deviceID] {
			continue
		}
		var d struct {
			Software []string `json:"software"`
		}
		if err := json.Unmarshal([]byte(e.details), &d); err != nil || d.Software == nil {
			continue
		}
		seen[e.deviceID] = true // bu cihazın en son envanterini işledik
		var m []string
		for _, name := range d.Software {
			if strings.Contains(strings.ToLower(name), q) {
				m = append(m, name)
			}
		}
		if len(m) > 0 {
			out[e.deviceID] = m
		}
	}
	return out, nil
}

// SetEventAck, bir olayın triyaj durumunu ayarlar (upsert). Alarm yaşam-döngüsü.
// SavePendingWipe, ikinci-onay bekleyen WIPE talebini saklar (çift-kontrol).
func (s *Store) SavePendingWipe(_ context.Context, deviceID, requestedBy, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendWipes == nil {
		s.pendWipes = map[string]pendingWipeRec{}
	}
	s.pendWipes[deviceID] = pendingWipeRec{requestedBy: requestedBy, reason: reason, at: time.Now()}
	return nil
}

// GetPendingWipe, cihaz için bekleyen WIPE talebini döner (talep eden admin id'si).
func (s *Store) GetPendingWipe(_ context.Context, deviceID string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.pendWipes[deviceID]
	return rec.requestedBy, ok, nil
}

// DeletePendingWipe, bekleyen WIPE talebini siler (onay/iptal sonrası).
func (s *Store) DeletePendingWipe(_ context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendWipes, deviceID)
	return nil
}

// ListPendingWipes, bekleyen tüm WIPE taleplerini döner (talep eden admin e-postasıyla).
func (s *Store) ListPendingWipes(_ context.Context) ([]adminread.PendingWipeRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]adminread.PendingWipeRow, 0, len(s.pendWipes))
	for dev, rec := range s.pendWipes {
		email := rec.requestedBy
		if a, ok := s.adminsByID[rec.requestedBy]; ok {
			email = a.email
		}
		out = append(out, adminread.PendingWipeRow{
			DeviceID: dev, RequestedBy: email, Reason: rec.reason, RequestedAt: rec.at,
		})
	}
	return out, nil
}

func (s *Store) SetEventAck(_ context.Context, eventID, adminID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.eventAcks == nil {
		s.eventAcks = map[string]eventAckRec{}
	}
	rec := s.eventAcks[eventID] // mevcut assignee/note korunur
	rec.status, rec.adminID, rec.at = status, adminID, time.Now()
	s.eventAcks[eventID] = rec
	return nil
}

// SetEventCase, olayın sorumlu+not alanlarını ayarlar (durumu korur). Vaka yönetimi.
func (s *Store) SetEventCase(_ context.Context, eventID, adminID, assignee, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.eventAcks == nil {
		s.eventAcks = map[string]eventAckRec{}
	}
	rec := s.eventAcks[eventID] // mevcut status korunur
	rec.assignee, rec.note, rec.adminID, rec.at = assignee, note, adminID, time.Now()
	s.eventAcks[eventID] = rec
	return nil
}

// EventAcks, triyaj işaretli olayların durumunu döner (adminID → e-posta çözülür).
func (s *Store) EventAcks(_ context.Context) (map[string]adminread.EventAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]adminread.EventAck, len(s.eventAcks))
	for id, a := range s.eventAcks {
		email := a.adminID
		if rec, ok := s.adminsByID[a.adminID]; ok {
			email = rec.email
		}
		out[id] = adminread.EventAck{Status: a.status, Assignee: a.assignee, Note: a.note, AdminEmail: email, At: a.at}
	}
	return out, nil
}

// SaveArtifact, toplanan bir dosyayı saklar ve id'sini döner (grpc.ArtifactSink).
func (s *Store) SaveArtifact(_ context.Context, deviceID, commandID, path, sha256 string, content []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randID("art-")
	cp := make([]byte, len(content))
	copy(cp, content)
	s.artifacts = append(s.artifacts, artifactRec{
		id: id, deviceID: deviceID, commandID: commandID, path: path, sha256: sha256,
		content: cp, collectedAt: time.Now(),
	})
	return id, nil
}

// ListArtifacts, bir cihazın artefakt meta verisini (içerik hariç) en yeniden
// eskiye döner.
func (s *Store) ListArtifacts(_ context.Context, deviceID string) ([]adminread.ArtifactRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.ArtifactRow
	for i := len(s.artifacts) - 1; i >= 0; i-- {
		a := s.artifacts[i]
		if a.deviceID != deviceID {
			continue
		}
		out = append(out, adminread.ArtifactRow{
			ID: a.id, DeviceID: a.deviceID, Path: a.path, SHA256: a.sha256,
			Size: len(a.content), CollectedAt: a.collectedAt,
		})
	}
	return out, nil
}

// GetArtifact, tek bir artefaktın içeriğini döner.
func (s *Store) GetArtifact(_ context.Context, id string) (adminread.ArtifactContent, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.artifacts {
		if a.id == id {
			cp := make([]byte, len(a.content))
			copy(cp, a.content)
			return adminread.ArtifactContent{Path: a.path, Content: cp}, true, nil
		}
	}
	return adminread.ArtifactContent{}, false, nil
}

// LatestSoftwareByDevice, her cihazın EN SON yazılım envanterini döner (olaylar
// yeniden-eskiye; cihaz başına ilk görülen envanter geçerli).
func (s *Store) LatestSoftwareByDevice(_ context.Context) (map[string][]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]string{}
	seen := map[string]bool{}
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if e.deviceID == "" || e.details == "" || seen[e.deviceID] {
			continue
		}
		var d struct {
			Software []string `json:"software"`
		}
		if err := json.Unmarshal([]byte(e.details), &d); err != nil || d.Software == nil {
			continue
		}
		seen[e.deviceID] = true
		out[e.deviceID] = d.Software
	}
	return out, nil
}

func (s *Store) ListAudit(_ context.Context, limit int) ([]adminread.AuditRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.AuditRow
	// En yeniden eskiye.
	for i := len(s.audit) - 1; i >= 0; i-- {
		a := s.audit[i]
		out = append(out, adminread.AuditRow{
			ID: a.id, AdminEmail: a.adminEmail, Action: a.action,
			TargetType: a.targetType, TargetID: a.targetID, CreatedAt: a.createdAt,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) DeviceByID(_ context.Context, id string) (adminread.DeviceRow, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return adminread.DeviceRow{}, false, nil
	}
	return adminread.DeviceRow{
		ID: d.id, Status: d.status, AgentVersion: d.agentVersion, OSPlatform: d.osPlatform,
		LastSeen: d.lastSeen, HostnameEnc: d.hostnameEnc, MACEnc: d.macEnc, OSVersion: d.osVersion, Tags: append([]string(nil), d.tags...),
	}, true, nil
}

// SetDeviceTags, cihazın etiketlerini değiştirir (bilinmeyen cihazda no-op).
func (s *Store) SetDeviceTags(_ context.Context, deviceID string, tags []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[deviceID]; ok {
		d.tags = append([]string(nil), tags...)
	}
	return nil
}

func (s *Store) CertsByDevice(_ context.Context, id string) ([]adminread.CertRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.CertRow
	for _, c := range s.certs {
		if c.deviceID != id {
			continue
		}
		out = append(out, adminread.CertRow{
			Serial:      c.serial,
			Fingerprint: hex.EncodeToString(c.fingerprint),
			NotBefore:   c.notBefore,
			NotAfter:    c.notAfter,
			Revoked:     c.revoked,
		})
	}
	return out, nil
}

func (s *Store) CommandHistory(_ context.Context, id string) ([]adminread.CmdRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adminread.CmdRow
	// En yeniden eskiye.
	for i := len(s.cmdHistory) - 1; i >= 0; i-- {
		c := s.cmdHistory[i]
		if c.deviceID != id {
			continue
		}
		out = append(out, adminread.CmdRow{
			Type: c.cmdType, IssuedBy: c.issuedBy, CreatedAt: c.createdAt, DeliveredAt: c.deliveredAt,
		})
	}
	return out, nil
}

func (s *Store) AssignedPolicy(_ context.Context, id string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return "", "", nil
	}
	return d.policyID, d.policyVersion, nil
}

// ListEnrollmentTokens, token meta verisini en yeniden eskiye döner. Ham token
// asla saklanmaz; createdBy admin id'si adminsByID'den e-postaya çözülür (db
// LEFT JOIN davranışını taklit eder — eşleşmezse boş kalır).
func (s *Store) ListEnrollmentTokens(_ context.Context, limit int) ([]adminread.EnrollmentTokenRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]adminread.EnrollmentTokenRow, 0, len(s.tokens))
	for _, t := range s.tokens {
		var email string
		if a, ok := s.adminsByID[t.createdBy]; ok {
			email = a.email
		}
		out = append(out, adminread.EnrollmentTokenRow{
			ID: t.id, CreatedByEmail: email, ExpiresAt: t.expiresAt,
			Used: t.used, CreatedAt: t.createdAt,
		})
	}
	// En yeniden eskiye (created_at DESC).
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// --- revocation.Source ---

func (s *Store) RevokedFingerprints(_ context.Context) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for _, c := range s.certs {
		if c.revoked {
			out = append(out, c.fingerprint)
		}
	}
	return out, nil
}

// --- retention.Store (bellek-içi: no-op) ---

func (s *Store) ListPartitions(context.Context) ([]time.Time, error) { return nil, nil }
func (s *Store) CreatePartition(context.Context, time.Time) error    { return nil }
func (s *Store) DropPartition(context.Context, time.Time) error      { return nil }

// PurgeArtifactsOlderThan, cutoff'tan eski artefaktları düşürür ve sayısını döner.
func (s *Store) PurgeArtifactsOlderThan(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.artifacts[:0]
	removed := 0
	for _, a := range s.artifacts {
		if a.collectedAt.Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, a)
	}
	s.artifacts = kept
	return removed, nil
}

// --- adminapi.AuthStore ---

func (s *Store) LookupAdmin(_ context.Context, email string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// db implementasyonuyla aynı: yalnız aktif yöneticiler giriş yapabilir
	// (pasifleştirilmiş hesap "bulunamadı" gibi ele alınır — hesap sızdırmaz).
	if a, ok := s.admins[email]; ok && a.active {
		return a.id, a.passwordHash, nil
	}
	return "", "", nil
}

func ruleTypeToProto(t string) xemsv1.PolicyRule_RuleType {
	switch t {
	case "APP_TIME_BLOCK":
		return xemsv1.PolicyRule_RULE_TYPE_APP_TIME_BLOCK
	case "APP_BLOCK_ALWAYS":
		return xemsv1.PolicyRule_RULE_TYPE_APP_BLOCK_ALWAYS
	case "NETWORK_RULE":
		return xemsv1.PolicyRule_RULE_TYPE_NETWORK_RULE
	default:
		return xemsv1.PolicyRule_RULE_TYPE_UNSPECIFIED
	}
}

func commandTypeToProto(t string) xemsv1.Command_CommandType {
	switch t {
	case "QUARANTINE":
		return xemsv1.Command_COMMAND_TYPE_QUARANTINE
	case "UNQUARANTINE":
		return xemsv1.Command_COMMAND_TYPE_UNQUARANTINE
	case "RUN_SIGNED_SCRIPT":
		return xemsv1.Command_COMMAND_TYPE_RUN_SIGNED_SCRIPT
	case "UNINSTALL":
		return xemsv1.Command_COMMAND_TYPE_UNINSTALL
	case "COLLECT_DIAGNOSTICS":
		return xemsv1.Command_COMMAND_TYPE_COLLECT_DIAGNOSTICS
	case "COLLECT_FILE":
		return xemsv1.Command_COMMAND_TYPE_COLLECT_FILE
	case "LOCK":
		return xemsv1.Command_COMMAND_TYPE_LOCK
	case "RESTART":
		return xemsv1.Command_COMMAND_TYPE_RESTART
	case "WIPE":
		return xemsv1.Command_COMMAND_TYPE_WIPE
	default:
		return xemsv1.Command_COMMAND_TYPE_UNSPECIFIED
	}
}

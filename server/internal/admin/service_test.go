package admin

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"xems.corp/suite/server/internal/security"
)

// memStore, admin testleri için bellek-içi Store.
type memStore struct {
	roles      map[string]Role
	tokens     map[string]string // tokenIndex(hex) -> createdBy
	revoked    map[string]bool   // tokenID -> iptal edildi mi
	commands   []cmd
	audits     []audit
	policies   map[string]string            // id -> name
	versions   map[string]string            // id -> version
	rules      map[string][]RuleInput       // id -> kurallar
	assigned   map[string]string            // deviceID -> policyID
	statuses   map[string]string            // deviceID -> son ayarlanan durum
	tags       map[string][]string          // deviceID -> etiketler
	admins     map[string]*adminEntry       // id -> yönetici
	erased     string                       // EraseDeviceData ile silinen son deviceID
	eventAcks  map[string]string            // eventID -> status (triyaj)
	eventCases map[string][2]string         // eventID -> {assignee, note} (vaka)
	pendWipes  map[string]string            // deviceID -> requestedBy (çift-kontrol WIPE)
	cmdParams  map[string]map[string]string // cmdType -> son params
	nextPolID  int
	nextAdmID  int
}

func (m *memStore) SetEventAck(_ context.Context, eventID, _, status string) error {
	if m.eventAcks == nil {
		m.eventAcks = map[string]string{}
	}
	m.eventAcks[eventID] = status
	return nil
}

func (m *memStore) SetEventCase(_ context.Context, eventID, _, assignee, note string) error {
	if m.eventCases == nil {
		m.eventCases = map[string][2]string{}
	}
	m.eventCases[eventID] = [2]string{assignee, note}
	return nil
}

func (m *memStore) SavePendingWipe(_ context.Context, deviceID, requestedBy, _ string) error {
	if m.pendWipes == nil {
		m.pendWipes = map[string]string{}
	}
	m.pendWipes[deviceID] = requestedBy
	return nil
}
func (m *memStore) GetPendingWipe(_ context.Context, deviceID string) (string, bool, error) {
	rb, ok := m.pendWipes[deviceID]
	return rb, ok, nil
}
func (m *memStore) DeletePendingWipe(_ context.Context, deviceID string) error {
	delete(m.pendWipes, deviceID)
	return nil
}

func (m *memStore) EraseDeviceData(_ context.Context, deviceID string) (int, int, int, error) {
	m.erased = deviceID
	return 3, 1, 1, nil // temsili sayımlar: 3 olay, 1 komut, 1 sertifika
}

type cmd struct{ deviceID, cmdType, issuedBy string }
type audit struct{ adminID, action, targetType, targetID string }
type adminEntry struct {
	email, hash string
	role        Role
	active      bool
	mfaSecret   string
	mfaEnrolled bool
}

func newMemStore() *memStore {
	return &memStore{
		roles:    map[string]Role{},
		tokens:   map[string]string{},
		revoked:  map[string]bool{},
		policies: map[string]string{},
		versions: map[string]string{},
		rules:    map[string][]RuleInput{},
		assigned: map[string]string{},
		statuses: map[string]string{},
		admins:   map[string]*adminEntry{},
	}
}

// fakePublisher, Publish çağrılarını kaydeder (anlık push doğrulaması için).
type fakePublisher struct{ published []string }

func (p *fakePublisher) Publish(deviceID string) { p.published = append(p.published, deviceID) }

func (m *memStore) AdminRole(_ context.Context, adminID string) (Role, error) {
	return m.roles[adminID], nil
}
func (m *memStore) SaveEnrollmentToken(_ context.Context, idx []byte, createdBy string, _ time.Time) error {
	m.tokens[string(idx)] = createdBy
	return nil
}
func (m *memStore) RevokeEnrollmentToken(_ context.Context, tokenID string) error {
	m.revoked[tokenID] = true
	return nil
}
func (m *memStore) EnqueueCommand(_ context.Context, deviceID, cmdType, issuedBy string) error {
	m.commands = append(m.commands, cmd{deviceID, cmdType, issuedBy})
	return nil
}
func (m *memStore) EnqueueCommandParams(_ context.Context, deviceID, cmdType, issuedBy string, params map[string]string) error {
	m.commands = append(m.commands, cmd{deviceID, cmdType, issuedBy})
	if m.cmdParams == nil {
		m.cmdParams = map[string]map[string]string{}
	}
	m.cmdParams[cmdType] = params
	return nil
}
func (m *memStore) SetDeviceStatus(_ context.Context, deviceID, status string) error {
	m.statuses[deviceID] = status
	return nil
}
func (m *memStore) SetDeviceTags(_ context.Context, deviceID string, tags []string) error {
	if m.tags == nil {
		m.tags = map[string][]string{}
	}
	m.tags[deviceID] = tags
	return nil
}
func (m *memStore) RevokeDeviceCerts(_ context.Context, deviceID, _ string) error {
	m.commands = append(m.commands, cmd{deviceID, "REVOKE", ""})
	return nil
}
func (m *memStore) WriteAudit(_ context.Context, adminID, action, targetType, targetID string) error {
	m.audits = append(m.audits, audit{adminID, action, targetType, targetID})
	return nil
}
func (m *memStore) CreatePolicy(_ context.Context, name, version string) (string, error) {
	m.nextPolID++
	id := "pol-" + string(rune('0'+m.nextPolID))
	m.policies[id] = name
	m.versions[id] = version
	return id, nil
}
func (m *memStore) AssignPolicy(_ context.Context, deviceID, policyID string) error {
	m.assigned[deviceID] = policyID
	return nil
}
func (m *memStore) AddPolicyRule(_ context.Context, policyID string, in RuleInput) error {
	m.rules[policyID] = append(m.rules[policyID], in)
	return nil
}
func (m *memStore) BumpPolicyVersion(_ context.Context, policyID string) (string, error) {
	nv := m.versions[policyID] + "+1"
	m.versions[policyID] = nv
	return nv, nil
}
func (m *memStore) DevicesForPolicy(_ context.Context, policyID string) ([]string, error) {
	var out []string
	for dev, pol := range m.assigned {
		if pol == policyID {
			out = append(out, dev)
		}
	}
	return out, nil
}
func (m *memStore) ListPolicyRules(_ context.Context, policyID string) ([]RuleView, error) {
	var out []RuleView
	for i, r := range m.rules[policyID] {
		out = append(out, RuleView{
			ID: "r-" + string(rune('0'+i)), Type: r.Type, Target: r.Target,
			Start: r.Start, End: r.End, ActiveDays: r.ActiveDays,
		})
	}
	return out, nil
}

func (m *memStore) CreateAdmin(_ context.Context, email, passwordHash string, role Role) (string, error) {
	m.nextAdmID++
	id := "adm-" + string(rune('0'+m.nextAdmID))
	m.admins[id] = &adminEntry{email: email, hash: passwordHash, role: role, active: true}
	m.roles[id] = role
	return id, nil
}
func (m *memStore) SetAdminRole(_ context.Context, id string, role Role) error {
	if a, ok := m.admins[id]; ok {
		a.role = role
	}
	m.roles[id] = role
	return nil
}
func (m *memStore) SetPendingMFASecret(_ context.Context, id, secret string) error {
	if a, ok := m.admins[id]; ok {
		a.mfaSecret = secret
		a.mfaEnrolled = false
	}
	return nil
}
func (m *memStore) LookupMFA(_ context.Context, id string) (string, bool, error) {
	if a, ok := m.admins[id]; ok {
		return a.mfaSecret, a.mfaEnrolled, nil
	}
	return "", false, nil
}
func (m *memStore) ActivateMFA(_ context.Context, id string) error {
	if a, ok := m.admins[id]; ok && a.mfaSecret != "" {
		a.mfaEnrolled = true
	}
	return nil
}
func (m *memStore) DisableMFA(_ context.Context, id string) error {
	if a, ok := m.admins[id]; ok {
		a.mfaSecret = ""
		a.mfaEnrolled = false
	}
	return nil
}
func (m *memStore) DeactivateAdmin(_ context.Context, id string) error {
	if a, ok := m.admins[id]; ok {
		a.active = false
	}
	return nil
}
func (m *memStore) ListAdmins(_ context.Context) ([]AdminInfo, error) {
	var out []AdminInfo
	for id, a := range m.admins {
		out = append(out, AdminInfo{ID: id, Email: a.email, Role: a.role, Active: a.active})
	}
	return out, nil
}

func newService(t *testing.T, store Store) (*Service, *security.BlindIndexer) {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(master, security.LabelBlindIndex))
	return NewService(store, bidx, time.Hour), bidx
}

// AckEvent (alarm yaşam-döngüsü): VIEWER reddedilir; geçersiz durum reddedilir;
// OPERATOR işaretler + denetim izine yazılır.
// MDM uzak eylemler: LOCK/RESTART OPERATOR+; WIPE yalnız ADMIN + denetim izi.
func TestMDMActionsRBAC(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	store.roles["adm1"] = RoleAdmin
	svc, _ := newService(t, store)
	ctx := context.Background()

	// LOCK: VIEWER reddedilir, OPERATOR geçer.
	if err := svc.LockDevice(ctx, "viewer1", "dev-1"); err != ErrForbidden {
		t.Fatalf("VIEWER kilitleyememeli: %v", err)
	}
	if err := svc.LockDevice(ctx, "op1", "dev-1"); err != nil {
		t.Fatalf("OPERATOR kilitleyebilmeli: %v", err)
	}
	// RESTART: OPERATOR geçer.
	if err := svc.RestartDevice(ctx, "op1", "dev-1"); err != nil {
		t.Fatalf("OPERATOR yeniden başlatabilmeli: %v", err)
	}
	// WIPE: OPERATOR reddedilir (ADMIN gerekir), ADMIN geçer + audit.
	if err := svc.WipeDevice(ctx, "op1", "dev-1"); err != ErrForbidden {
		t.Fatalf("OPERATOR silememeli (ADMIN gerekir): %v", err)
	}
	if err := svc.WipeDevice(ctx, "adm1", "dev-1"); err != nil {
		t.Fatalf("ADMIN silebilmeli: %v", err)
	}
	if !hasAudit(store.audits, "WIPE", "device", "dev-1") {
		t.Fatalf("WIPE denetim izine yazılmalıydı: %+v", store.audits)
	}
}

// CollectFile (adli dosya toplama): VIEWER reddedilir; boş yol reddedilir;
// OPERATOR COLLECT_FILE komutunu params.path ile kuyruğa alır + audit.
func TestCollectFileRBACAndParams(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)
	ctx := context.Background()

	if err := svc.CollectFile(ctx, "viewer1", "dev-1", "C:/x/log.txt"); err != ErrForbidden {
		t.Fatalf("VIEWER toplayamamalı, dönen: %v", err)
	}
	if err := svc.CollectFile(ctx, "op1", "dev-1", "  "); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("boş yol reddedilmeliydi, dönen: %v", err)
	}
	if err := svc.CollectFile(ctx, "op1", "dev-1", "C:/x/log.txt"); err != nil {
		t.Fatalf("OPERATOR toplayabilmeli: %v", err)
	}
	if len(store.commands) != 1 || store.commands[0].cmdType != "COLLECT_FILE" {
		t.Fatalf("COLLECT_FILE komutu kuyruğa eklenmeliydi: %+v", store.commands)
	}
	if store.cmdParams["COLLECT_FILE"]["path"] != "C:/x/log.txt" {
		t.Fatalf("params.path iletilmeliydi: %+v", store.cmdParams)
	}
	if !hasAudit(store.audits, "COLLECT_FILE", "device", "dev-1") {
		t.Fatalf("denetim izine yazılmalıydı: %+v", store.audits)
	}
}

// Çift-kontrol WIPE (dört-göz): OPERATOR talep edemez; talep aşamasında komut
// kuyruğa GİRMEZ; talep eden kendi talebini onaylayamaz; FARKLI bir ADMIN onaylayınca
// WIPE kuyruğa girer ve bekleyen talep temizlenir; audit WIPE_REQUEST+WIPE_APPROVE.
func TestWipeDualControlFourEyes(t *testing.T) {
	store := newMemStore()
	store.roles["adminA"] = RoleAdmin
	store.roles["adminB"] = RoleAdmin
	store.roles["op"] = RoleOperator
	svc, _ := newService(t, store)
	ctx := context.Background()

	if err := svc.RequestWipe(ctx, "op", "dev-1", "kayıp cihaz"); err != ErrForbidden {
		t.Fatalf("OPERATOR RequestWipe reddedilmeli: %v", err)
	}
	if err := svc.ApproveWipe(ctx, "adminB", "dev-1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bekleyen yokken onay reddedilmeli: %v", err)
	}
	if err := svc.RequestWipe(ctx, "adminA", "dev-1", "kayıp cihaz"); err != nil {
		t.Fatal(err)
	}
	for _, c := range store.commands {
		if c.cmdType == "WIPE" {
			t.Fatal("talep aşamasında WIPE kuyruğa GİRMEMELİ")
		}
	}
	if err := svc.ApproveWipe(ctx, "adminA", "dev-1"); err != ErrForbidden {
		t.Fatalf("kendi talebini onaylama reddedilmeli (dört-göz): %v", err)
	}
	if err := svc.ApproveWipe(ctx, "adminB", "dev-1"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range store.commands {
		if c.cmdType == "WIPE" && c.deviceID == "dev-1" && c.issuedBy == "adminB" {
			found = true
		}
	}
	if !found {
		t.Fatalf("onay sonrası WIPE kuyruğa girmeli: %+v", store.commands)
	}
	if err := svc.ApproveWipe(ctx, "adminB", "dev-1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("onay sonrası bekleyen temizlenmeli: %v", err)
	}
	if !hasAudit(store.audits, "WIPE_REQUEST", "device", "dev-1") || !hasAudit(store.audits, "WIPE_APPROVE", "device", "dev-1") {
		t.Fatalf("denetim izi eksik: %+v", store.audits)
	}
}

func TestUpdateEventCaseRBACAndAudit(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)
	ctx := context.Background()

	// VIEWER reddedilmeli.
	if err := svc.UpdateEventCase(ctx, "viewer1", "evt-1", "soc@corp", "inceleniyor"); err != ErrForbidden {
		t.Fatalf("VIEWER vaka atayamamalı, dönen: %v", err)
	}
	// Boş olay kimliği reddedilmeli.
	if err := svc.UpdateEventCase(ctx, "op1", "", "soc@corp", "x"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("boş kimlik reddedilmeliydi, dönen: %v", err)
	}
	// Aşırı uzun not reddedilmeli.
	if err := svc.UpdateEventCase(ctx, "op1", "evt-1", "soc@corp", strings.Repeat("x", 2001)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("uzun not reddedilmeliydi, dönen: %v", err)
	}
	// OPERATOR: vaka ata + audit. Girdi kırpılmalı.
	if err := svc.UpdateEventCase(ctx, "op1", "evt-1", "  soc@corp  ", "  fidye şüphesi  "); err != nil {
		t.Fatalf("OPERATOR vaka atayabilmeli: %v", err)
	}
	if got := store.eventCases["evt-1"]; got[0] != "soc@corp" || got[1] != "fidye şüphesi" {
		t.Fatalf("vaka alanları kırpılıp kaydedilmeliydi: %+v", got)
	}
	if !hasAudit(store.audits, "EVENT_CASE", "event", "evt-1") {
		t.Fatalf("denetim izine yazılmalıydı: %+v", store.audits)
	}
}

func TestAckEventRBACAndAudit(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)
	ctx := context.Background()

	// VIEWER reddedilmeli.
	if err := svc.AckEvent(ctx, "viewer1", "evt-1", "ACKNOWLEDGED"); err != ErrForbidden {
		t.Fatalf("VIEWER işaretleyememeli, dönen: %v", err)
	}
	// Geçersiz durum reddedilmeli (ErrInvalidInput).
	if err := svc.AckEvent(ctx, "op1", "evt-1", "BOGUS"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("geçersiz durum reddedilmeliydi, dönen: %v", err)
	}
	// Boş olay kimliği reddedilmeli.
	if err := svc.AckEvent(ctx, "op1", "", "RESOLVED"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("boş kimlik reddedilmeliydi, dönen: %v", err)
	}
	// OPERATOR: işaretle + audit.
	if err := svc.AckEvent(ctx, "op1", "evt-1", "ACKNOWLEDGED"); err != nil {
		t.Fatalf("OPERATOR işaretleyebilmeli: %v", err)
	}
	if store.eventAcks["evt-1"] != "ACKNOWLEDGED" {
		t.Fatalf("triyaj durumu kaydedilmeliydi: %v", store.eventAcks)
	}
	if !hasAudit(store.audits, "EVENT_ACKNOWLEDGED", "event", "evt-1") {
		t.Fatalf("denetim izine yazılmalıydı: %+v", store.audits)
	}
	// RESOLVED'e geçiş.
	if err := svc.AckEvent(ctx, "op1", "evt-1", "RESOLVED"); err != nil {
		t.Fatal(err)
	}
	if store.eventAcks["evt-1"] != "RESOLVED" {
		t.Fatalf("RESOLVED olmalıydı: %v", store.eventAcks)
	}
}

func TestSetDeviceTagsRBACAndNormalize(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)

	// VIEWER reddedilmeli.
	if err := svc.SetDeviceTags(context.Background(), "viewer1", "dev-1", []string{"prod"}); err != ErrForbidden {
		t.Fatalf("VIEWER etiket ayarlayamamalı, dönen: %v", err)
	}
	// OPERATOR: normalize (kırp, boş at, tekilleştir) + audit.
	if err := svc.SetDeviceTags(context.Background(), "op1", "dev-1",
		[]string{"  prod ", "prod", "", "finans"}); err != nil {
		t.Fatal(err)
	}
	got := store.tags["dev-1"]
	if len(got) != 2 || got[0] != "prod" || got[1] != "finans" {
		t.Fatalf("etiketler normalize edilmeliydi: %v", got)
	}
	if !hasAudit(store.audits, "SET_TAGS", "device", "dev-1") {
		t.Fatal("SET_TAGS denetim izine yazılmalıydı")
	}
}

func TestNormalizeTagsLimits(t *testing.T) {
	// Sayı sınırı.
	many := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		many = append(many, "t"+string(rune('a'+i%26))+string(rune('0'+i)))
	}
	if n := len(normalizeTags(many)); n != maxTags {
		t.Fatalf("etiket sayısı %d ile sınırlanmalıydı, %d döndü", maxTags, n)
	}
	// Uzunluk sınırı.
	long := strings.Repeat("x", maxTagLen+50)
	if got := normalizeTags([]string{long}); len(got[0]) != maxTagLen {
		t.Fatalf("etiket uzunluğu %d ile sınırlanmalıydı, %d", maxTagLen, len(got[0]))
	}
}

func TestRBACQuarantineRequiresOperator(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)

	// VIEWER reddedilmeli.
	if err := svc.QuarantineDevice(context.Background(), "viewer1", "dev-1"); err != ErrForbidden {
		t.Fatalf("VIEWER karantina yapamamalı, dönen: %v", err)
	}
	if len(store.commands) != 0 {
		t.Fatal("reddedilen işlem komut üretmemeli")
	}

	// OPERATOR başarılı olmalı ve komut + audit üretmeli.
	if err := svc.QuarantineDevice(context.Background(), "op1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 || store.commands[0].cmdType != "QUARANTINE" || store.commands[0].deviceID != "dev-1" {
		t.Fatalf("QUARANTINE komutu kuyruğa eklenmeliydi: %+v", store.commands)
	}
	if len(store.audits) != 1 || store.audits[0].action != "QUARANTINE" {
		t.Fatalf("denetim izi yazılmalıydı: %+v", store.audits)
	}
}

func TestEraseDeviceAndExportRequireAdminAndAudit(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)

	// SİLME: OPERATOR yetkisiz (ADMIN gerekir).
	if _, err := svc.EraseDevice(context.Background(), "op1", "dev-1"); err != ErrForbidden {
		t.Fatalf("OPERATOR silme için ErrForbidden beklenirdi: %v", err)
	}
	// ADMIN silme uygulayabilmeli + rapor + denetim.
	rep, err := svc.EraseDevice(context.Background(), "admin1", "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.EventsDeleted != 3 || rep.CommandsDeleted != 1 || rep.CertsRevoked != 1 {
		t.Fatalf("silme raporu sayımları hatalı: %+v", rep)
	}
	if store.erased != "dev-1" {
		t.Fatalf("EraseDeviceData çağrılmalıydı, erased=%q", store.erased)
	}
	if !hasAudit(store.audits, "DATA_ERASURE", "device", "dev-1") {
		t.Fatalf("DATA_ERASURE denetim izine yazılmalıydı: %+v", store.audits)
	}

	// ERİŞİM (dışa aktarma yetkisi): OPERATOR yetkisiz, ADMIN + denetim.
	if err := svc.AuthorizeExport(context.Background(), "op1", "dev-1"); err != ErrForbidden {
		t.Fatalf("OPERATOR export için ErrForbidden beklenirdi: %v", err)
	}
	if err := svc.AuthorizeExport(context.Background(), "admin1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if !hasAudit(store.audits, "DATA_EXPORT", "device", "dev-1") {
		t.Fatalf("DATA_EXPORT denetim izine yazılmalıydı: %+v", store.audits)
	}
}

func hasAudit(audits []audit, action, targetType, targetID string) bool {
	for _, a := range audits {
		if a.action == action && a.targetType == targetType && a.targetID == targetID {
			return true
		}
	}
	return false
}

func TestCollectDiagnosticsQueuesCommandWithoutStatusChange(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["viewer1"] = RoleViewer
	svc, _ := newService(t, store)

	// VIEWER komut kuyruğa alamamalı (403).
	if err := svc.CollectDiagnostics(context.Background(), "viewer1", "dev-1"); err != ErrForbidden {
		t.Fatalf("VIEWER için ErrForbidden beklenirdi, dönen: %v", err)
	}

	// OPERATOR tanılama komutu kuyruğa alabilmeli.
	if err := svc.CollectDiagnostics(context.Background(), "op1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 || store.commands[0].cmdType != "COLLECT_DIAGNOSTICS" || store.commands[0].deviceID != "dev-1" {
		t.Fatalf("COLLECT_DIAGNOSTICS komutu kuyruğa eklenmeliydi: %+v", store.commands)
	}
	if len(store.audits) != 1 || store.audits[0].action != "COLLECT_DIAGNOSTICS" {
		t.Fatalf("denetim izi yazılmalıydı: %+v", store.audits)
	}
	// Tanılama durum DEĞİŞTİRMEZ (zararsız salt-toplama).
	if _, ok := store.statuses["dev-1"]; ok {
		t.Fatalf("tanılama cihaz durumunu değiştirmemeliydi, dönen: %q", store.statuses["dev-1"])
	}
}

func TestQuarantineReleaseReflectsStatus(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)

	// Karantina: durum QUARANTINED olarak yansımalı.
	if err := svc.QuarantineDevice(context.Background(), "op1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if got := store.statuses["dev-1"]; got != "QUARANTINED" {
		t.Fatalf("karantina sonrası durum QUARANTINED olmalı, dönen: %q", got)
	}

	// Serbest bırakma: durum ACTIVE'e dönmeli.
	if err := svc.ReleaseDevice(context.Background(), "op1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if got := store.statuses["dev-1"]; got != "ACTIVE" {
		t.Fatalf("serbest bırakma sonrası durum ACTIVE olmalı, dönen: %q", got)
	}
}

func TestCreatePolicyRequiresAdmin(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)

	if _, err := svc.CreatePolicy(context.Background(), "op1", "P", "v1"); err != ErrForbidden {
		t.Fatalf("OPERATOR politika oluşturamamalı, dönen: %v", err)
	}
	id, err := svc.CreatePolicy(context.Background(), "admin1", "Mesai Politikası", "v1")
	if err != nil || id == "" {
		t.Fatalf("ADMIN politika oluşturabilmeli: %v", err)
	}
}

func TestAddPolicyRuleRBACAndPush(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)
	pub := &fakePublisher{}
	svc.SetPublisher(pub)

	// Bir politika oluştur ve iki cihaza ata.
	id, err := store.CreatePolicy(context.Background(), "Mesai", "v1")
	if err != nil {
		t.Fatal(err)
	}
	store.assigned["dev-1"] = id
	store.assigned["dev-2"] = id
	store.assigned["dev-other"] = "başka-politika"

	// OPERATOR kural ekleyememeli (403).
	if err := svc.AddPolicyRule(context.Background(), "op1", id,
		RuleInput{Type: "APP_BLOCK_ALWAYS", Target: "oyun.exe"}); err != ErrForbidden {
		t.Fatalf("OPERATOR kural ekleyememeli, dönen: %v", err)
	}
	if len(store.rules[id]) != 0 {
		t.Fatal("reddedilen işlem kural eklememeli")
	}

	// APP_TIME_BLOCK'ta Start/End yoksa geçersiz kural hatası.
	if err := svc.AddPolicyRule(context.Background(), "admin1", id,
		RuleInput{Type: "APP_TIME_BLOCK", Target: "oyun.exe"}); err != ErrInvalidRule {
		t.Fatalf("zaman aralığı olmadan APP_TIME_BLOCK reddedilmeli, dönen: %v", err)
	}

	// Geçersiz tip reddedilmeli.
	if err := svc.AddPolicyRule(context.Background(), "admin1", id,
		RuleInput{Type: "BOGUS", Target: "x"}); err != ErrInvalidRule {
		t.Fatalf("geçersiz tip reddedilmeli, dönen: %v", err)
	}

	// ADMIN geçerli kural ekleyebilmeli.
	verBefore := store.versions[id]
	if err := svc.AddPolicyRule(context.Background(), "admin1", id,
		RuleInput{Type: "APP_TIME_BLOCK", Target: "oyun.exe", Start: "09:00", End: "18:00", ActiveDays: []int32{1, 2, 3, 4, 5}}); err != nil {
		t.Fatalf("ADMIN kural ekleyebilmeli: %v", err)
	}
	if len(store.rules[id]) != 1 {
		t.Fatalf("kural eklenmiş olmalı: %+v", store.rules[id])
	}
	// Sürüm yükseltilmeli.
	if store.versions[id] == verBefore {
		t.Fatalf("politika sürümü yükseltilmeliydi (önce=%q, sonra=%q)", verBefore, store.versions[id])
	}
	// Yalnız bu politikaya atanmış cihazlar push almalı (dev-1, dev-2; dev-other DEĞİL).
	if len(pub.published) != 2 {
		t.Fatalf("atanmış 2 cihaz push almalıydı: %v", pub.published)
	}
	for _, d := range pub.published {
		if d != "dev-1" && d != "dev-2" {
			t.Fatalf("beklenmeyen cihaz push aldı: %q", d)
		}
	}
	// Audit yazılmalı.
	var found bool
	for _, a := range store.audits {
		if a.action == "ADD_POLICY_RULE" && a.targetType == "policy" && a.targetID == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("ADD_POLICY_RULE denetim izi yazılmalıydı: %+v", store.audits)
	}
}

func TestIssueEnrollmentTokenStoresHMACIndex(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	svc, bidx := newService(t, store)

	token, err := svc.IssueEnrollmentToken(context.Background(), "op1")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("ham token dönmeliydi")
	}
	// DB'de saklanan indeks, ham token'ın HMAC'i olmalı (ham token DEĞİL).
	wantIdx := string(bidx.Compute("enroll-token:" + token))
	if _, ok := store.tokens[wantIdx]; !ok {
		t.Fatal("token HMAC indeksi saklanmadı (ham token asla saklanmamalı)")
	}
	if len(store.audits) != 1 || store.audits[0].action != "ISSUE_ENROLLMENT_TOKEN" {
		t.Fatal("token üretimi denetim izine yazılmalıydı")
	}
}

func TestRevokeEnrollmentTokenRBAC(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)

	// VIEWER reddedilmeli; store'a dokunulmamalı.
	if err := svc.RevokeEnrollmentToken(context.Background(), "viewer1", "tok-1"); err != ErrForbidden {
		t.Fatalf("VIEWER token iptal edememeli, dönen: %v", err)
	}
	if store.revoked["tok-1"] {
		t.Fatal("reddedilen işlem token iptal etmemeli")
	}

	// OPERATOR iptal edebilmeli ve audit yazmalı.
	if err := svc.RevokeEnrollmentToken(context.Background(), "op1", "tok-1"); err != nil {
		t.Fatal(err)
	}
	if !store.revoked["tok-1"] {
		t.Fatal("OPERATOR token'ı iptal etmeliydi")
	}
	var found bool
	for _, a := range store.audits {
		if a.action == "REVOKE_ENROLLMENT_TOKEN" && a.targetType == "token" && a.targetID == "tok-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("token iptali denetim izine yazılmalıydı")
	}
}

func TestCreateAdminRBACHashingAndAudit(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)

	// OPERATOR yeni yönetici oluşturamamalı (403).
	if _, err := svc.CreateAdmin(context.Background(), "op1", "yeni@x", "parola12", RoleViewer); err != ErrForbidden {
		t.Fatalf("OPERATOR admin oluşturamamalı, dönen: %v", err)
	}
	if len(store.admins) != 0 {
		t.Fatal("reddedilen işlem yönetici oluşturmamalı")
	}

	// Kısa parola reddedilmeli (400/ErrInvalidInput).
	if _, err := svc.CreateAdmin(context.Background(), "admin1", "yeni@x", "kisa", RoleViewer); err != ErrInvalidInput {
		t.Fatalf("kısa parola reddedilmeli, dönen: %v", err)
	}
	// Boş e-posta reddedilmeli.
	if _, err := svc.CreateAdmin(context.Background(), "admin1", "", "parola12", RoleViewer); err != ErrInvalidInput {
		t.Fatalf("boş e-posta reddedilmeli, dönen: %v", err)
	}
	// Geçersiz rol reddedilmeli.
	if _, err := svc.CreateAdmin(context.Background(), "admin1", "yeni@x", "parola12", Role("BOGUS")); err != ErrInvalidInput {
		t.Fatalf("geçersiz rol reddedilmeli, dönen: %v", err)
	}

	// ADMIN başarılı olmalı.
	const plain = "parola12"
	id, err := svc.CreateAdmin(context.Background(), "admin1", "yeni@x", plain, RoleOperator)
	if err != nil || id == "" {
		t.Fatalf("ADMIN yönetici oluşturabilmeli: %v", err)
	}
	rec, ok := store.admins[id]
	if !ok {
		t.Fatal("yeni yönetici depoda olmalı")
	}
	// Parola düz metin DEĞİL, Argon2id hash olarak saklanmalı.
	if rec.hash == plain || rec.hash == "" {
		t.Fatalf("parola düz metin saklanmamalı: %q", rec.hash)
	}
	valid, err := security.VerifyPassword(rec.hash, plain)
	if err != nil || !valid {
		t.Fatalf("saklanan hash parolayı doğrulamalı: valid=%v err=%v", valid, err)
	}
	// Audit yazılmalı.
	var found bool
	for _, a := range store.audits {
		if a.action == "CREATE_ADMIN" && a.targetType == "admin" && a.targetID == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("REVOKE_ENROLLMENT_TOKEN denetim izi yazılmalıydı: %+v", store.audits)
		t.Fatalf("CREATE_ADMIN denetim izi yazılmalıydı: %+v", store.audits)
	}
}

func TestListAdminsNoHashAndRBAC(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)

	id, err := svc.CreateAdmin(context.Background(), "admin1", "u@x", "parola12", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}

	// VIEWER listeleyememeli (OPERATOR+ gerekir).
	if _, err := svc.ListAdmins(context.Background(), "viewer1"); err != ErrForbidden {
		t.Fatalf("VIEWER listeleyememeli, dönen: %v", err)
	}

	// OPERATOR listeleyebilmeli; AdminView'de parola hash'i alanı YOKTUR.
	views, err := svc.ListAdmins(context.Background(), "op1")
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, v := range views {
		if v.ID == id && v.Email == "u@x" && v.Role == RoleViewer && v.Active {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("oluşturulan yönetici listede görünmeliydi: %+v", views)
	}

	// Rol değiştir ve doğrula.
	if err := svc.SetAdminRole(context.Background(), "admin1", id, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	// Pasifleştir ve doğrula.
	if err := svc.DeactivateAdmin(context.Background(), "admin1", id); err != nil {
		t.Fatal(err)
	}
	views, _ = svc.ListAdmins(context.Background(), "op1")
	for _, v := range views {
		if v.ID == id {
			if v.Role != RoleAdmin {
				t.Fatalf("rol ADMIN olmalıydı: %v", v.Role)
			}
			if v.Active {
				t.Fatal("yönetici pasifleştirilmiş olmalıydı")
			}
		}
	}
}

// Bu token, enroll servisinin ConsumeEnrollmentToken'ıyla uyumlu indeks üretir:
// aynı "enroll-token:" ön eki ve aynı blind index anahtarı kullanılır.
func TestTokenIndexPrefixMatchesEnrollFlow(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	svc, bidx := newService(t, store)
	token, _ := svc.IssueEnrollmentToken(context.Background(), "op1")
	// enroll tarafı da tokenIndex = bidx.Compute("enroll-token:"+token) hesaplar.
	if _, ok := store.tokens[string(bidx.Compute("enroll-token:"+token))]; !ok {
		t.Fatal("admin ve enroll aynı indeks şemasını kullanmalı")
	}
}

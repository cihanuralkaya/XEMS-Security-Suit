// Package admin, yönetici işlemlerinin iş mantığıdır: RBAC ile korunmuş
// enrollment token üretimi, karantina komutu verme ve politika yönetimi.
// Her hassas işlem denetim izine (audit_log) yazılır (#10).
//
// Transport'tan (HTTP/gRPC) ve DB'den bağımsızdır: depolama Store arayüzünün
// arkasındadır ve gerçek bir veritabanı olmadan test edilebilir.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"xems.corp/suite/server/internal/security"
)

// Role, yönetici yetki seviyesidir.
type Role string

const (
	RoleViewer   Role = "VIEWER"
	RoleOperator Role = "OPERATOR"
	RoleAdmin    Role = "ADMIN"
)

func rank(r Role) int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// ErrForbidden, çağıran yöneticinin yetkisi yetersiz olduğunda döner.
var ErrForbidden = errors.New("admin: yetki yetersiz")

// ErrInvalidRule, kural girdisi doğrulamayı geçemediğinde döner (istemci hatası).
var ErrInvalidRule = errors.New("admin: geçersiz kural")

// RuleInput, bir politikaya eklenecek kuralın girdisidir.
type RuleInput struct {
	Type       string  // APP_TIME_BLOCK | APP_BLOCK_ALWAYS | NETWORK_RULE
	Target     string  // hedef (uygulama adı / ağ hedefi)
	Start      string  // "HH:MM" (APP_TIME_BLOCK için zorunlu; aksi halde boş)
	End        string  // "HH:MM"
	ActiveDays []int32 // 0=Pazar .. 6=Cumartesi (boşsa depoda varsayılan uygulanır)
}

// RuleView, bir politika kuralının okunabilir görünümüdür.
type RuleView struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Target     string  `json:"target"`
	Start      string  `json:"start"`
	End        string  `json:"end"`
	ActiveDays []int32 `json:"active_days"`
}

// Store, admin işlemlerinin ihtiyaç duyduğu kalıcılıktır.
type Store interface {
	AdminRole(ctx context.Context, adminID string) (Role, error)
	SaveEnrollmentToken(ctx context.Context, tokenIndex []byte, createdBy string, expiresAt time.Time) error
	// RevokeEnrollmentToken, kullanılmamış bir enrollment token'ı iptal eder
	// (used_at damgalar). Zaten kullanılmış/yok token için sessizdir (no-op).
	RevokeEnrollmentToken(ctx context.Context, tokenID string) error
	EnqueueCommand(ctx context.Context, deviceID, cmdType, issuedBy string) error
	// EnqueueCommandParams, parametreli komut kuyruğa ekler (ör. COLLECT_FILE
	// için params.path). params ajana google.protobuf.Struct olarak iletilir.
	EnqueueCommandParams(ctx context.Context, deviceID, cmdType, issuedBy string, params map[string]string) error
	// SetDeviceStatus, cihazın durum sütununu doğrudan ayarlar (komut kuyruğa
	// girdikten sonra durumun UI'da yansıması için).
	SetDeviceStatus(ctx context.Context, deviceID, status string) error
	// SetDeviceTags, cihazın etiketlerini (filo gruplama) değiştirir.
	SetDeviceTags(ctx context.Context, deviceID string, tags []string) error
	RevokeDeviceCerts(ctx context.Context, deviceID, reason string) error
	// EraseDeviceData, KVKK veri silme talebi için cihazın davranışsal/telemetri
	// verisini (olay logları, komut geçmişi) siler ve sertifikalarını iptal eder
	// (kalıcı erişim engeli). Denetim izi KORUNUR (işleme kaydı). Silinen olay/komut
	// ve iptal edilen sertifika sayısını döner.
	EraseDeviceData(ctx context.Context, deviceID string) (events, commands, certs int, err error)
	WriteAudit(ctx context.Context, adminID, action, targetType, targetID string) error
	// SetEventAck, bir olayın triyaj durumunu (ACKNOWLEDGED/RESOLVED) ayarlar
	// (olay başına upsert). Alarm yaşam-döngüsü.
	SetEventAck(ctx context.Context, eventID, adminID, status string) error
	// SetEventCase, bir olayın vaka alanlarını (sorumlu + not) ayarlar (upsert;
	// durum sütununa dokunmaz). Vaka yönetimi (#9).
	SetEventCase(ctx context.Context, eventID, adminID, assignee, note string) error
	CreatePolicy(ctx context.Context, name, version string) (policyID string, err error)
	AssignPolicy(ctx context.Context, deviceID, policyID string) error
	// AddPolicyRule, politikaya yeni bir kural ekler.
	AddPolicyRule(ctx context.Context, policyID string, in RuleInput) error
	// BumpPolicyVersion, politikanın sürümünü yükseltir ve yeni sürümü döner.
	BumpPolicyVersion(ctx context.Context, policyID string) (newVersion string, err error)
	// DevicesForPolicy, politikaya atanmış cihaz id'lerini döner (republish için).
	DevicesForPolicy(ctx context.Context, policyID string) ([]string, error)
	// ListPolicyRules, politikanın kurallarını döner.
	ListPolicyRules(ctx context.Context, policyID string) ([]RuleView, error)
	// CreateAdmin, yeni bir yönetici ekler ve id'sini döner. passwordHash zaten
	// Argon2id ile hash'lenmiştir (depo düz metin görmez).
	CreateAdmin(ctx context.Context, email, passwordHash string, role Role) (string, error)
	// SetAdminRole, bir yöneticinin rolünü değiştirir.
	SetAdminRole(ctx context.Context, id string, role Role) error
	// DeactivateAdmin, bir yöneticiyi pasifleştirir (is_active=false).
	DeactivateAdmin(ctx context.Context, id string) error
	// ListAdmins, tüm yöneticileri döner (parola hash'i olmadan).
	ListAdmins(ctx context.Context) ([]AdminInfo, error)
	// SetPendingMFASecret, yöneticinin TOTP sırrını (henüz etkin değil) saklar.
	// Depo sırrı at-rest şifreler (db katmanı); mfa_enrolled false kalır.
	SetPendingMFASecret(ctx context.Context, adminID, secret string) error
	// LookupMFA, yöneticinin TOTP sırrını ve etkin (enrolled) durumunu döner.
	// Sır yoksa ("", false, nil) döner.
	LookupMFA(ctx context.Context, adminID string) (secret string, enrolled bool, err error)
	// ActivateMFA, bekleyen TOTP sırrını etkinleştirir (mfa_enrolled=true).
	ActivateMFA(ctx context.Context, adminID string) error
	// DisableMFA, TOTP sırrını siler ve MFA'yı kapatır.
	DisableMFA(ctx context.Context, adminID string) error
	// SavePendingWipe, bir cihaz için ikinci-onay bekleyen WIPE talebini saklar
	// (çift-kontrol / dört-göz). deviceID başına upsert.
	SavePendingWipe(ctx context.Context, deviceID, requestedBy, reason string) error
	// GetPendingWipe, cihaz için bekleyen WIPE talebini (talep eden admin id'si)
	// döner. Yoksa ("", false, nil).
	GetPendingWipe(ctx context.Context, deviceID string) (requestedBy string, exists bool, err error)
	// DeletePendingWipe, bekleyen WIPE talebini siler (onay/iptal sonrası). Yoksa no-op.
	DeletePendingWipe(ctx context.Context, deviceID string) error
}

// validRuleType, kabul edilen kural tiplerini doğrular.
func validRuleType(t string) bool {
	switch t {
	case "APP_TIME_BLOCK", "APP_BLOCK_ALWAYS", "NETWORK_RULE":
		return true
	default:
		return false
	}
}

// Publisher, bir cihaza politika atandığında anlık push tetiklemek için
// kullanılır (opsiyonel; nil ise push tetiklenmez).
type Publisher interface {
	Publish(deviceID string)
}

// Service, admin işlemlerini yürütür.
type Service struct {
	store           Store
	bidx            *security.BlindIndexer
	tokenTTL        time.Duration
	now             func() time.Time
	genToken        func() (string, error)
	pub             Publisher
	wipeDualControl bool // açıksa WIPE iki farklı ADMIN onayı gerektirir (dört-göz)
}

// NewService oluşturur.
func NewService(store Store, bidx *security.BlindIndexer, tokenTTL time.Duration) *Service {
	return &Service{
		store:    store,
		bidx:     bidx,
		tokenTTL: tokenTTL,
		now:      time.Now,
		genToken: defaultGenToken,
	}
}

// SetPublisher, politika atamalarında anlık push için bir yayıncı bağlar.
func (s *Service) SetPublisher(p Publisher) { s.pub = p }

// require, adminID'nin en az min yetkiye sahip olduğunu doğrular.
func (s *Service) require(ctx context.Context, adminID string, min Role) error {
	role, err := s.store.AdminRole(ctx, adminID)
	if err != nil {
		return err
	}
	if rank(role) < rank(min) {
		return ErrForbidden
	}
	return nil
}

// IssueEnrollmentToken, tek kullanımlık bir kayıt token'ı üretir (OPERATOR+).
// Ham token YALNIZ burada döner (bir kez gösterilir); DB'de HMAC indeksi saklanır.
func (s *Service) IssueEnrollmentToken(ctx context.Context, adminID string) (string, error) {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return "", err
	}
	token, err := s.genToken()
	if err != nil {
		return "", err
	}
	idx := s.bidx.Compute("enroll-token:" + token)
	if err := s.store.SaveEnrollmentToken(ctx, idx, adminID, s.now().Add(s.tokenTTL)); err != nil {
		return "", err
	}
	_ = s.store.WriteAudit(ctx, adminID, "ISSUE_ENROLLMENT_TOKEN", "device", "")
	return token, nil
}

// QuarantineDevice, cihazı karantinaya alma komutu kuyruğa ekler (OPERATOR+) ve
// durum sütununu QUARANTINED olarak yansıtır.
// RevokeEnrollmentToken, henüz kullanılmamış bir enrollment token'ı iptal eder
// (OPERATOR+). İptal edilen token bir sonraki kayıt denemesinde reddedilir.
func (s *Service) RevokeEnrollmentToken(ctx context.Context, adminID, tokenID string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if err := s.store.RevokeEnrollmentToken(ctx, tokenID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "REVOKE_ENROLLMENT_TOKEN", "token", tokenID)
	return nil
}

// BeginMFAEnrollment, yönetici için yeni bir TOTP sırrı üretir, bekleyen olarak
// saklar ve authenticator uygulamasına eklenecek otpauth:// URI'sini döner. Yalnız
// oturum sahibinin kendi hesabı için çağrılır (adminID oturumdan gelir). Etkin
// olması için ActivateMFA ile doğrulama gerekir.
func (s *Service) BeginMFAEnrollment(ctx context.Context, adminID string) (secret, uri string, err error) {
	if err := s.require(ctx, adminID, RoleViewer); err != nil {
		return "", "", err
	}
	secret, err = security.GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	if err := s.store.SetPendingMFASecret(ctx, adminID, secret); err != nil {
		return "", "", err
	}
	uri = security.OTPAuthURI("XEMS Konsol", adminID, secret)
	return secret, uri, nil
}

// ActivateMFA, bekleyen TOTP sırrını yalnız geçerli bir kod ile etkinleştirir
// (kullanıcının authenticator'ı doğru kurduğunu kanıtlar). Doğrulama izi yazılır.
func (s *Service) ActivateMFA(ctx context.Context, adminID, code string) error {
	if err := s.require(ctx, adminID, RoleViewer); err != nil {
		return err
	}
	secret, _, err := s.store.LookupMFA(ctx, adminID)
	if err != nil {
		return err
	}
	if secret == "" {
		return fmt.Errorf("%w: MFA kaydı başlatılmadı", ErrForbidden)
	}
	if !security.VerifyTOTP(secret, code, s.now()) {
		return fmt.Errorf("%w: doğrulama kodu geçersiz", ErrForbidden)
	}
	if err := s.store.ActivateMFA(ctx, adminID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "MFA_ENABLED", "admin", adminID)
	return nil
}

// DisableMFA, MFA'yı yalnız geçerli bir kod doğrulamasından sonra kapatır (kaza/
// yetkisiz kapatmayı önler). Kayıt başlatılmış ama etkinleşmemiş sır da temizlenir.
func (s *Service) DisableMFA(ctx context.Context, adminID, code string) error {
	if err := s.require(ctx, adminID, RoleViewer); err != nil {
		return err
	}
	secret, enrolled, err := s.store.LookupMFA(ctx, adminID)
	if err != nil {
		return err
	}
	if enrolled && !security.VerifyTOTP(secret, code, s.now()) {
		return fmt.Errorf("%w: doğrulama kodu geçersiz", ErrForbidden)
	}
	if err := s.store.DisableMFA(ctx, adminID); err != nil {
		return err
	}
	if enrolled {
		_ = s.store.WriteAudit(ctx, adminID, "MFA_DISABLED", "admin", adminID)
	}
	return nil
}

// maxTags, cihaz başına etiket üst sınırı; maxTagLen tek etiket uzunluk sınırı.
const (
	maxTags   = 20
	maxTagLen = 40
)

// SetDeviceTags, cihazın etiketlerini ayarlar (OPERATOR+). Etiketler kırpılır,
// boşlar atılır, tekilleştirilir; sayısı/uzunluğu sınırlanır (kaynak/DoS koruması).
// Denetim izine yazılır.
func (s *Service) SetDeviceTags(ctx context.Context, adminID, deviceID string, tags []string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	clean := normalizeTags(tags)
	if err := s.store.SetDeviceTags(ctx, deviceID, clean); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "SET_TAGS", "device", deviceID)
	return nil
}

// normalizeTags, etiketleri kırpar, boşları atar, tekilleştirir (sıra korunur) ve
// sayı/uzunluk sınırlarını uygular.
func normalizeTags(tags []string) []string {
	seen := make(map[string]bool, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) > maxTagLen {
			t = t[:maxTagLen]
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= maxTags {
			break
		}
	}
	return out
}

// QuarantineDevice, cihazı karantinaya alma komutu kuyruğa ekler (OPERATOR+).
func (s *Service) QuarantineDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "QUARANTINE", "QUARANTINED")
}

// ReleaseDevice, karantinayı kaldırma komutu kuyruğa ekler (OPERATOR+) ve durum
// sütununu ACTIVE olarak geri yansıtır.
func (s *Service) ReleaseDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "UNQUARANTINE", "ACTIVE")
}

// CollectDiagnostics, cihazdan tanılama toplama komutu kuyruğa ekler (OPERATOR+).
// Durum değiştirmez — zararsız, salt-toplama bir işlemdir.
func (s *Service) CollectDiagnostics(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "COLLECT_DIAGNOSTICS", "")
}

// LockDevice, uzaktan ekran kilitleme komutu kuyruğa ekler (OPERATOR+, MDM).
func (s *Service) LockDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "LOCK", "")
}

// RestartDevice, uzaktan yeniden başlatma komutu kuyruğa ekler (OPERATOR+, MDM).
func (s *Service) RestartDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, "RESTART", "")
}

// WipeDevice, uzaktan veri silme komutu kuyruğa ekler — YIKICI olduğundan ADMIN
// gerektirir ve denetim izine yazılır. (Ajan bu sürümde gerçek silme yapmaz;
// komut/RBAC/denetim akışı tamdır — bkz. deviceaction.Wipe.)
func (s *Service) WipeDevice(ctx context.Context, adminID, deviceID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if err := s.store.EnqueueCommand(ctx, deviceID, "WIPE", adminID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "WIPE", "device", deviceID)
	return nil
}

// SetWipeDualControl, WIPE için çift-kontrolü (iki farklı ADMIN onayı) açar/kapatır.
func (s *Service) SetWipeDualControl(on bool) { s.wipeDualControl = on }

// WipeDualControl, çift-kontrolün açık olup olmadığını döner (görünürlük/yönlendirme).
func (s *Service) WipeDualControl() bool { return s.wipeDualControl }

// RequestWipe, çift-kontrol modunda bir WIPE talebini kaydeder (ADMIN). Komut HENÜZ
// kuyruğa GİRMEZ — farklı bir ADMIN ApproveWipe ile onaylamalıdır (dört-göz ilkesi;
// tek ele geçirilmiş/kötü-niyetli ADMIN filo silemez). Denetim izine yazılır.
func (s *Service) RequestWipe(ctx context.Context, adminID, deviceID, reason string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if strings.TrimSpace(deviceID) == "" {
		return fmt.Errorf("%w: cihaz kimliği zorunlu", ErrInvalidInput)
	}
	if len(reason) > 500 {
		return fmt.Errorf("%w: gerekçe çok uzun", ErrInvalidInput)
	}
	if err := s.store.SavePendingWipe(ctx, deviceID, adminID, strings.TrimSpace(reason)); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "WIPE_REQUEST", "device", deviceID)
	return nil
}

// ApproveWipe, bekleyen bir WIPE talebini onaylar ve komutu kuyruğa alır (ADMIN).
// Onaylayan, talep edenden FARKLI olmalıdır — kendi talebini onaylayamaz (dört-göz).
// Onaydan sonra bekleyen talep silinir. Denetim izine yazılır.
func (s *Service) ApproveWipe(ctx context.Context, approverID, deviceID string) error {
	if err := s.require(ctx, approverID, RoleAdmin); err != nil {
		return err
	}
	requestedBy, exists, err := s.store.GetPendingWipe(ctx, deviceID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: bekleyen WIPE talebi yok", ErrInvalidInput)
	}
	if requestedBy == approverID {
		return ErrForbidden // kendi talebini onaylayamaz (dört-göz)
	}
	if err := s.store.EnqueueCommand(ctx, deviceID, "WIPE", approverID); err != nil {
		return err
	}
	_ = s.store.DeletePendingWipe(ctx, deviceID)
	_ = s.store.WriteAudit(ctx, approverID, "WIPE_APPROVE", "device", deviceID)
	return nil
}

// CancelWipe, bekleyen bir WIPE talebini iptal eder (ADMIN). Denetim izine yazılır.
func (s *Service) CancelWipe(ctx context.Context, adminID, deviceID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if err := s.store.DeletePendingWipe(ctx, deviceID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "WIPE_CANCEL", "device", deviceID)
	return nil
}

// UpdateEventCase, bir olayın vaka alanlarını (sorumlu analist + not) günceller
// (OPERATOR+). Vaka yönetimi (#9). Denetim izine yazılır.
func (s *Service) UpdateEventCase(ctx context.Context, adminID, eventID, assignee, note string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if eventID == "" {
		return fmt.Errorf("%w: olay kimliği zorunlu", ErrInvalidInput)
	}
	if len(assignee) > 200 || len(note) > 2000 {
		return fmt.Errorf("%w: sorumlu/not çok uzun", ErrInvalidInput)
	}
	if err := s.store.SetEventCase(ctx, eventID, adminID, strings.TrimSpace(assignee), strings.TrimSpace(note)); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "EVENT_CASE", "event", eventID)
	return nil
}

// CollectFile, bir cihazdan adli/IR dosya toplama komutu kuyruğa ekler
// (OPERATOR+). Ajan dosyayı okuyup UploadArtifact ile yükler. Denetim izine yazılır.
func (s *Service) CollectFile(ctx context.Context, adminID, deviceID, path string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: dosya yolu zorunlu", ErrInvalidInput)
	}
	if err := s.store.EnqueueCommandParams(ctx, deviceID, "COLLECT_FILE", adminID, map[string]string{"path": path}); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "COLLECT_FILE", "device", deviceID)
	return nil
}

// AckEvent, bir olayı triyaj durumuna geçirir (ACKNOWLEDGED "inceleniyor" veya
// RESOLVED "kapatıldı") — alarm yaşam-döngüsü (OPERATOR+). Denetim izine yazılır.
func (s *Service) AckEvent(ctx context.Context, adminID, eventID, status string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if status != "ACKNOWLEDGED" && status != "RESOLVED" {
		return fmt.Errorf("%w: geçersiz durum %q", ErrInvalidInput, status)
	}
	if eventID == "" {
		return fmt.Errorf("%w: olay kimliği zorunlu", ErrInvalidInput)
	}
	if err := s.store.SetEventAck(ctx, eventID, adminID, status); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "EVENT_"+status, "event", eventID)
	return nil
}

// command, RBAC kontrolü sonrası komutu kuyruğa ekler, denetim izine yazar ve
// (reflectStatus boş değilse) cihazın durum sütununu günceller. Durum güncelleme
// hatası akışı BOZMAZ: komut zaten kuyruğa girmiştir; hata yutulur (best-effort
// yansıma), çünkü asıl doğruluk kaynağı komut kuyruğudur.
func (s *Service) command(ctx context.Context, adminID, deviceID, cmdType, reflectStatus string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if err := s.store.EnqueueCommand(ctx, deviceID, cmdType, adminID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, cmdType, "device", deviceID)
	if reflectStatus != "" {
		// Best-effort: komut kuyruğa girdiği için hata olsa da akışı bozma.
		_ = s.store.SetDeviceStatus(ctx, deviceID, reflectStatus)
	}
	return nil
}

// ErasureReport, bir KVKK veri silme işleminin sonucudur.
type ErasureReport struct {
	EventsDeleted   int `json:"events_deleted"`
	CommandsDeleted int `json:"commands_deleted"`
	CertsRevoked    int `json:"certs_revoked"`
}

// EraseDevice, KVKK veri sahibi SİLME talebini uygular (ADMIN). Cihazın
// davranışsal/telemetri verisini siler ve sertifikalarını iptal eder; işlemin
// kendisi denetim izine ("DATA_ERASURE") yazılır (silme kaydı korunur).
func (s *Service) EraseDevice(ctx context.Context, adminID, deviceID string) (ErasureReport, error) {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return ErasureReport{}, err
	}
	ev, cmd, cert, err := s.store.EraseDeviceData(ctx, deviceID)
	if err != nil {
		return ErasureReport{}, err
	}
	_ = s.store.WriteAudit(ctx, adminID, "DATA_ERASURE", "device", deviceID)
	return ErasureReport{EventsDeleted: ev, CommandsDeleted: cmd, CertsRevoked: cert}, nil
}

// EnsureRole, adminID'nin en az verilen role sahip olduğunu doğrular (yoksa
// ErrForbidden). Okuma uçlarında RBAC kapısı olarak kullanılır (SEC-009).
func (s *Service) EnsureRole(ctx context.Context, adminID string, min Role) error {
	return s.require(ctx, adminID, min)
}

// AuthorizeExport, KVKK veri sahibi ERİŞİM (dışa aktarma) talebini yetkilendirir
// (ADMIN) ve denetim izine ("DATA_EXPORT") yazar. Asıl veri toplama okuma
// servisinde yapılır; bu yalnız RBAC + denetim kapısıdır.
func (s *Service) AuthorizeExport(ctx context.Context, adminID, deviceID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "DATA_EXPORT", "device", deviceID)
	return nil
}

// RevokeDevice, cihazın sertifikalarını iptal eder (OPERATOR+). İptal edilen
// ajan bir sonraki mTLS el sıkışmasında reddedilir.
func (s *Service) RevokeDevice(ctx context.Context, adminID, deviceID string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if err := s.store.RevokeDeviceCerts(ctx, deviceID, "admin_revoke"); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "REVOKE_CERT", "device", deviceID)
	return nil
}

// CreatePolicy, yeni bir politika oluşturur (ADMIN).
func (s *Service) CreatePolicy(ctx context.Context, adminID, name, version string) (string, error) {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return "", err
	}
	id, err := s.store.CreatePolicy(ctx, name, version)
	if err != nil {
		return "", err
	}
	_ = s.store.WriteAudit(ctx, adminID, "CREATE_POLICY", "policy", id)
	return id, nil
}

// AssignPolicy, bir politikayı cihaza atar (ADMIN).
func (s *Service) AssignPolicy(ctx context.Context, adminID, deviceID, policyID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if err := s.store.AssignPolicy(ctx, deviceID, policyID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "ASSIGN_POLICY", "device", deviceID)
	// Cihazın açık politika akışını uyandır (anlık push).
	if s.pub != nil {
		s.pub.Publish(deviceID)
	}
	return nil
}

// AddPolicyRule, bir politikaya yeni bir kural ekler (ADMIN). Kuralı ekler,
// politikanın sürümünü yükseltir, denetim izine yazar ve politikaya atanmış her
// cihaza anlık push tetikler (açık StreamPolicies akışını uyandırır).
func (s *Service) AddPolicyRule(ctx context.Context, adminID, policyID string, in RuleInput) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	// Doğrulama: tip geçerli olmalı; APP_TIME_BLOCK ise Start ve End zorunlu.
	if !validRuleType(in.Type) {
		return ErrInvalidRule
	}
	if in.Type == "APP_TIME_BLOCK" && (in.Start == "" || in.End == "") {
		return ErrInvalidRule
	}
	if err := s.store.AddPolicyRule(ctx, policyID, in); err != nil {
		return err
	}
	// Kural değişti; ajanların yeni paketi çekmesi için sürümü yükselt.
	if _, err := s.store.BumpPolicyVersion(ctx, policyID); err != nil {
		return err
	}
	_ = s.store.WriteAudit(ctx, adminID, "ADD_POLICY_RULE", "policy", policyID)
	// Politikaya atanmış her cihazın açık akışını uyandır (anlık push).
	if s.pub != nil {
		devices, err := s.store.DevicesForPolicy(ctx, policyID)
		if err != nil {
			return err
		}
		for _, deviceID := range devices {
			s.pub.Publish(deviceID)
		}
	}
	return nil
}

// ListPolicyRules, bir politikanın kurallarını döner (OPERATOR+).
func (s *Service) ListPolicyRules(ctx context.Context, adminID, policyID string) ([]RuleView, error) {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return nil, err
	}
	return s.store.ListPolicyRules(ctx, policyID)
}

// defaultGenToken, 20 baytlık rastgele, okunabilir (base32) bir token üretir.
func defaultGenToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

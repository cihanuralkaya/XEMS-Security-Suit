// Package adminread, yönetim konsolu için okuma (görünürlük) sorgularını sağlar.
// Cihaz kayıtlarındaki şifreli alanları (hostname, mac) sunucu tarafında (ana
// anahtar RAM'de) deşifre eder; olay logları zaten düz metindir (sorgulanabilir
// olması için, bkz. db şema notu).
package adminread

import (
	"context"
	"encoding/json"
	"time"

	"xems.corp/suite/server/internal/security"
)

// DeviceRow, DB'den okunan ham cihaz satırıdır (şifreli alanlar dahil).
type DeviceRow struct {
	ID           string
	Status       string
	AgentVersion string
	OSPlatform   string
	OSVersion    string
	LastSeen     time.Time
	HostnameEnc  []byte
	MACEnc       []byte
	Tags         []string
}

// EventRow, DB'den okunan ham olay satırıdır (şifresiz).
type EventRow struct {
	ID         string
	DeviceID   string // olayı üreten cihazın kimliği (filo-geneli görünümde atıf/gruplama)
	Category   string
	Severity   string
	Message    string
	OccurredAt time.Time
	CreatedAt  time.Time
	// Details, olayın yapılandırılmış ek verisidir (ham JSON). Ayrıntı yoksa nil.
	Details json.RawMessage
}

// AuditRow, DB'den okunan ham denetim izi satırıdır (admin e-postası çözülmüş).
type AuditRow struct {
	ID         int64
	AdminEmail string
	Action     string
	TargetType string
	TargetID   string
	CreatedAt  time.Time
}

// CertRow, DB'den okunan ham sertifika satırıdır. Fingerprint hex-kodlu döner.
type CertRow struct {
	Serial      string
	Fingerprint string // SHA-256(DER), hex
	NotBefore   time.Time
	NotAfter    time.Time
	Revoked     bool
}

// CmdRow, DB'den okunan ham komut geçmişi satırıdır. DeliveredAt nil ise komut
// henüz teslim edilmemiştir (bekliyor).
type CmdRow struct {
	Type        string
	IssuedBy    string
	CreatedAt   time.Time
	DeliveredAt *time.Time
}

// EnrollmentTokenRow, DB'den okunan ham enrollment token satırıdır. Ham token
// ASLA saklanmaz (yalnız HMAC hash'i); yalnız meta veri okunur. CreatedByEmail,
// admins tablosuyla LEFT JOIN'den çözülür (admin silinmişse boş kalır).
type EnrollmentTokenRow struct {
	ID             string
	CreatedByEmail string
	ExpiresAt      time.Time
	Used           bool
	CreatedAt      time.Time
}

// PolicyRow, DB'den okunan ham politika satırıdır (kural + atanmış cihaz
// sayımlarıyla). Politika adı/sürümü hassas değildir; şifrelenmez.
type PolicyRow struct {
	ID          string
	Name        string
	Version     string
	RuleCount   int
	DeviceCount int
}

// Store, okuma sorgularının kalıcılık kaynağıdır.
type Store interface {
	ListDevices(ctx context.Context, limit int) ([]DeviceRow, error)
	// QueryEvents, zaman-pencereli + alan-filtreli olay sorgusudur (retro-hunt /
	// SIEM arama primitifi). Tüm alanlar opsiyonel; Since/Until sıfır ise sınırsız.
	QueryEvents(ctx context.Context, f EventFilter) ([]EventRow, error)
	// ListEvents, olayları en yeniden eskiye listeler. deviceID/severity/category
	// boş ("") ise ilgili filtre uygulanmaz (opsiyonel sunucu-tarafı filtre).
	ListEvents(ctx context.Context, deviceID, severity, category string, limit int) ([]EventRow, error)
	// DeviceStatusCounts, cihaz durumuna göre (status -> adet) sayımları döner.
	DeviceStatusCounts(ctx context.Context) (map[string]int, error)
	// EventSeverityCounts, since'ten bu yana olayları önem seviyesine göre sayar.
	EventSeverityCounts(ctx context.Context, since time.Time) (map[string]int, error)
	// EventCategoryCounts, since'ten bu yana olayları kategoriye göre sayar.
	EventCategoryCounts(ctx context.Context, since time.Time) (map[string]int, error)
	// LatestComplianceByDevice, uyum verisi taşıyan her cihaz için EN SON
	// disk_encryption/firewall durumunu döner (cihaz kimliği → durum). Filo-geneli
	// doğru uyum KPI'ı için (istemci-taraflı 200-olay penceresiyle sınırlı değil).
	LatestComplianceByDevice(ctx context.Context) (map[string]ComplianceStatus, error)
	// SearchSoftware, her cihazın EN SON yazılım envanterinde adı query'yi (küçük/
	// büyük harf duyarsız alt-dize) içeren paketleri arar; cihaz kimliği → eşleşen
	// paket adları döner (eşleşme olmayan cihazlar dışarıda). Zafiyet müdahalesi
	// ("X kurulu cihazlar hangileri") için filo-geneli arama.
	SearchSoftware(ctx context.Context, query string) (map[string][]string, error)
	// EventAcks, triyaj işaretli olayların durumunu döner (olay kimliği → durum).
	// Alarm yaşam-döngüsü: olay listesine ACKNOWLEDGED/RESOLVED bindirilir.
	EventAcks(ctx context.Context) (map[string]EventAck, error)
	// LatestSoftwareByDevice, her cihazın EN SON yazılım envanterini döner
	// (cihaz kimliği → paket adları). Zafiyet eşleştirmesi için.
	LatestSoftwareByDevice(ctx context.Context) (map[string][]string, error)
	// ListArtifacts, bir cihazdan toplanan dosya artefaktlarının META verisini
	// (içerik HARİÇ) en yeniden eskiye döner (adli/IR).
	ListArtifacts(ctx context.Context, deviceID string) ([]ArtifactRow, error)
	// ListPendingWipes, ikinci-onay bekleyen tüm WIPE taleplerini döner (çift-kontrol
	// görünürlüğü — konsolun onay/iptal için gösterdiği liste).
	ListPendingWipes(ctx context.Context) ([]PendingWipeRow, error)
	// GetArtifact, tek bir artefaktın içeriğini (indirme için) döner.
	GetArtifact(ctx context.Context, id string) (ArtifactContent, bool, error)
	ListAudit(ctx context.Context, limit int) ([]AuditRow, error)
	DeviceByID(ctx context.Context, id string) (DeviceRow, bool, error)
	CertsByDevice(ctx context.Context, id string) ([]CertRow, error)
	CommandHistory(ctx context.Context, id string) ([]CmdRow, error)
	AssignedPolicy(ctx context.Context, id string) (policyID, version string, err error)
	// ListEnrollmentTokens, enrollment token'ların meta verisini en yeniden
	// eskiye listeler (ham token asla okunmaz).
	ListEnrollmentTokens(ctx context.Context, limit int) ([]EnrollmentTokenRow, error)
	// ListPolicies, tüm politikaları (kural sayısı + atanmış cihaz sayısıyla)
	// listeler.
	ListPolicies(ctx context.Context, limit int) ([]PolicyRow, error)
}

// DeviceDTO, konsola dönen deşifre edilmiş cihaz görünümüdür.
type DeviceDTO struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	MAC          string    `json:"mac"`
	Status       string    `json:"status"`
	AgentVersion string    `json:"agent_version"`
	OSPlatform   string    `json:"os_platform"`
	OSVersion    string    `json:"os_version"`
	LastSeen     time.Time `json:"last_seen"`
	Tags         []string  `json:"tags"`
}

// CertView, konsola dönen sertifika görünümüdür.
type CertView struct {
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Revoked     bool      `json:"revoked"`
}

// CmdView, konsola dönen komut geçmişi görünümüdür. DeliveredAt nil ise JSON'da
// null olur (komut bekliyor).
type CmdView struct {
	Type        string     `json:"type"`
	IssuedBy    string     `json:"issued_by"`
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at"`
}

// DeviceDetailDTO, tek bir cihazın tam görünümüdür (deşifre edilmiş cihaz alanları
// + sertifikalar + komut geçmişi + atanmış politika).
type DeviceDetailDTO struct {
	Device                DeviceDTO  `json:"device"`
	Certs                 []CertView `json:"certs"`
	Commands              []CmdView  `json:"commands"`
	AssignedPolicyID      string     `json:"assigned_policy_id"`
	AssignedPolicyVersion string     `json:"assigned_policy_version"`
}

// ArtifactRow, toplanan bir dosya artefaktının meta verisidir (içerik hariç).
type ArtifactRow struct {
	ID          string
	DeviceID    string
	Path        string
	SHA256      string
	Size        int
	CollectedAt time.Time
}

// ArtifactContent, bir artefaktın indirme içeriğidir.
type ArtifactContent struct {
	Path    string
	Content []byte
}

// ArtifactDTO, konsola dönen artefakt meta görünümüdür.
type ArtifactDTO struct {
	ID          string    `json:"id"`
	Path        string    `json:"path"`
	SHA256      string    `json:"sha256"`
	Size        int       `json:"size"`
	CollectedAt time.Time `json:"collected_at"`
}

// EventAck, bir olayın triyaj/vaka durumudur (alarm yaşam-döngüsü + vaka yönetimi).
type EventAck struct {
	Status     string    // "ACKNOWLEDGED" | "RESOLVED" | "" (yalnız atama/not)
	Assignee   string    // sorumlu analist (vaka yönetimi)
	Note       string    // serbest triyaj notu
	AdminEmail string    // son işleyen (görüntüleme; çözülmüş)
	At         time.Time // son güncelleme
}

// EventDTO, konsola dönen olay görünümüdür.
type EventDTO struct {
	ID         string          `json:"id"`
	DeviceID   string          `json:"device_id,omitempty"`
	Category   string          `json:"category"`
	Severity   string          `json:"severity"`
	Message    string          `json:"message"`
	OccurredAt time.Time       `json:"occurred_at"`
	CreatedAt  time.Time       `json:"created_at"`
	Details    json.RawMessage `json:"details,omitempty"`
	// Alarm yaşam-döngüsü + vaka yönetimi (işaretlenmişse dolu).
	AckStatus   string    `json:"ack_status,omitempty"`
	AckBy       string    `json:"ack_by,omitempty"`
	AckAt       time.Time `json:"ack_at,omitempty"`
	AckAssignee string    `json:"ack_assignee,omitempty"`
	AckNote     string    `json:"ack_note,omitempty"`
}

// ComplianceStatus, bir cihazın en son güvenlik-duruşu uyum durumudur
// ("on"/"off"/"unknown"; boş = veri yok).
type ComplianceStatus struct {
	Enc string `json:"disk_encryption"`
	Fw  string `json:"firewall"`
}

// SummaryDTO, yönetim panosu için özet/KPI sayaçlarıdır.
type SummaryDTO struct {
	DevicesTotal       int `json:"devices_total"`
	DevicesOnline      int `json:"devices_online"`
	DevicesOffline     int `json:"devices_offline"`
	DevicesQuarantined int `json:"devices_quarantined"`
	// Uyum (filo-geneli, en son duruma göre): şifreleme/duvar kapalı cihaz
	// sayıları ve benzersiz uyumsuz cihaz sayısı.
	ComplianceEncOff    int            `json:"compliance_enc_off"`
	ComplianceFwOff     int            `json:"compliance_fw_off"`
	NonCompliantDevices int            `json:"non_compliant_devices"`
	EventsBySeverity    map[string]int `json:"events_by_severity"` // INFO/LOW/MEDIUM/HIGH/CRITICAL
	EventsByCategory    map[string]int `json:"events_by_category"`
	DevicesByOS         map[string]int `json:"devices_by_os"` // OS sürümü/platform → cihaz sayısı (filo envanteri)
	Since               time.Time      `json:"since"`         // sayımların kapsadığı pencerenin başı (RFC3339)
}

// summaryWindow, özet olay sayımlarının kapsadığı zaman penceresidir (son 24 saat).
const summaryWindow = 24 * time.Hour

// onlineWindow, bir cihazın "çevrimiçi" sayılması için son görülme eşiğidir.
const onlineWindow = 30 * time.Second

// AuditDTO, konsola dönen denetim izi görünümüdür.
type AuditDTO struct {
	ID         int64     `json:"id"`
	AdminEmail string    `json:"admin_email"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// EnrollmentTokenDTO, konsola dönen enrollment token görünümüdür. YALNIZ meta
// veri içerir; ham token hiçbir zaman burada yer almaz (yalnız HMAC hash saklı).
type EnrollmentTokenDTO struct {
	ID             string    `json:"id"`
	CreatedByEmail string    `json:"created_by_email"`
	ExpiresAt      time.Time `json:"expires_at"`
	Used           bool      `json:"used"`
	CreatedAt      time.Time `json:"created_at"`
}

// PolicyDTO, konsola dönen politika görünümüdür.
type PolicyDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	RuleCount   int    `json:"rule_count"`
	DeviceCount int    `json:"device_count"`
}

// Service, okuma sorgularını yürütür ve şifreli alanları deşifre eder.
type Service struct {
	store  Store
	cipher *security.FieldCipher
}

// NewService oluşturur.
func NewService(store Store, cipher *security.FieldCipher) *Service {
	return &Service{store: store, cipher: cipher}
}

// Devices, cihaz listesini (deşifre edilmiş) döner.
func (s *Service) Devices(ctx context.Context, limit int) ([]DeviceDTO, error) {
	rows, err := s.store.ListDevices(ctx, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	out := make([]DeviceDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, DeviceDTO{
			ID:           r.ID,
			Hostname:     s.decrypt(r.HostnameEnc),
			MAC:          s.decrypt(r.MACEnc),
			Status:       r.Status,
			AgentVersion: r.AgentVersion,
			OSPlatform:   r.OSPlatform,
			OSVersion:    r.OSVersion,
			LastSeen:     r.LastSeen,
			Tags:         nonNilTags(r.Tags),
		})
	}
	return out, nil
}

// nonNilTags, JSON'da null yerine boş dizi dönmek için nil dilimi []string{}'e
// çevirir (konsol her zaman dizi bekler).
func nonNilTags(t []string) []string {
	if t == nil {
		return []string{}
	}
	return t
}

// DeviceDetail, tek bir cihazın tam görünümünü döner. Cihaz bulunamazsa
// ok=false döner. Şifreli alanlar (hostname, mac) sunucuda deşifre edilir.
func (s *Service) DeviceDetail(ctx context.Context, id string) (DeviceDetailDTO, bool, error) {
	row, ok, err := s.store.DeviceByID(ctx, id)
	if err != nil || !ok {
		return DeviceDetailDTO{}, ok, err
	}
	certRows, err := s.store.CertsByDevice(ctx, id)
	if err != nil {
		return DeviceDetailDTO{}, false, err
	}
	cmdRows, err := s.store.CommandHistory(ctx, id)
	if err != nil {
		return DeviceDetailDTO{}, false, err
	}
	policyID, policyVersion, err := s.store.AssignedPolicy(ctx, id)
	if err != nil {
		return DeviceDetailDTO{}, false, err
	}

	certs := make([]CertView, 0, len(certRows))
	for _, c := range certRows {
		certs = append(certs, CertView{
			Serial:      c.Serial,
			Fingerprint: c.Fingerprint,
			NotBefore:   c.NotBefore,
			NotAfter:    c.NotAfter,
			Revoked:     c.Revoked,
		})
	}
	commands := make([]CmdView, 0, len(cmdRows))
	for _, c := range cmdRows {
		commands = append(commands, CmdView{
			Type:        c.Type,
			IssuedBy:    c.IssuedBy,
			CreatedAt:   c.CreatedAt,
			DeliveredAt: c.DeliveredAt,
		})
	}

	return DeviceDetailDTO{
		Device: DeviceDTO{
			ID:           row.ID,
			Hostname:     s.decrypt(row.HostnameEnc),
			MAC:          s.decrypt(row.MACEnc),
			Status:       row.Status,
			AgentVersion: row.AgentVersion,
			OSPlatform:   row.OSPlatform,
			OSVersion:    row.OSVersion,
			LastSeen:     row.LastSeen,
			Tags:         nonNilTags(row.Tags),
		},
		Certs:                 certs,
		Commands:              commands,
		AssignedPolicyID:      policyID,
		AssignedPolicyVersion: policyVersion,
	}, true, nil
}

// Events, bir cihazın (deviceID boşsa tümünün) olaylarını döner. severity ve
// category boş ("") değilse sunucu-tarafında ilgili sütuna göre filtrelenir.
func (s *Service) Events(ctx context.Context, deviceID, severity, category string, limit int) ([]EventDTO, error) {
	rows, err := s.store.ListEvents(ctx, deviceID, severity, category, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	// Alarm yaşam-döngüsü: triyaj işaretlerini (varsa) olaylara bindir.
	acks, err := s.store.EventAcks(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]EventDTO, 0, len(rows))
	for _, r := range rows {
		dto := EventDTO{
			ID:         r.ID,
			DeviceID:   r.DeviceID,
			Category:   r.Category,
			Severity:   r.Severity,
			Message:    r.Message,
			OccurredAt: r.OccurredAt,
			CreatedAt:  r.CreatedAt,
			Details:    r.Details,
		}
		if a, ok := acks[r.ID]; ok {
			dto.AckStatus, dto.AckBy, dto.AckAt = a.Status, a.AdminEmail, a.At
			dto.AckAssignee, dto.AckNote = a.Assignee, a.Note
		}
		out = append(out, dto)
	}
	return out, nil
}

// Summary, yönetim panosu için özet/KPI sayaçlarını hesaplar. Cihazlar duruma
// göre gruplanır; olaylar son 24 saatlik pencerede önem ve kategoriye göre
// sayılır. "online", cihaz listesinden son görülme (< onlineWindow) üzerinden
// hesaplanır (duruma ek, best-effort).
func (s *Service) Summary(ctx context.Context) (SummaryDTO, error) {
	now := time.Now()
	since := now.Add(-summaryWindow)

	statusCounts, err := s.store.DeviceStatusCounts(ctx)
	if err != nil {
		return SummaryDTO{}, err
	}
	sevCounts, err := s.store.EventSeverityCounts(ctx, since)
	if err != nil {
		return SummaryDTO{}, err
	}
	catCounts, err := s.store.EventCategoryCounts(ctx, since)
	if err != nil {
		return SummaryDTO{}, err
	}

	total := 0
	for _, n := range statusCounts {
		total += n
	}

	// online: cihaz listesinden son görülmesi eşiğin altında olanları say.
	rows, err := s.store.ListDevices(ctx, clampLimit(0))
	if err != nil {
		return SummaryDTO{}, err
	}
	online := 0
	byOS := map[string]int{}
	for _, r := range rows {
		if now.Sub(r.LastSeen) < onlineWindow {
			online++
		}
		// Filo OS envanteri: sürüm varsa ona, yoksa platforma, o da yoksa "bilinmiyor".
		key := r.OSVersion
		if key == "" {
			key = r.OSPlatform
		}
		if key == "" {
			key = "bilinmiyor"
		}
		byOS[key]++
	}
	offline := total - online
	if offline < 0 {
		offline = 0
	}

	if sevCounts == nil {
		sevCounts = map[string]int{}
	}
	if catCounts == nil {
		catCounts = map[string]int{}
	}

	// Filo-geneli uyum: her cihazın en son durumundan kapalı/uyumsuz sayıları.
	comp, err := s.store.LatestComplianceByDevice(ctx)
	if err != nil {
		return SummaryDTO{}, err
	}
	encOff, fwOff, nonComp := 0, 0, 0
	for _, c := range comp {
		bad := false
		if c.Enc == "off" {
			encOff++
			bad = true
		}
		if c.Fw == "off" {
			fwOff++
			bad = true
		}
		if bad {
			nonComp++
		}
	}

	return SummaryDTO{
		DevicesTotal:        total,
		DevicesOnline:       online,
		DevicesOffline:      offline,
		DevicesQuarantined:  statusCounts["QUARANTINED"],
		ComplianceEncOff:    encOff,
		ComplianceFwOff:     fwOff,
		NonCompliantDevices: nonComp,
		EventsBySeverity:    sevCounts,
		EventsByCategory:    catCounts,
		DevicesByOS:         byOS,
		Since:               since,
	}, nil
}

// EventFilter, retro-hunt / SIEM arama için zaman-pencereli + alan-filtreli olay
// sorgusunun ölçütleridir. Boş string / sıfır zaman = o alan filtrelenmez.
type EventFilter struct {
	DeviceID        string
	Severity        string
	Category        string
	MessageContains string    // mesajda alt-dize (ILIKE); büyük/küçük harf duyarsız
	Since           time.Time // olay >= Since (created_at)
	Until           time.Time // olay <= Until
	Limit           int
}

// QueryEvents, zaman-pencereli olay sorgusunu depoya devreder (retro-hunt/arama).
func (s *Service) QueryEvents(ctx context.Context, f EventFilter) ([]EventDTO, error) {
	f.Limit = clampLimit(f.Limit)
	rows, err := s.store.QueryEvents(ctx, f)
	if err != nil {
		return nil, err
	}
	out := make([]EventDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, EventDTO{
			ID: r.ID, DeviceID: r.DeviceID, Category: r.Category, Severity: r.Severity,
			Message: r.Message, OccurredAt: r.OccurredAt, CreatedAt: r.CreatedAt, Details: r.Details,
		})
	}
	return out, nil
}

// PendingWipeRow, ikinci-onay bekleyen bir WIPE talebidir (çift-kontrol görünümü).
type PendingWipeRow struct {
	DeviceID    string    `json:"device_id"`
	RequestedBy string    `json:"requested_by"` // talep eden admin (e-posta ya da id)
	Reason      string    `json:"reason,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
}

// PendingWipes, ikinci-onay bekleyen WIPE taleplerini döner (çift-kontrol konsol görünümü).
func (s *Service) PendingWipes(ctx context.Context) ([]PendingWipeRow, error) {
	return s.store.ListPendingWipes(ctx)
}

// LatestSoftwareByDevice, her cihazın en son yazılım envanterini döner (zafiyet
// eşleştirme için; adminapi katmanı vuln veri kümesiyle eşler).
func (s *Service) LatestSoftwareByDevice(ctx context.Context) (map[string][]string, error) {
	return s.store.LatestSoftwareByDevice(ctx)
}

// Artifacts, bir cihazdan toplanan dosya artefaktlarının meta listesini döner
// (içerik hariç; indirme ayrı uçtan). Adli/IR.
func (s *Service) Artifacts(ctx context.Context, deviceID string) ([]ArtifactDTO, error) {
	rows, err := s.store.ListArtifacts(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	out := make([]ArtifactDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, ArtifactDTO{ID: r.ID, Path: r.Path, SHA256: r.SHA256, Size: r.Size, CollectedAt: r.CollectedAt})
	}
	return out, nil
}

// ArtifactBytes, tek bir artefaktın içeriğini (indirme için) döner.
func (s *Service) ArtifactBytes(ctx context.Context, id string) (ArtifactContent, bool, error) {
	return s.store.GetArtifact(ctx, id)
}

// SoftwareMatchDTO, yazılım aramasında eşleşen bir cihazı ve eşleşen paketleri
// taşır (hostname deşifre edilmiş).
type SoftwareMatchDTO struct {
	DeviceID string   `json:"device_id"`
	Hostname string   `json:"hostname"`
	Matches  []string `json:"matches"`
}

// SoftwareSearch, filo-geneli yazılım araması yapar: adı query'yi içeren paketleri
// taşıyan cihazları (deşifre hostname + eşleşen paketler) döner. Zafiyet
// müdahalesi ("X kurulu cihazlar") için. Eşleşme yoksa boş liste.
func (s *Service) SoftwareSearch(ctx context.Context, query string) ([]SoftwareMatchDTO, error) {
	byDev, err := s.store.SearchSoftware(ctx, query)
	if err != nil {
		return nil, err
	}
	out := make([]SoftwareMatchDTO, 0, len(byDev))
	if len(byDev) == 0 {
		return out, nil
	}
	// Hostname eşlemesi için cihaz kayıtlarını yükle (şifreli → deşifre).
	rows, err := s.store.ListDevices(ctx, clampLimit(0))
	if err != nil {
		return nil, err
	}
	hn := make(map[string]string, len(rows))
	for _, r := range rows {
		hn[r.ID] = s.decrypt(r.HostnameEnc)
	}
	for id, matches := range byDev {
		out = append(out, SoftwareMatchDTO{DeviceID: id, Hostname: hn[id], Matches: matches})
	}
	return out, nil
}

// Audit, denetim izi kayıtlarını en yeniden eskiye döner.
func (s *Service) Audit(ctx context.Context, limit int) ([]AuditDTO, error) {
	rows, err := s.store.ListAudit(ctx, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	out := make([]AuditDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, AuditDTO{
			ID:         r.ID,
			AdminEmail: r.AdminEmail,
			Action:     r.Action,
			TargetType: r.TargetType,
			TargetID:   r.TargetID,
			CreatedAt:  r.CreatedAt,
		})
	}
	return out, nil
}

// EnrollmentTokens, enrollment token'ların meta verisini en yeniden eskiye
// döner. Ham token asla dönmez; yalnız id, üreten admin e-postası, son geçerlilik,
// kullanıldı-mı ve oluşturulma zamanı gösterilir.
func (s *Service) EnrollmentTokens(ctx context.Context, limit int) ([]EnrollmentTokenDTO, error) {
	rows, err := s.store.ListEnrollmentTokens(ctx, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	out := make([]EnrollmentTokenDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, EnrollmentTokenDTO{
			ID:             r.ID,
			CreatedByEmail: r.CreatedByEmail,
			ExpiresAt:      r.ExpiresAt,
			Used:           r.Used,
			CreatedAt:      r.CreatedAt,
		})
	}
	return out, nil
}

// DeviceExportDTO, bir cihaz hakkında tutulan tüm veriyi tek pakette toplar
// (KVKK veri sahibi ERİŞİM talebi). Şifreli alanlar deşifre edilerek verilir.
type DeviceExportDTO struct {
	GeneratedAt time.Time       `json:"generated_at"`
	DeviceID    string          `json:"device_id"`
	Device      DeviceDetailDTO `json:"device"`
	Events      []EventDTO      `json:"events"`
	Audit       []AuditDTO      `json:"audit"` // bu cihazı hedefleyen denetim kayıtları
}

// ExportDevice, cihaz hakkında tutulan veriyi (detay + tüm olaylar + cihazı
// hedefleyen denetim kayıtları) tek pakette toplar. Cihaz yoksa ok=false.
func (s *Service) ExportDevice(ctx context.Context, deviceID string) (DeviceExportDTO, bool, error) {
	detail, ok, err := s.DeviceDetail(ctx, deviceID)
	if err != nil || !ok {
		return DeviceExportDTO{}, ok, err
	}
	events, err := s.Events(ctx, deviceID, "", "", 0)
	if err != nil {
		return DeviceExportDTO{}, false, err
	}
	allAudit, err := s.Audit(ctx, 0)
	if err != nil {
		return DeviceExportDTO{}, false, err
	}
	deviceAudit := make([]AuditDTO, 0)
	for _, a := range allAudit {
		if a.TargetType == "device" && a.TargetID == deviceID {
			deviceAudit = append(deviceAudit, a)
		}
	}
	return DeviceExportDTO{
		GeneratedAt: time.Now().UTC(),
		DeviceID:    deviceID,
		Device:      detail,
		Events:      events,
		Audit:       deviceAudit,
	}, true, nil
}

// Policies, tüm politikaları (kural + atanmış cihaz sayımlarıyla) döner.
func (s *Service) Policies(ctx context.Context, limit int) ([]PolicyDTO, error) {
	rows, err := s.store.ListPolicies(ctx, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	out := make([]PolicyDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, PolicyDTO{
			ID:          r.ID,
			Name:        r.Name,
			Version:     r.Version,
			RuleCount:   r.RuleCount,
			DeviceCount: r.DeviceCount,
		})
	}
	return out, nil
}

func (s *Service) decrypt(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	v, err := s.cipher.DecryptString(blob)
	if err != nil {
		return "(çözülemedi)"
	}
	return v
}

func clampLimit(n int) int {
	if n <= 0 {
		return 100
	}
	if n > 1000 {
		return 1000
	}
	return n
}

// Package adminread, yönetim konsolu için okuma (görünürlük) sorgularını sağlar.
// Cihaz kayıtlarındaki şifreli alanları (hostname, mac) sunucu tarafında (ana
// anahtar RAM'de) deşifre eder; olay logları zaten düz metindir (sorgulanabilir
// olması için, bkz. db şema notu).
package adminread

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"xems.corp/suite/server/internal/complianceframework"
	"xems.corp/suite/server/internal/risk"
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
	// ListIncidents, korelasyonla gruplanmış olayları en yeniden eskiye döner.
	ListIncidents(ctx context.Context, limit int) ([]IncidentRow, error)
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
	// SaveSearch, adlandırılmış bir threat-hunting sorgusunu (filtre JSON) kalıcılaştırır
	// ve oluşturulan kaydı döner (SIEM kayıtlı-arama). name+filter zorunlu.
	SaveSearch(ctx context.Context, name, filterJSON, createdBy string) (SavedSearchRow, error)
	// ListSavedSearches, kayıtlı aramaları en yeniden eskiye döner.
	ListSavedSearches(ctx context.Context) ([]SavedSearchRow, error)
	// DeleteSavedSearch, verilen kimlikli kayıtlı aramayı siler.
	DeleteSavedSearch(ctx context.Context, id string) error
}

// SavedSearchRow, kalıcılaştırılmış bir threat-hunting sorgusudur.
type SavedSearchRow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Filter    string    `json:"filter"` // ham EventFilter/hunt isteği JSON'u
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
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

// CoverageDTO, filo koruma-kapsamı ve ajan sürüm-kaymasıdır ("kim korunuyor?").
type CoverageDTO struct {
	Total          int            `json:"total"`
	Online         int            `json:"online"`       // son onlineWindow içinde görülen
	Stale          int            `json:"stale"`        // çevrimiçi olmayan (sessiz/çevrimdışı)
	CoveragePct    int            `json:"coverage_pct"` // online*100/total
	ByAgentVersion map[string]int `json:"by_agent_version"`
	VersionCount   int            `json:"version_count"` // farklı ajan sürümü sayısı (kayma göstergesi)
}

// Coverage, "kim korunuyor?" görünümünü hesaplar: çevrimiçi kapsam yüzdesi ve ajan
// sürüm dağılımı (sürüm-kayması). Sessiz/eski ajanlar EDR dağıtımının gerçek boşluğudur.
func (s *Service) Coverage(ctx context.Context) (CoverageDTO, error) {
	rows, err := s.store.ListDevices(ctx, 0)
	if err != nil {
		return CoverageDTO{}, err
	}
	now := time.Now()
	cov := CoverageDTO{ByAgentVersion: map[string]int{}}
	for _, r := range rows {
		cov.Total++
		if now.Sub(r.LastSeen) < onlineWindow {
			cov.Online++
		} else {
			cov.Stale++
		}
		ver := r.AgentVersion
		if ver == "" {
			ver = "(bilinmiyor)"
		}
		cov.ByAgentVersion[ver]++
	}
	cov.VersionCount = len(cov.ByAgentVersion)
	if cov.Total > 0 {
		cov.CoveragePct = cov.Online * 100 / cov.Total
	}
	return cov, nil
}

// IncidentRow, korelasyonla gruplanmış bir olaydır (incident); ilişkili tespitler
// tek satırda katlanır (sayaç + son-görülme).
type IncidentRow struct {
	ID            string    `json:"id"`
	DeviceID      string    `json:"device_id"`
	RuleID        string    `json:"rule_id"`
	Technique     string    `json:"technique,omitempty"`
	Severity      string    `json:"severity"`
	SampleMessage string    `json:"sample_message"`
	Count         int       `json:"count"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Status        string    `json:"status"`
}

// Incidents, korelasyonla gruplanmış olayları en yeniden eskiye döner (konsol).
func (s *Service) Incidents(ctx context.Context, limit int) ([]IncidentRow, error) {
	return s.store.ListIncidents(ctx, clampLimit(limit))
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

// IncidentTimelineDTO, bir incident'in kronolojik olay zaman çizelgesidir.
type IncidentTimelineDTO struct {
	Incident IncidentRow `json:"incident"`
	Events   []EventDTO  `json:"events"`
}

// IncidentTimeline, bir incident'i (kimliğine göre) ve onu oluşturan cihazın
// [first_seen, last_seen] penceresindeki olaylarını kronolojik döner (IR
// araştırması: "bu incident nasıl gelişti?"). Mevcut depo yüzeyini kullanır.
func (s *Service) IncidentTimeline(ctx context.Context, incidentID string) (IncidentTimelineDTO, bool, error) {
	incidents, err := s.store.ListIncidents(ctx, clampLimit(1000))
	if err != nil {
		return IncidentTimelineDTO{}, false, err
	}
	var inc IncidentRow
	found := false
	for _, it := range incidents {
		if it.ID == incidentID {
			inc, found = it, true
			break
		}
	}
	if !found {
		return IncidentTimelineDTO{}, false, nil
	}
	// İlişkili olaylar: aynı cihaz, [first_seen - tampon, last_seen + tampon].
	buffer := 2 * time.Minute
	rows, err := s.store.QueryEvents(ctx, EventFilter{
		DeviceID: inc.DeviceID,
		Since:    inc.FirstSeen.Add(-buffer),
		Until:    inc.LastSeen.Add(buffer),
		Limit:    500,
	})
	if err != nil {
		return IncidentTimelineDTO{}, false, err
	}
	events := make([]EventDTO, 0, len(rows))
	for _, r := range rows {
		events = append(events, EventDTO{
			ID: r.ID, DeviceID: r.DeviceID, Category: r.Category, Severity: r.Severity,
			Message: r.Message, OccurredAt: r.OccurredAt, CreatedAt: r.CreatedAt, Details: r.Details,
		})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].OccurredAt.Before(events[j].OccurredAt) })
	return IncidentTimelineDTO{Incident: inc, Events: events}, true, nil
}

// FrameworkCompliance, filo güvenlik-duruşunu tanınmış uyum çerçevelerine (CIS/
// NIST/ISO/KVKK) eşler. Her kontrolün filo-geneli uyum oranı (uyumlu cihaz /
// veri taşıyan cihaz) hesaplanıp çerçeve skorlarına çevrilir. Mevcut compliance
// verisini (LatestComplianceByDevice) kullanır; yeni depo sorgusu yok.
func (s *Service) FrameworkCompliance(ctx context.Context) (complianceframework.Report, error) {
	comp, err := s.store.LatestComplianceByDevice(ctx)
	if err != nil {
		return complianceframework.Report{}, err
	}
	var encOn, encTotal, fwOn, fwTotal int
	for _, c := range comp {
		if c.Enc != "" && c.Enc != "unknown" {
			encTotal++
			if c.Enc == "on" {
				encOn++
			}
		}
		if c.Fw != "" && c.Fw != "unknown" {
			fwTotal++
			if c.Fw == "on" {
				fwOn++
			}
		}
	}
	ratios := map[string]float64{}
	if encTotal > 0 {
		ratios["disk_encryption"] = float64(encOn) / float64(encTotal)
	}
	if fwTotal > 0 {
		ratios["firewall"] = float64(fwOn) / float64(fwTotal)
	}
	return complianceframework.Evaluate(ratios), nil
}

// DeviceRiskDTO, bir cihazın toplam risk skorudur (çok-faktörlü risk motoru).
type DeviceRiskDTO struct {
	DeviceID string   `json:"device_id"`
	Hostname string   `json:"hostname"`
	Score    int      `json:"score"` // 0-100
	Band     string   `json:"band"`  // INFO..CRITICAL
	Drivers  []string `json:"drivers"`
}

// FleetRiskDTO, filo-geneli risk özetidir.
type FleetRiskDTO struct {
	FleetScore int             `json:"fleet_score"` // en riskli cihaz baskın
	FleetBand  string          `json:"fleet_band"`
	Bands      map[string]int  `json:"bands"` // band → cihaz sayısı
	Devices    []DeviceRiskDTO `json:"devices"`
}

// FleetRisk, çok-faktörlü risk motorunu (risk paketi) mevcut sinyallere (açık
// incident'ler, uyum ihlalleri, karantina durumu) uygular ve cihaz + filo risk
// skorlarını hesaplar. Yeni depo sorgusu kullanmaz.
func (s *Service) FleetRisk(ctx context.Context) (FleetRiskDTO, error) {
	devices, err := s.Devices(ctx, 0)
	if err != nil {
		return FleetRiskDTO{}, err
	}
	incidents, err := s.store.ListIncidents(ctx, clampLimit(1000))
	if err != nil {
		return FleetRiskDTO{}, err
	}
	comp, err := s.store.LatestComplianceByDevice(ctx)
	if err != nil {
		return FleetRiskDTO{}, err
	}

	// Cihaz başına risk faktörlerini (bulgu skorları + sürücü açıklamaları) topla.
	scores := map[string][]int{}
	drivers := map[string][]string{}
	add := func(dev string, sc int, why string) {
		scores[dev] = append(scores[dev], sc)
		if why != "" {
			drivers[dev] = append(drivers[dev], why)
		}
	}
	for _, inc := range incidents {
		if inc.Status == "RESOLVED" || inc.Status == "CLOSED" {
			continue
		}
		sc := risk.Score(risk.Factors{
			Severity: inc.Severity, AssetCriticality: 3,
			Confidence: 0.9, Exploitability: 0.3,
		})
		add(inc.DeviceID, sc, "açık incident ("+inc.Severity+"): "+inc.RuleID)
	}
	for _, d := range devices {
		if c, ok := comp[d.ID]; ok {
			if c.Enc == "off" {
				add(d.ID, risk.Score(risk.Factors{Severity: "MEDIUM", AssetCriticality: 3, Confidence: 1}), "disk şifreleme kapalı")
			}
			if c.Fw == "off" {
				add(d.ID, risk.Score(risk.Factors{Severity: "MEDIUM", AssetCriticality: 3, Confidence: 1}), "güvenlik duvarı kapalı")
			}
		}
		if d.Status == "QUARANTINED" {
			add(d.ID, risk.Score(risk.Factors{Severity: "HIGH", AssetCriticality: 4, Exposure: 1, Confidence: 1}), "karantinada (aktif müdahale)")
		}
	}

	out := FleetRiskDTO{Bands: map[string]int{}}
	fleet := 0
	for _, d := range devices {
		sc := risk.Aggregate(scores[d.ID])
		band := risk.Band(sc)
		out.Bands[band]++
		if sc > fleet {
			fleet = sc
		}
		dr := drivers[d.ID]
		if dr == nil {
			dr = []string{}
		}
		out.Devices = append(out.Devices, DeviceRiskDTO{
			DeviceID: d.ID, Hostname: d.Hostname, Score: sc, Band: band, Drivers: dr,
		})
	}
	// En riskli cihaz önce.
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].Score > out.Devices[j].Score })
	out.FleetScore = fleet
	out.FleetBand = risk.Band(fleet)
	return out, nil
}

// SaveSearch, adlandırılmış bir hunt sorgusunu kalıcılaştırır. Girdi doğrulaması
// (name+filter boş olamaz) çağıran katmanda (handler) yapılır.
func (s *Service) SaveSearch(ctx context.Context, name, filterJSON, createdBy string) (SavedSearchRow, error) {
	return s.store.SaveSearch(ctx, strings.TrimSpace(name), filterJSON, createdBy)
}

// SavedSearches, kayıtlı aramaları döner.
func (s *Service) SavedSearches(ctx context.Context) ([]SavedSearchRow, error) {
	return s.store.ListSavedSearches(ctx)
}

// DeleteSavedSearch, bir kayıtlı aramayı siler.
func (s *Service) DeleteSavedSearch(ctx context.Context, id string) error {
	return s.store.DeleteSavedSearch(ctx, id)
}

// TrendPoint, tek bir günün MTTD/MTTR ortalamalarıdır (trend çizgisi noktası).
type TrendPoint struct {
	Day         string  `json:"day"`          // YYYY-MM-DD (UTC)
	MTTDSeconds float64 `json:"mttd_seconds"` // o gün algılanan olaylar için ort. algılama gecikmesi
	MTTRSeconds float64 `json:"mttr_seconds"` // o gün triyaj edilen olaylar için ort. yanıt süresi
	DetectN     int     `json:"detect_n"`     // MTTD örnek sayısı
	RespondN    int     `json:"respond_n"`    // MTTR örnek sayısı
}

// TrendsDTO, MTTD (Mean Time To Detect) ve MTTR (Mean Time To Respond) metrikleri
// ve günlük trendidir (SOC olgunluk göstergesi).
//
// MTTD = olay sunucuya ulaşma (created_at) − uçta gözlemlenme (occurred_at):
//
//	tespit/alım gecikmesi (SECURITY olayları üzerinde).
//
// MTTR = triyaj (ack_at) − olay oluşturulma (created_at): analistin yanıt süresi
// (durum/atama işaretlenmiş olaylar üzerinde).
type TrendsDTO struct {
	WindowDays  int          `json:"window_days"`
	MTTDSeconds float64      `json:"mttd_seconds"` // pencere geneli ortalama
	MTTRSeconds float64      `json:"mttr_seconds"`
	DetectN     int          `json:"detect_n"`
	RespondN    int          `json:"respond_n"`
	Daily       []TrendPoint `json:"daily"` // eskiden yeniye, gün başına (boş günler dahil)
}

// ComputeTrends, verilen olaylardan MTTD/MTTR metriklerini ve günlük trendini
// hesaplar. SAF fonksiyon (test edilebilir): now referans an, days pencere.
// Negatif gecikmeler (saat kayması) yok sayılır.
func ComputeTrends(events []EventDTO, now time.Time, days int) TrendsDTO {
	if days <= 0 {
		days = 7
	}
	type bucket struct {
		mttdSum, mttrSum float64
		mttdN, mttrN     int
	}
	buckets := map[string]*bucket{}
	get := func(day string) *bucket {
		b := buckets[day]
		if b == nil {
			b = &bucket{}
			buckets[day] = b
		}
		return b
	}

	var mttdSum, mttrSum float64
	var mttdN, mttrN int
	for _, e := range events {
		day := e.CreatedAt.UTC().Format("2006-01-02")
		// MTTD: SECURITY olayları için alım gecikmesi.
		if e.Category == "SECURITY" && !e.OccurredAt.IsZero() && !e.CreatedAt.IsZero() {
			if d := e.CreatedAt.Sub(e.OccurredAt).Seconds(); d >= 0 {
				b := get(day)
				b.mttdSum += d
				b.mttdN++
				mttdSum += d
				mttdN++
			}
		}
		// MTTR: triyaj edilmiş (durum ya da atama işaretli) olaylar için yanıt süresi.
		triaged := e.AckStatus != "" || e.AckAssignee != ""
		if triaged && !e.AckAt.IsZero() && !e.CreatedAt.IsZero() {
			if r := e.AckAt.Sub(e.CreatedAt).Seconds(); r >= 0 {
				b := get(day)
				b.mttrSum += r
				b.mttrN++
				mttrSum += r
				mttrN++
			}
		}
	}

	out := TrendsDTO{WindowDays: days, DetectN: mttdN, RespondN: mttrN}
	out.MTTDSeconds = mean(mttdSum, mttdN)
	out.MTTRSeconds = mean(mttrSum, mttrN)
	// Bitişik günlük noktalar (eskiden yeniye), boş günler 0 ile dahil.
	for i := days - 1; i >= 0; i-- {
		day := now.UTC().AddDate(0, 0, -i).Format("2006-01-02")
		p := TrendPoint{Day: day}
		if b := buckets[day]; b != nil {
			p.MTTDSeconds = mean(b.mttdSum, b.mttdN)
			p.MTTRSeconds = mean(b.mttrSum, b.mttrN)
			p.DetectN = b.mttdN
			p.RespondN = b.mttrN
		}
		out.Daily = append(out.Daily, p)
	}
	return out
}

// mean, sıfır-bölmeye karşı güvenli ortalama (n==0 → 0).
func mean(sum float64, n int) float64 {
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// DetectionResponseTrends, son `days` gün için MTTD/MTTR metriklerini ve günlük
// trendini hesaplar. Pencere içindeki olaylar (created_at) triyaj işaretleriyle
// birleştirilip ComputeTrends'e verilir.
func (s *Service) DetectionResponseTrends(ctx context.Context, days int) (TrendsDTO, error) {
	if days <= 0 {
		days = 7
	}
	now := time.Now()
	rows, err := s.store.QueryEvents(ctx, EventFilter{
		Since: now.AddDate(0, 0, -days), Until: now, Limit: 1000,
	})
	if err != nil {
		return TrendsDTO{}, err
	}
	acks, err := s.store.EventAcks(ctx)
	if err != nil {
		return TrendsDTO{}, err
	}
	dtos := make([]EventDTO, 0, len(rows))
	for _, r := range rows {
		dto := EventDTO{
			ID: r.ID, DeviceID: r.DeviceID, Category: r.Category, Severity: r.Severity,
			Message: r.Message, OccurredAt: r.OccurredAt, CreatedAt: r.CreatedAt,
		}
		if a, ok := acks[r.ID]; ok {
			dto.AckStatus, dto.AckBy, dto.AckAt = a.Status, a.AdminEmail, a.At
			dto.AckAssignee, dto.AckNote = a.Assignee, a.Note
		}
		dtos = append(dtos, dto)
	}
	return ComputeTrends(dtos, now, days), nil
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

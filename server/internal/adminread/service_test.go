package adminread

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xems.corp/suite/server/internal/security"
)

type memStore struct {
	devices    []DeviceRow
	events     []EventRow
	audit      []AuditRow
	certs      []CertRow
	commands   []CmdRow
	tokens     []EnrollmentTokenRow
	policies   []PolicyRow
	polID      string
	polVer     string
	acks       map[string]EventAck
	artifacts  []ArtifactRow
	artContent map[string]ArtifactContent
	latestSW   map[string][]string
}

func (m *memStore) ListPolicies(_ context.Context, _ int) ([]PolicyRow, error) {
	return m.policies, nil
}

func (m *memStore) ListDevices(_ context.Context, _ int) ([]DeviceRow, error) {
	return m.devices, nil
}
func (m *memStore) ListEvents(_ context.Context, deviceID, severity, category string, _ int) ([]EventRow, error) {
	var out []EventRow
	for _, e := range m.events {
		if severity != "" && e.Severity != severity {
			continue
		}
		if category != "" && e.Category != category {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
func (m *memStore) DeviceStatusCounts(_ context.Context) (map[string]int, error) {
	out := map[string]int{}
	for _, d := range m.devices {
		out[d.Status]++
	}
	return out, nil
}
func (m *memStore) EventSeverityCounts(_ context.Context, since time.Time) (map[string]int, error) {
	out := map[string]int{}
	for _, e := range m.events {
		if e.CreatedAt.Before(since) {
			continue
		}
		out[e.Severity]++
	}
	return out, nil
}
func (m *memStore) EventCategoryCounts(_ context.Context, since time.Time) (map[string]int, error) {
	out := map[string]int{}
	for _, e := range m.events {
		if e.CreatedAt.Before(since) {
			continue
		}
		out[e.Category]++
	}
	return out, nil
}
func (m *memStore) LatestComplianceByDevice(_ context.Context) (map[string]ComplianceStatus, error) {
	out := map[string]ComplianceStatus{}
	for i := len(m.events) - 1; i >= 0; i-- {
		e := m.events[i]
		if e.DeviceID == "" || len(e.Details) == 0 {
			continue
		}
		if _, seen := out[e.DeviceID]; seen {
			continue
		}
		var d struct {
			Enc string `json:"disk_encryption"`
			Fw  string `json:"firewall"`
		}
		if err := json.Unmarshal(e.Details, &d); err != nil {
			continue
		}
		if d.Enc == "" && d.Fw == "" {
			continue
		}
		out[e.DeviceID] = ComplianceStatus{Enc: d.Enc, Fw: d.Fw}
	}
	return out, nil
}
func (m *memStore) SearchSoftware(_ context.Context, query string) (map[string][]string, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	out := map[string][]string{}
	if q == "" {
		return out, nil
	}
	seen := map[string]bool{}
	for i := len(m.events) - 1; i >= 0; i-- {
		e := m.events[i]
		if e.DeviceID == "" || len(e.Details) == 0 || seen[e.DeviceID] {
			continue
		}
		var d struct {
			Software []string `json:"software"`
		}
		if err := json.Unmarshal(e.Details, &d); err != nil || d.Software == nil {
			continue
		}
		seen[e.DeviceID] = true
		var mm []string
		for _, n := range d.Software {
			if strings.Contains(strings.ToLower(n), q) {
				mm = append(mm, n)
			}
		}
		if len(mm) > 0 {
			out[e.DeviceID] = mm
		}
	}
	return out, nil
}
func (m *memStore) EventAcks(_ context.Context) (map[string]EventAck, error) {
	return m.acks, nil
}
func (m *memStore) ListPendingWipes(_ context.Context) ([]PendingWipeRow, error) {
	return nil, nil
}
func (m *memStore) LatestSoftwareByDevice(_ context.Context) (map[string][]string, error) {
	return m.latestSW, nil
}
func (m *memStore) ListArtifacts(_ context.Context, deviceID string) ([]ArtifactRow, error) {
	var out []ArtifactRow
	for _, a := range m.artifacts {
		if a.DeviceID == deviceID {
			out = append(out, a)
		}
	}
	return out, nil
}
func (m *memStore) GetArtifact(_ context.Context, id string) (ArtifactContent, bool, error) {
	c, ok := m.artContent[id]
	return c, ok, nil
}
func (m *memStore) ListAudit(_ context.Context, _ int) ([]AuditRow, error) {
	return m.audit, nil
}
func (m *memStore) DeviceByID(_ context.Context, id string) (DeviceRow, bool, error) {
	for _, d := range m.devices {
		if d.ID == id {
			return d, true, nil
		}
	}
	return DeviceRow{}, false, nil
}
func (m *memStore) CertsByDevice(_ context.Context, _ string) ([]CertRow, error) {
	return m.certs, nil
}
func (m *memStore) CommandHistory(_ context.Context, _ string) ([]CmdRow, error) {
	return m.commands, nil
}
func (m *memStore) AssignedPolicy(_ context.Context, _ string) (string, string, error) {
	return m.polID, m.polVer, nil
}
func (m *memStore) ListEnrollmentTokens(_ context.Context, _ int) ([]EnrollmentTokenRow, error) {
	return m.tokens, nil
}

func newCipher(t *testing.T) *security.FieldCipher {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := security.NewFieldCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDevicesDecrypted(t *testing.T) {
	cipher := newCipher(t)
	hostEnc, _ := cipher.EncryptString("WORKSTATION-07")
	macEnc, _ := cipher.EncryptString("aa:bb:cc:dd:ee:ff")

	store := &memStore{devices: []DeviceRow{{
		ID: "dev-1", Status: "ACTIVE", AgentVersion: "0.1.0", OSPlatform: "windows",
		LastSeen: time.Now(), HostnameEnc: hostEnc, MACEnc: macEnc,
	}}}
	svc := NewService(store, cipher)

	dtos, err := svc.Devices(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(dtos) != 1 {
		t.Fatalf("1 cihaz beklenirdi, %d", len(dtos))
	}
	if dtos[0].Hostname != "WORKSTATION-07" || dtos[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("şifreli alanlar deşifre edilmeliydi: %+v", dtos[0])
	}
}

func TestDevicesBadCiphertext(t *testing.T) {
	cipher := newCipher(t)
	store := &memStore{devices: []DeviceRow{{ID: "d", HostnameEnc: []byte("bozuk-veri")}}}
	svc := NewService(store, cipher)
	dtos, _ := svc.Devices(context.Background(), 0)
	if dtos[0].Hostname != "(çözülemedi)" {
		t.Fatalf("bozuk şifreli veri güvenli işlenmeliydi: %q", dtos[0].Hostname)
	}
}

func TestSummaryCounts(t *testing.T) {
	now := time.Now()
	store := &memStore{
		devices: []DeviceRow{
			{ID: "d1", Status: "ACTIVE", LastSeen: now, OSVersion: "Windows 10"},                       // online
			{ID: "d2", Status: "ACTIVE", LastSeen: now.Add(-5 * time.Minute), OSVersion: "Windows 10"}, // offline
			{ID: "d3", Status: "QUARANTINED", LastSeen: now.Add(-time.Hour), OSPlatform: "linux"},      // offline (sürüm yok → platform)
		},
		events: []EventRow{
			{Severity: "HIGH", Category: "SECURITY", CreatedAt: now},
			{Severity: "HIGH", Category: "SECURITY", CreatedAt: now},
			{Severity: "INFO", Category: "SYSTEM", CreatedAt: now},
			{Severity: "CRITICAL", Category: "SECURITY", CreatedAt: now.Add(-48 * time.Hour)}, // pencere dışı
		},
	}
	svc := NewService(store, newCipher(t))

	sum, err := svc.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.DevicesTotal != 3 {
		t.Fatalf("toplam cihaz 3 beklenirdi, %d", sum.DevicesTotal)
	}
	if sum.DevicesOnline != 1 {
		t.Fatalf("çevrimiçi 1 beklenirdi, %d", sum.DevicesOnline)
	}
	if sum.DevicesOffline != 2 {
		t.Fatalf("çevrimdışı 2 beklenirdi, %d", sum.DevicesOffline)
	}
	if sum.DevicesQuarantined != 1 {
		t.Fatalf("karantina 1 beklenirdi, %d", sum.DevicesQuarantined)
	}
	if sum.DevicesByOS["Windows 10"] != 2 || sum.DevicesByOS["linux"] != 1 {
		t.Fatalf("OS envanteri hatalı (Windows 10:2, linux:1 beklenirdi): %+v", sum.DevicesByOS)
	}
	if sum.EventsBySeverity["HIGH"] != 2 || sum.EventsBySeverity["INFO"] != 1 {
		t.Fatalf("önem sayımları hatalı: %+v", sum.EventsBySeverity)
	}
	if _, ok := sum.EventsBySeverity["CRITICAL"]; ok {
		t.Fatalf("pencere dışı olay sayılmamalıydı: %+v", sum.EventsBySeverity)
	}
	if sum.EventsByCategory["SECURITY"] != 2 || sum.EventsByCategory["SYSTEM"] != 1 {
		t.Fatalf("kategori sayımları hatalı: %+v", sum.EventsByCategory)
	}
	if sum.Since.After(now) {
		t.Fatalf("since geçmişte olmalı: %v", sum.Since)
	}
}

// Filo-geneli uyum sayımı: cihaz başına EN SON uyum olayına göre şifreleme/duvar
// kapalı ve benzersiz uyumsuz cihaz sayıları.
func TestSummaryCompliance(t *testing.T) {
	now := time.Now()
	det := func(enc, fw string) []byte {
		return []byte(`{"disk_encryption":"` + enc + `","firewall":"` + fw + `"}`)
	}
	store := &memStore{
		devices: []DeviceRow{{ID: "d1", Status: "ACTIVE", LastSeen: now}},
		// Eskiden yeniye sıra (memstore append düzeni; sondan gezilir → en yeni).
		events: []EventRow{
			// dA: eski on/on, sonra yeni off/on → en son off/on (şifreleme ihlali)
			{DeviceID: "dA", Category: "SYSTEM", CreatedAt: now.Add(-time.Hour), Details: det("on", "on")},
			{DeviceID: "dA", Category: "SECURITY", CreatedAt: now, Details: det("off", "on")},
			// dB: fw=off
			{DeviceID: "dB", Category: "SECURITY", CreatedAt: now, Details: det("on", "off")},
			// dC: her ikisi kapalı → tek uyumsuz cihaz olarak sayılır
			{DeviceID: "dC", Category: "SECURITY", CreatedAt: now, Details: det("off", "off")},
			// dD: uyumlu
			{DeviceID: "dD", Category: "SYSTEM", CreatedAt: now, Details: det("on", "on")},
			// uyum-olayı olmayan (device_id yok / details yok) sayılmamalı
			{DeviceID: "", Category: "SYSTEM", CreatedAt: now, Details: det("off", "off")},
			{DeviceID: "dE", Category: "NETWORK_DISCOVERY", CreatedAt: now, Details: []byte(`{"ip":"1.2.3.4"}`)},
		},
	}
	svc := NewService(store, newCipher(t))
	sum, err := svc.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.ComplianceEncOff != 2 { // dA, dC
		t.Fatalf("şifreleme-kapalı 2 beklenirdi, %d", sum.ComplianceEncOff)
	}
	if sum.ComplianceFwOff != 2 { // dB, dC
		t.Fatalf("duvar-kapalı 2 beklenirdi, %d", sum.ComplianceFwOff)
	}
	if sum.NonCompliantDevices != 3 { // dA, dB, dC (dC bir kez)
		t.Fatalf("uyumsuz cihaz 3 beklenirdi, %d", sum.NonCompliantDevices)
	}
}

// Filo yazılım araması: eşleşen paketi taşıyan cihazlar (deşifre hostname +
// eşleşen paketler); cihaz başına yalnız en son envanter dikkate alınır.
func TestSoftwareSearch(t *testing.T) {
	cipher := newCipher(t)
	encHost := func(h string) []byte {
		b, err := cipher.EncryptString(h)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	now := time.Now()
	inv := func(pkgs string) []byte { return []byte(`{"software":[` + pkgs + `]}`) }
	store := &memStore{
		devices: []DeviceRow{
			{ID: "dA", HostnameEnc: encHost("host-A")},
			{ID: "dB", HostnameEnc: encHost("host-B")},
		},
		events: []EventRow{
			// dA: eski envanterde Chrome yok, yeni envanterde var → en son geçerli
			{DeviceID: "dA", CreatedAt: now.Add(-time.Hour), Details: inv(`"7-Zip"`)},
			{DeviceID: "dA", CreatedAt: now, Details: inv(`"Google Chrome","7-Zip"`)},
			// dB: sadece Firefox
			{DeviceID: "dB", CreatedAt: now, Details: inv(`"Mozilla Firefox"`)},
		},
	}
	svc := NewService(store, cipher)

	res, err := svc.SoftwareSearch(context.Background(), "chrome")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("1 cihaz eşleşmeliydi (dA), %d: %+v", len(res), res)
	}
	if res[0].DeviceID != "dA" || res[0].Hostname != "host-A" {
		t.Fatalf("dA/host-A beklenirdi: %+v", res[0])
	}
	if len(res[0].Matches) != 1 || res[0].Matches[0] != "Google Chrome" {
		t.Fatalf("eşleşen paket Google Chrome olmalı: %+v", res[0].Matches)
	}

	// Eşleşme yoksa boş.
	if res, _ := svc.SoftwareSearch(context.Background(), "nonexistent-xyz"); len(res) != 0 {
		t.Fatalf("eşleşme olmamalıydı: %+v", res)
	}
}

func TestAuditPassthrough(t *testing.T) {
	now := time.Now()
	store := &memStore{audit: []AuditRow{
		{ID: 2, AdminEmail: "op@x", Action: "QUARANTINE", TargetType: "device", TargetID: "dev-1", CreatedAt: now},
		{ID: 1, AdminEmail: "", Action: "CREATE_POLICY", TargetType: "policy", TargetID: "pol-1", CreatedAt: now},
	}}
	svc := NewService(store, newCipher(t))
	dtos, err := svc.Audit(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(dtos) != 2 {
		t.Fatalf("2 kayıt beklenirdi, %d", len(dtos))
	}
	if dtos[0].ID != 2 || dtos[0].AdminEmail != "op@x" || dtos[0].Action != "QUARANTINE" || dtos[0].TargetID != "dev-1" {
		t.Fatalf("denetim izi aynen dönmeliydi: %+v", dtos[0])
	}
	if dtos[1].AdminEmail != "" {
		t.Fatalf("çözülemeyen admin e-postası boş kalmalıydı: %+v", dtos[1])
	}
}

func TestDeviceDetail(t *testing.T) {
	cipher := newCipher(t)
	hostEnc, _ := cipher.EncryptString("WORKSTATION-07")
	macEnc, _ := cipher.EncryptString("aa:bb:cc:dd:ee:ff")

	delivered := time.Now()
	store := &memStore{
		devices: []DeviceRow{{
			ID: "dev-1", Status: "ACTIVE", AgentVersion: "0.1.0", OSPlatform: "windows",
			LastSeen: time.Now(), HostnameEnc: hostEnc, MACEnc: macEnc,
		}},
		certs: []CertRow{{
			Serial: "42", Fingerprint: "abcd", NotBefore: time.Now(), NotAfter: time.Now(), Revoked: false,
		}},
		commands: []CmdRow{
			{Type: "QUARANTINE", IssuedBy: "op1", CreatedAt: time.Now(), DeliveredAt: &delivered},
			{Type: "COLLECT_DIAGNOSTICS", IssuedBy: "op1", CreatedAt: time.Now(), DeliveredAt: nil},
		},
		polID:  "pol-1",
		polVer: "v3",
	}
	svc := NewService(store, cipher)

	detail, ok, err := svc.DeviceDetail(context.Background(), "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("cihaz bulunmalıydı")
	}
	if detail.Device.Hostname != "WORKSTATION-07" || detail.Device.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("şifreli alanlar deşifre edilmeliydi: %+v", detail.Device)
	}
	if len(detail.Certs) != 1 || detail.Certs[0].Serial != "42" || detail.Certs[0].Fingerprint != "abcd" {
		t.Fatalf("sertifikalar birleştirilmeliydi: %+v", detail.Certs)
	}
	if len(detail.Commands) != 2 || detail.Commands[0].Type != "QUARANTINE" {
		t.Fatalf("komut geçmişi birleştirilmeliydi: %+v", detail.Commands)
	}
	if detail.Commands[0].DeliveredAt == nil || detail.Commands[1].DeliveredAt != nil {
		t.Fatalf("delivered_at teslim durumunu yansıtmalı: %+v", detail.Commands)
	}
	if detail.AssignedPolicyID != "pol-1" || detail.AssignedPolicyVersion != "v3" {
		t.Fatalf("atanmış politika dönmeliydi: %+v", detail)
	}
}

func TestDeviceDetailNotFound(t *testing.T) {
	store := &memStore{}
	svc := NewService(store, newCipher(t))
	_, ok, err := svc.DeviceDetail(context.Background(), "yok")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("bulunamayan cihaz için ok=false beklenirdi")
	}
}

func TestEnrollmentTokensPassthrough(t *testing.T) {
	now := time.Now()
	store := &memStore{tokens: []EnrollmentTokenRow{
		{ID: "etok-2", CreatedByEmail: "op@x", ExpiresAt: now.Add(time.Hour), Used: false, CreatedAt: now},
		{ID: "etok-1", CreatedByEmail: "", ExpiresAt: now, Used: true, CreatedAt: now.Add(-time.Hour)},
	}}
	svc := NewService(store, newCipher(t))
	dtos, err := svc.EnrollmentTokens(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(dtos) != 2 {
		t.Fatalf("2 token beklenirdi, %d", len(dtos))
	}
	if dtos[0].ID != "etok-2" || dtos[0].CreatedByEmail != "op@x" || dtos[0].Used {
		t.Fatalf("token meta verisi aynen dönmeliydi: %+v", dtos[0])
	}
	if !dtos[1].Used || dtos[1].CreatedByEmail != "" {
		t.Fatalf("kullanılmış/çözülemeyen token doğru yansımalıydı: %+v", dtos[1])
	}
}

func TestEventsPassthrough(t *testing.T) {
	store := &memStore{events: []EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "HIGH", Message: "test", OccurredAt: time.Now(),
			Details: json.RawMessage(`{"pid":42}`)},
	}}
	svc := NewService(store, newCipher(t))
	dtos, err := svc.Events(context.Background(), "", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(dtos) != 1 || dtos[0].Message != "test" || dtos[0].Severity != "HIGH" {
		t.Fatalf("olaylar aynen dönmeliydi: %+v", dtos)
	}
	// Details ham JSON olarak aynen geçmeli.
	if string(dtos[0].Details) != `{"pid":42}` {
		t.Fatalf("details ham JSON olarak geçmeliydi: %q", string(dtos[0].Details))
	}
}

func TestEventsServerSideFilter(t *testing.T) {
	now := time.Now()
	store := &memStore{events: []EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "HIGH", Message: "a", OccurredAt: now},
		{ID: "e2", Category: "SYSTEM", Severity: "INFO", Message: "b", OccurredAt: now},
		{ID: "e3", Category: "SECURITY", Severity: "INFO", Message: "c", OccurredAt: now},
	}}
	svc := NewService(store, newCipher(t))

	// severity filtresi.
	high, err := svc.Events(context.Background(), "", "HIGH", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(high) != 1 || high[0].ID != "e1" {
		t.Fatalf("severity=HIGH yalnız e1 dönmeliydi: %+v", high)
	}

	// category filtresi.
	sec, err := svc.Events(context.Background(), "", "", "SECURITY", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sec) != 2 {
		t.Fatalf("category=SECURITY 2 olay dönmeliydi: %+v", sec)
	}

	// severity + category birlikte.
	both, err := svc.Events(context.Background(), "", "INFO", "SECURITY", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(both) != 1 || both[0].ID != "e3" {
		t.Fatalf("INFO+SECURITY yalnız e3 dönmeliydi: %+v", both)
	}
}

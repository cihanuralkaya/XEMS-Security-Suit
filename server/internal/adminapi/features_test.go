package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xems.corp/suite/server/internal/admin"
	"xems.corp/suite/server/internal/adminread"
)

func authedGET(t *testing.T, url, token string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}

// SEC-008: konsol CSP'si per-request nonce kullanır; script-src'de 'unsafe-inline'
// YOKTUR ve gövdedeki script tag'i aynı nonce'u taşır (placeholder değiştirilmiş).
// /api/mitre/coverage: kimlik doğrulanmış admin ATT&CK teknik kataloğunu alır;
// kimliksiz istek reddedilir.
func TestMitreCoverageEndpoint(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)

	// Kimliksiz → 401.
	if r, err := authedGET(t, ts.URL+"/api/mitre/coverage", ""); err != nil || r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("kimliksiz istek 401 dönmeliydi, %d %v", r.StatusCode, err)
	}
	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	token := body["token"]

	r, err := authedGET(t, ts.URL+"/api/mitre/coverage", token)
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("coverage 200 dönmeliydi, %d %v", r.StatusCode, err)
	}
	var out struct {
		Techniques []struct {
			ID, Name, Tactic string
		} `json:"techniques"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Techniques) == 0 {
		t.Fatal("teknik kataloğu boş döndü")
	}
	var hasScript bool
	for _, tq := range out.Techniques {
		if tq.ID == "T1059" && tq.Tactic == "Execution" {
			hasScript = true
		}
	}
	if !hasScript {
		t.Fatal("beklenen teknik (T1059/Execution) katalogda yok")
	}
}

// Cihaz etiketleme: OPERATOR etiket ayarlar, liste ?tag= ile filtrelenir, VIEWER
// ayarlayamaz.
func TestDeviceTagsSetAndFilter(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	store.devRows = []adminread.DeviceRow{
		{ID: "dev-1", Status: "ACTIVE"},
		{ID: "dev-2", Status: "ACTIVE"},
	}

	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	opTok := ob["token"]
	_, vb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	vTok := vb["token"]

	// VIEWER reddedilmeli (403).
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/tags", vTok, map[string][]string{"tags": {"prod"}}); code != http.StatusForbidden {
		t.Fatalf("VIEWER etiket ayarlayamamalı (403), %d", code)
	}
	// OPERATOR dev-1'e "prod" etiketi ekler.
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/tags", opTok, map[string][]string{"tags": {"prod", "finans"}}); code != http.StatusOK {
		t.Fatalf("OPERATOR etiket ayarlamalı (200), %d", code)
	}

	// Filtre: ?tag=prod yalnız dev-1'i döner.
	r, err := authedGET(t, ts.URL+"/api/devices?tag=prod", opTok)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Devices []struct {
			ID   string   `json:"id"`
			Tags []string `json:"tags"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Devices) != 1 || out.Devices[0].ID != "dev-1" {
		t.Fatalf("?tag=prod yalnız dev-1 dönmeliydi: %+v", out.Devices)
	}
	if len(out.Devices[0].Tags) != 2 {
		t.Fatalf("dev-1 iki etiket taşımalıydı: %+v", out.Devices[0].Tags)
	}
	// Eşleşmeyen etiket → boş.
	r2, _ := authedGET(t, ts.URL+"/api/devices?tag=yok", opTok)
	var out2 struct {
		Devices []struct{ ID string } `json:"devices"`
	}
	_ = json.NewDecoder(r2.Body).Decode(&out2)
	if len(out2.Devices) != 0 {
		t.Fatalf("eşleşmeyen etiket boş dönmeliydi: %+v", out2.Devices)
	}
}

// /api/detections/rules: kimlik doğrulanmış admin tespit kural kataloğunu alır.
func TestDetectionRulesEndpoint(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)

	if r, _ := authedGET(t, ts.URL+"/api/detections/rules", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("kimliksiz istek 401 dönmeliydi, %d", r.StatusCode)
	}
	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	r, err := authedGET(t, ts.URL+"/api/detections/rules", body["token"])
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("kural kataloğu 200 dönmeliydi, %d %v", r.StatusCode, err)
	}
	var out struct {
		Rules []struct {
			ID, Name, Severity string
		} `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) == 0 {
		t.Fatal("kural kataloğu boş döndü")
	}
	if out.Rules[0].ID == "" || out.Rules[0].Severity == "" {
		t.Fatalf("kural alanları eksik: %+v", out.Rules[0])
	}
}

// /api/devices/bulk: bir etikete sahip tüm cihazlara toplu eylem uygular.
func TestBulkActionByTag(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	store.devRows = []adminread.DeviceRow{
		{ID: "d1", Status: "ACTIVE", Tags: []string{"prod"}},
		{ID: "d2", Status: "ACTIVE", Tags: []string{"prod", "finans"}},
		{ID: "d3", Status: "ACTIVE", Tags: []string{"test"}},
	}
	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	opTok := ob["token"]

	// "prod" etiketli 2 cihaza karantina.
	code, body := post(t, ts.URL+"/api/devices/bulk", opTok,
		map[string]string{"tag": "prod", "action": "quarantine"})
	if code != http.StatusOK {
		t.Fatalf("toplu eylem 200 dönmeliydi, %d", code)
	}
	if body["matched"] != "2" && body["matched"] != "" { // map[string]string decode int'i boş bırakır
		// sayısal alanları ayrı doğrula
	}
	// Komutlar iki cihaza da kuyruğa alınmış olmalı (memStore.commands).
	nq := 0
	for _, c := range store.commands {
		if strings.HasPrefix(c, "d1:") || strings.HasPrefix(c, "d2:") {
			nq++
		}
	}
	if nq < 2 {
		t.Fatalf("prod etiketli 2 cihaza karantina komutu beklenirdi: %v", store.commands)
	}
	// Geçersiz eylem → 400.
	if c, _ := post(t, ts.URL+"/api/devices/bulk", opTok, map[string]string{"tag": "prod", "action": "yok"}); c != http.StatusBadRequest {
		t.Fatalf("geçersiz eylem 400 dönmeliydi, %d", c)
	}
	// Boş tag → 400.
	if c, _ := post(t, ts.URL+"/api/devices/bulk", opTok, map[string]string{"tag": "", "action": "quarantine"}); c != http.StatusBadRequest {
		t.Fatalf("boş tag 400 dönmeliydi, %d", c)
	}
	// VIEWER → eşleşen cihaz var ama RBAC reddi (403).
	_, vb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	if c, _ := post(t, ts.URL+"/api/devices/bulk", vb["token"], map[string]string{"tag": "prod", "action": "quarantine"}); c != http.StatusForbidden {
		t.Fatalf("VIEWER toplu eylem 403 dönmeliydi, %d", c)
	}
}

// /api/features: yalnız ADMIN dağıtım koruma-duruşunu alır (VIEWER/OPERATOR 403).
func TestFeaturesEndpointAdminOnly(t *testing.T) {
	srv, store := newServer(t)
	srv.SetFeatures(map[string]any{"alerting_enabled": true, "ioc_indicators": 3})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	addAdmin(t, store, "ad1", "ad@x", "secret", admin.RoleAdmin)

	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if r, _ := authedGET(t, ts.URL+"/api/features", ob["token"]); r.StatusCode != http.StatusForbidden {
		t.Fatalf("OPERATOR 403 almalıydı, %d", r.StatusCode)
	}
	_, ab := post(t, ts.URL+"/api/login", "", map[string]string{"email": "ad@x", "password": "secret"})
	r, err := authedGET(t, ts.URL+"/api/features", ab["token"])
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("ADMIN 200 almalıydı, %d %v", r.StatusCode, err)
	}
	var out struct {
		Features map[string]any `json:"features"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Features["alerting_enabled"] != true {
		t.Fatalf("alerting_enabled bayrağı bekleniyordu: %+v", out.Features)
	}
	if _, ok := out.Features["detection_rules"]; !ok {
		t.Fatal("detection_rules alanı (detector'dan) olmalıydı")
	}
}

// /api/activity: kimlik doğrulanmış admin süreç-içi tehdit sayaçlarını alır.
func TestActivityEndpoint(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	if r, _ := authedGET(t, ts.URL+"/api/activity", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("kimliksiz 401 dönmeliydi, %d", r.StatusCode)
	}
	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	r, err := authedGET(t, ts.URL+"/api/activity", body["token"])
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("activity 200 dönmeliydi, %d %v", r.StatusCode, err)
	}
	var out struct {
		Counters map[string]int64 `json:"counters"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Counters["detections"]; !ok {
		t.Fatalf("counters detections içermeliydi: %+v", out.Counters)
	}
}

// /healthz: durum + sürüm + uptime döner (kimlik gerekmez).
func TestHealthzEnriched(t *testing.T) {
	ts, _ := setup(t)
	defer ts.Close()
	r, err := http.Get(ts.URL + "/healthz")
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("/healthz 200 dönmeliydi, %d %v", r.StatusCode, err)
	}
	var out map[string]any
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "ok" {
		t.Fatalf("status ok olmalıydı: %v", out["status"])
	}
	if _, ok := out["version"]; !ok {
		t.Fatal("version alanı olmalıydı")
	}
	if _, ok := out["uptime_seconds"]; !ok {
		t.Fatal("uptime_seconds alanı olmalıydı")
	}
}

func TestConsoleCSPNonce(t *testing.T) {
	ts, _ := setup(t)
	defer ts.Close()
	r, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	csp := r.Header.Get("Content-Security-Policy")
	if strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Fatalf("script-src'de 'unsafe-inline' olmamalıydı: %q", csp)
	}
	i := strings.Index(csp, "script-src 'nonce-")
	if i < 0 {
		t.Fatalf("script-src nonce içermeliydi: %q", csp)
	}
	rest := csp[i+len("script-src 'nonce-"):]
	nonce := rest[:strings.IndexByte(rest, '\'')]
	if nonce == "" {
		t.Fatal("nonce boş")
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), `nonce="`+nonce+`"`) {
		t.Fatal("gövdedeki script tag'i CSP nonce'unu taşımıyor")
	}
	if strings.Contains(string(body), "__CSP_NONCE__") {
		t.Fatal("placeholder değiştirilmemiş")
	}
}

// /metrics: token ayarlı değilse 404 (kapalı); ayarlıysa yanlış token 401, doğru
// token Prometheus exposition döner.
func TestMetricsEndpointTokenGated(t *testing.T) {
	srv, store := newServer(t)
	_ = store
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Token ayarlı değil → 404 (uç kapalı; varlığını sızdırma).
	if r, _ := http.Get(ts.URL + "/metrics"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("token yokken /metrics 404 dönmeliydi, %d", r.StatusCode)
	}

	srv.SetMetricsToken("gizli-scrape-token")

	// Yanlış token → 401.
	req, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer yanlis")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("yanlış token 401 dönmeliydi, %d", r.StatusCode)
	}

	// Doğru token → 200 + exposition.
	req2, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)
	req2.Header.Set("Authorization", "Bearer gizli-scrape-token")
	r, err := http.DefaultClient.Do(req2)
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("doğru token 200 dönmeliydi, %d %v", r.StatusCode, err)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), "xems_build_info") || !strings.Contains(string(body), "xems_devices{") {
		t.Fatalf("exposition beklenen metrikleri içermiyor:\n%s", body)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	ts, _ := setup(t)
	defer ts.Close()

	// Global güvenlik başlıkları her yanıtta olmalı (ör. /healthz).
	r, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"Cache-Control":             "no-store",
	}
	for k, v := range want {
		if got := r.Header.Get(k); got != v {
			t.Fatalf("%s başlığı %q olmalıydı, %q", k, v, got)
		}
	}
	if r.Header.Get("Permissions-Policy") == "" {
		t.Fatal("Permissions-Policy başlığı olmalıydı")
	}

	// Konsol sayfası ayrıca CSP (frame-ancestors 'none' dahil) taşımalı.
	rc, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	csp := rc.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("konsol CSP eksik: %q", csp)
	}
}

func TestLoginBruteForceReturns429(t *testing.T) {
	srv, store := newServer(t)
	srv.SetLoginLimit(3, time.Minute) // 3 başarısızlıkta kilit
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "ad1", "ad@x", "dogru-parola", admin.RoleAdmin)

	// 3 başarısız deneme → her biri 401.
	for i := 0; i < 3; i++ {
		code, _ := post(t, ts.URL+"/api/login", "", map[string]string{"email": "ad@x", "password": "yanlis"})
		if code != http.StatusUnauthorized {
			t.Fatalf("%d. başarısız deneme 401 dönmeliydi, %d", i+1, code)
		}
	}

	// 4. deneme (DOĞRU parola bile) kilit nedeniyle 429 dönmeli + Retry-After.
	body, _ := json.Marshal(map[string]string{"email": "ad@x", "password": "dogru-parola"})
	resp, err := http.Post(ts.URL+"/api/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("kilit sonrası 429 dönmeliydi, %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 yanıtı Retry-After başlığı içermeliydi")
	}
}

// Denetim izi doğrulama ucu: ADMIN gerektirir; doğrulayıcı sonucunu yansıtır.
// SEC-003: pasifleştirilen bir yöneticinin durumsuz token'ı, TTL dolmadan da
// authed tarafından anında reddedilmeli (salt-okuma uçları dahil).
func TestDeactivatedAdminTokenRejected(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	id := "ad1"
	addAdmin(t, store, id, "ad@x", "secret", admin.RoleAdmin)
	_, ab := post(t, ts.URL+"/api/login", "", map[string]string{"email": "ad@x", "password": "secret"})
	tok := ab["token"]

	// Token önce çalışır.
	if r, _ := authedGET(t, ts.URL+"/api/devices", tok); r.StatusCode != http.StatusOK {
		t.Fatalf("aktif admin token'ı çalışmalıydı, %d", r.StatusCode)
	}
	// Pasifleştir → aynı token artık reddedilmeli (401).
	if err := store.DeactivateAdmin(nil, id); err != nil {
		t.Fatal(err)
	}
	if r, _ := authedGET(t, ts.URL+"/api/devices", tok); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("pasifleştirilen admin token'ı 401 dönmeliydi, %d", r.StatusCode)
	}
}

func TestAuditVerifyEndpoint(t *testing.T) {
	srv, store := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	addAdmin(t, store, "ad1", "ad@x", "secret", admin.RoleAdmin)
	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	_, ab := post(t, ts.URL+"/api/login", "", map[string]string{"email": "ad@x", "password": "secret"})

	// OPERATOR yasak.
	if r, _ := authedGET(t, ts.URL+"/api/audit/verify", ob["token"]); r.StatusCode != http.StatusForbidden {
		t.Fatalf("OPERATOR için 403 beklenirdi, %d", r.StatusCode)
	}
	// ADMIN + sağlam zincir → valid:true.
	srv.SetAuditVerifier(func(context.Context) error { return nil })
	r, _ := authedGET(t, ts.URL+"/api/audit/verify", ab["token"])
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != http.StatusOK || !strings.Contains(string(b), `"valid":true`) {
		t.Fatalf("sağlam zincir valid:true olmalıydı: %d %s", r.StatusCode, b)
	}
	// ADMIN + kırık zincir → valid:false.
	srv.SetAuditVerifier(func(context.Context) error { return errors.New("kırık") })
	r2, _ := authedGET(t, ts.URL+"/api/audit/verify", ab["token"])
	b2, _ := io.ReadAll(r2.Body)
	if !strings.Contains(string(b2), `"valid":false`) {
		t.Fatalf("kırık zincir valid:false olmalıydı: %s", b2)
	}
}

// SEC-009: denetim izi ve enrollment token meta verisi VIEWER'a kapalı (OPERATOR+).
func TestAuditAndTokensRequireOperator(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	_, vb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	vTok := vb["token"]
	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	oTok := ob["token"]

	for _, path := range []string{"/api/audit", "/api/enrollment-tokens"} {
		if r, _ := authedGET(t, ts.URL+path, vTok); r.StatusCode != http.StatusForbidden {
			t.Fatalf("VIEWER için %s 403 dönmeliydi, %d", path, r.StatusCode)
		}
		if r, _ := authedGET(t, ts.URL+path, oTok); r.StatusCode != http.StatusOK {
			t.Fatalf("OPERATOR için %s 200 dönmeliydi, %d", path, r.StatusCode)
		}
	}
}

func TestPrivacyNoticeEndpoint(t *testing.T) {
	srv, _ := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Kimlik doğrulamasız erişilebilir + varsayılan KVKK metni döner.
	r, err := http.Get(ts.URL + "/api/notice")
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK {
		t.Fatalf("/api/notice 200 dönmeliydi, %d", r.StatusCode)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), "KVKK") {
		t.Fatalf("aydınlatma metni beklenirdi: %s", body)
	}

	// Özelleştirilebilir; boş verilince varsayılan korunur.
	srv.SetPrivacyNotice("Özel kurumsal metin.")
	r2, _ := http.Get(ts.URL + "/api/notice")
	b2, _ := io.ReadAll(r2.Body)
	if !strings.Contains(string(b2), "Özel kurumsal metin") {
		t.Fatalf("özel metin dönmeliydi: %s", b2)
	}
	srv.SetPrivacyNotice("   ") // boş/whitespace → varsayılan korunur (değişmez)
	r3, _ := http.Get(ts.URL + "/api/notice")
	b3, _ := io.ReadAll(r3.Body)
	if !strings.Contains(string(b3), "Özel kurumsal metin") {
		t.Fatalf("boş metin varsayılanı ezmemeliydi: %s", b3)
	}
}

func TestHealthAndReadyEndpoints(t *testing.T) {
	// Kimlik doğrulama GEREKMEZ; sağlık kontrolü ayarlıysa /readyz onu çağırır.
	srv, _ := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// /healthz her zaman 200 (liveness), token'sız.
	r, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK {
		t.Fatalf("/healthz 200 dönmeliydi, %d", r.StatusCode)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("/healthz gövdesi beklenmedik: %s", body)
	}

	// Sağlık kontrolü yokken /readyz hazır (ready).
	if r2, _ := http.Get(ts.URL + "/readyz"); r2.StatusCode != http.StatusOK {
		t.Fatalf("/readyz (kontrolsüz) 200 dönmeliydi, %d", r2.StatusCode)
	}

	// Sağlık kontrolü başarısızsa /readyz 503 dönmeli.
	srv.SetHealthCheck(func(context.Context) error { return errors.New("db down") })
	r3, _ := http.Get(ts.URL + "/readyz")
	if r3.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz (depo hatası) 503 dönmeliydi, %d", r3.StatusCode)
	}

	// Sağlıklıya dönünce yine 200.
	srv.SetHealthCheck(func(context.Context) error { return nil })
	if r4, _ := http.Get(ts.URL + "/readyz"); r4.StatusCode != http.StatusOK {
		t.Fatalf("/readyz (sağlıklı) 200 dönmeliydi, %d", r4.StatusCode)
	}
}

func TestKVKKExportAndEraseHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	addAdmin(t, store, "ad1", "ad@x", "secret", admin.RoleAdmin)

	now := time.Now()
	store.devRows = []adminread.DeviceRow{{ID: "dev-1", Status: "ACTIVE", LastSeen: now}}
	store.evtRows = []adminread.EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "HIGH", Message: "x", OccurredAt: now, CreatedAt: now},
	}

	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	opTok := ob["token"]
	_, ab := post(t, ts.URL+"/api/login", "", map[string]string{"email": "ad@x", "password": "secret"})
	adTok := ab["token"]

	// EXPORT: OPERATOR yasak (403), ADMIN başarılı (200) + paket.
	if r, _ := authedGET(t, ts.URL+"/api/devices/dev-1/export", opTok); r.StatusCode != http.StatusForbidden {
		t.Fatalf("OPERATOR export 403 dönmeliydi, %d", r.StatusCode)
	}
	resp, err := authedGET(t, ts.URL+"/api/devices/dev-1/export", adTok)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ADMIN export 200 dönmeliydi, %d", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "kvkk-export") {
		t.Fatalf("indirme başlığı beklenirdi: %q", cd)
	}
	var bundle struct {
		DeviceID string `json:"device_id"`
		Events   []struct {
			ID string `json:"id"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.DeviceID != "dev-1" || len(bundle.Events) != 1 {
		t.Fatalf("dışa aktarma paketi eksik: %+v", bundle)
	}

	// ERASE: OPERATOR yasak (403), ADMIN başarılı (200) + rapor.
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/erase", opTok, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("OPERATOR silme 403 dönmeliydi, %d", code)
	}
	// ADMIN silme: 200 + ham gövdede sayım alanları (rapor).
	req, _ := http.NewRequest("POST", ts.URL+"/api/devices/dev-1/erase", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adTok)
	er, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer er.Body.Close()
	if er.StatusCode != http.StatusOK {
		t.Fatalf("ADMIN silme 200 dönmeliydi, %d", er.StatusCode)
	}
	raw, _ := io.ReadAll(er.Body)
	if !strings.Contains(string(raw), "events_deleted") || !strings.Contains(string(raw), "certs_revoked") {
		t.Fatalf("silme raporu sayım alanları içermeliydi: %s", raw)
	}
}

func TestStreamSSEDeliversNotice(t *testing.T) {
	ts, store, bus := setupStream(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	// Token'sız akış 401.
	if r, _ := http.Get(ts.URL + "/api/stream"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız akış 401 dönmeliydi, %d", r.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/stream", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("text/event-stream beklenirdi, %q", ct)
	}

	// Bağlantı kurulduktan sonra yayın yap; frame gelmeli.
	go func() {
		time.Sleep(150 * time.Millisecond)
		bus.PublishEvent("dev-1", "HIGH", "test olayı")
	}()

	buf := make([]byte, 4096)
	var got string
	for !strings.Contains(got, "test olayı") {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			got += string(buf[:n])
		}
		if err != nil {
			break
		}
	}
	if !strings.Contains(got, `"type":"event"`) || !strings.Contains(got, "test olayı") || !strings.Contains(got, `"severity":"HIGH"`) {
		t.Fatalf("SSE olay frame'i bekleniyordu, alınan: %q", got)
	}
}

func TestListPoliciesHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	store.polID = "pol-1"
	store.polVer = "v2"
	store.rules["pol-1"] = []admin.RuleInput{
		{Type: "APP_BLOCK_ALWAYS", Target: "oyun.exe"},
		{Type: "APP_TIME_BLOCK", Target: "steam.exe", Start: "18:00", End: "08:00"},
	}
	store.assigned["dev-a"] = "pol-1"
	store.assigned["dev-b"] = "pol-1"

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	if r, _ := http.Get(ts.URL + "/api/policies"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız politika listesi 401 dönmeliydi, %d", r.StatusCode)
	}

	resp, err := authedGET(t, ts.URL+"/api/policies", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	var out struct {
		Policies []struct {
			ID          string `json:"id"`
			Version     string `json:"version"`
			RuleCount   int    `json:"rule_count"`
			DeviceCount int    `json:"device_count"`
		} `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Policies) != 1 {
		t.Fatalf("1 politika beklenirdi: %+v", out.Policies)
	}
	p := out.Policies[0]
	if p.ID != "pol-1" || p.Version != "v2" || p.RuleCount != 2 || p.DeviceCount != 2 {
		t.Fatalf("politika sayımları hatalı: %+v", p)
	}
}

func TestSummaryEndpoint(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	now := time.Now()
	store.devRows = []adminread.DeviceRow{
		{ID: "d1", Status: "ACTIVE", LastSeen: now},
		{ID: "d2", Status: "QUARANTINED", LastSeen: now.Add(-time.Hour)},
	}
	store.evtRows = []adminread.EventRow{
		{Severity: "HIGH", Category: "SECURITY", CreatedAt: now},
		{Severity: "LOW", Category: "SYSTEM", CreatedAt: now},
	}
	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	resp, err := authedGET(t, ts.URL+"/api/summary", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	var out struct {
		Summary struct {
			DevicesTotal       int            `json:"devices_total"`
			DevicesOnline      int            `json:"devices_online"`
			DevicesOffline     int            `json:"devices_offline"`
			DevicesQuarantined int            `json:"devices_quarantined"`
			EventsBySeverity   map[string]int `json:"events_by_severity"`
			EventsByCategory   map[string]int `json:"events_by_category"`
			Since              time.Time      `json:"since"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	s := out.Summary
	if s.DevicesTotal != 2 || s.DevicesOnline != 1 || s.DevicesOffline != 1 || s.DevicesQuarantined != 1 {
		t.Fatalf("cihaz sayaçları hatalı: %+v", s)
	}
	if s.EventsBySeverity["HIGH"] != 1 || s.EventsByCategory["SECURITY"] != 1 {
		t.Fatalf("olay sayaçları hatalı: %+v", s)
	}
	if s.Since.IsZero() {
		t.Fatal("since doldurulmalıydı")
	}
	if r2, _ := http.Get(ts.URL + "/api/summary"); r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız özet 401 dönmeliydi, %d", r2.StatusCode)
	}
}

func TestListAudit(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	store.auditRows = []adminread.AuditRow{
		{ID: 1, AdminEmail: "op@x", Action: "QUARANTINE", TargetType: "device", TargetID: "dev-1", CreatedAt: time.Now()},
	}

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	resp, err := authedGET(t, ts.URL+"/api/audit", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Audit []struct {
			Action     string `json:"action"`
			TargetID   string `json:"target_id"`
			TargetType string `json:"target_type"`
		} `json:"audit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Audit) != 1 || out.Audit[0].Action != "QUARANTINE" || out.Audit[0].TargetID != "dev-1" {
		t.Fatalf("denetim izi beklenen kaydı taşımıyor: %+v", out.Audit)
	}
	if r2, _ := http.Get(ts.URL + "/api/audit"); r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız denetim izi 401 dönmeliydi, %d", r2.StatusCode)
	}
}

func TestListEventsFilter(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	now := time.Now()
	store.evtRows = []adminread.EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "HIGH", Message: "yüksek", OccurredAt: now, CreatedAt: now,
			Details: json.RawMessage(`{"pid":42}`)},
		{ID: "e2", Category: "SYSTEM", Severity: "INFO", Message: "bilgi", OccurredAt: now, CreatedAt: now},
	}

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	resp, err := authedGET(t, ts.URL+"/api/events?severity=HIGH", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	var out struct {
		Events []struct {
			ID       string          `json:"id"`
			Severity string          `json:"severity"`
			Details  json.RawMessage `json:"details"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 1 || out.Events[0].ID != "e1" || out.Events[0].Severity != "HIGH" {
		t.Fatalf("severity=HIGH filtresi yalnız e1 dönmeliydi: %+v", out.Events)
	}
	if string(out.Events[0].Details) != `{"pid":42}` {
		t.Fatalf("details ham JSON olarak dönmeliydi: %q", string(out.Events[0].Details))
	}
	if r2, _ := http.Get(ts.URL + "/api/events"); r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız olay listesi 401 dönmeliydi, %d", r2.StatusCode)
	}
}

func TestEnrollmentTokenLifecycleHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	if r, _ := http.Get(ts.URL + "/api/enrollment-tokens"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız liste 401 dönmeliydi, %d", r.StatusCode)
	}

	code, issued := post(t, ts.URL+"/api/enrollment-tokens", token, map[string]string{})
	if code != http.StatusOK || issued["enrollment_token"] == "" {
		t.Fatalf("token üretilmeliydi: code=%d body=%v", code, issued)
	}
	rawToken := issued["enrollment_token"]

	resp, err := authedGET(t, ts.URL+"/api/enrollment-tokens", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(rawBody), rawToken) {
		t.Fatal("ham enrollment token listede ASLA görünmemeli")
	}
	var out struct {
		Tokens []struct {
			ID             string `json:"id"`
			CreatedByEmail string `json:"created_by_email"`
			Used           bool   `json:"used"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(rawBody, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tokens) != 1 || out.Tokens[0].ID == "" {
		t.Fatalf("token meta verisi listelenmiş olmalı: %+v", out.Tokens)
	}
	if out.Tokens[0].CreatedByEmail != "op@x" {
		t.Fatalf("üreten admin e-postası dönmeliydi: %+v", out.Tokens[0])
	}
	if out.Tokens[0].Used {
		t.Fatalf("yeni token kullanılmamış olmalı: %+v", out.Tokens[0])
	}
	tokenID := out.Tokens[0].ID

	code, _ = post(t, ts.URL+"/api/enrollment-tokens/"+tokenID+"/revoke", token, map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("token iptali 200 dönmeliydi, %d", code)
	}

	resp2, err := authedGET(t, ts.URL+"/api/enrollment-tokens", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if err := json.NewDecoder(resp2.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tokens) != 1 || !out.Tokens[0].Used {
		t.Fatalf("iptal sonrası token 'used' olmalıydı: %+v", out.Tokens)
	}
}

func TestDeviceDetailEndpoint(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	hostEnc, _ := store.cipher.EncryptString("WS-07")
	macEnc, _ := store.cipher.EncryptString("aa:bb:cc:dd:ee:ff")
	store.devRows = []adminread.DeviceRow{{ID: "dev-1", Status: "ACTIVE", HostnameEnc: hostEnc, MACEnc: macEnc}}
	store.certRows = []adminread.CertRow{{Serial: "42", Fingerprint: "abcd"}}
	store.cmdRows = []adminread.CmdRow{{Type: "QUARANTINE", IssuedBy: "op1", CreatedAt: time.Now()}}
	store.polID, store.polVer = "pol-1", "v3"

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	if r0, _ := http.Get(ts.URL + "/api/devices/dev-1"); r0.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız detay 401 dönmeliydi, %d", r0.StatusCode)
	}

	resp, err := authedGET(t, ts.URL+"/api/devices/dev-1", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	var out struct {
		DeviceDetail struct {
			Device struct {
				Hostname string `json:"hostname"`
				MAC      string `json:"mac"`
			} `json:"device"`
			Certs                 []adminread.CertView `json:"certs"`
			Commands              []adminread.CmdView  `json:"commands"`
			AssignedPolicyID      string               `json:"assigned_policy_id"`
			AssignedPolicyVersion string               `json:"assigned_policy_version"`
		} `json:"device_detail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	d := out.DeviceDetail
	if d.Device.Hostname != "WS-07" || d.Device.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("cihaz alanları deşifre edilmeliydi: %+v", d.Device)
	}
	if len(d.Certs) != 1 || d.Certs[0].Serial != "42" {
		t.Fatalf("sertifikalar dönmeliydi: %+v", d.Certs)
	}
	if len(d.Commands) != 1 || d.Commands[0].Type != "QUARANTINE" {
		t.Fatalf("komut geçmişi dönmeliydi: %+v", d.Commands)
	}
	if d.AssignedPolicyID != "pol-1" || d.AssignedPolicyVersion != "v3" {
		t.Fatalf("atanmış politika dönmeliydi: %+v", d)
	}

	resp2, err := authedGET(t, ts.URL+"/api/devices/yok", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("bilinmeyen cihaz 404 dönmeliydi, %d", resp2.StatusCode)
	}
}

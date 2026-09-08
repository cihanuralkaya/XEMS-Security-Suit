// Package e2e, C2 sunucu yığınının uçtan-uca entegrasyon testidir.
//
// Gerçek TCP dinleyiciler + gerçek mTLS gRPC + gerçek enroll/agent handler'lar
// + bellek-içi store ile şu akışı KANITLAR: enroll → mTLS heartbeat → olay
// gönderimi (ack) → tek-kullanımlık token. PostgreSQL veya harici süreç gerekmez.
//
// Not: agent/internal/transport bir "internal" paket olduğundan buradan
// (server/ ağacı) import edilemez; bu yüzden istemci CSR üretimi ve mTLS dial
// bu testte satır içi tekrarlanır — sunucu yığını ise gerçek koddur.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	xemsv1 "xems.corp/suite/gen/xems/v1"
	"xems.corp/suite/otawire"
	"xems.corp/suite/server/internal/enroll"
	xgrpc "xems.corp/suite/server/internal/grpc"
	"xems.corp/suite/server/internal/model"
	"xems.corp/suite/server/internal/ota"
	"xems.corp/suite/server/internal/policypush"
	"xems.corp/suite/server/internal/revocation"
	"xems.corp/suite/server/internal/security"
)

const serverName = "xems-c2"

func TestEndToEnd(t *testing.T) {
	caCertPEM, caKeyPEM := makeCA(t)
	srvCertPEM, srvKeyPEM := makeServerCert(t, caCertPEM, caKeyPEM)

	// Güvenlik ilkelleri (ana anahtardan türetilir).
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewFieldCipher(security.DeriveKey(master, security.LabelFieldEncryption))
	if err != nil {
		t.Fatal(err)
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(master, security.LabelBlindIndex))
	ca, err := security.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Bellek-içi store + önceden bir enrollment token.
	store := newMemStore()
	token := "E2E-TOKEN"
	store.addToken(bidx.Compute("enroll-token:" + token))

	// Handler'lar + iki gRPC sunucu.
	enrollSvc := enroll.NewService(store, ca, bidx, cipher, caCertPEM, time.Hour)
	tlsMat := xgrpc.TLSMaterial{ServerCertPEM: srvCertPEM, ServerKeyPEM: srvKeyPEM, ClientCAPEM: caCertPEM}
	enrollSrv, err := xgrpc.NewEnrollServer(tlsMat, xgrpc.NewEnrollmentHandler(enrollSvc))
	if err != nil {
		t.Fatal(err)
	}
	revCache := revocation.NewCache()
	tlsMat.Revocation = revCache
	notifier := policypush.New()
	agentSrv, err := xgrpc.NewAgentServer(tlsMat, xgrpc.NewAgentHandler(store, store, store, store, notifier))
	if err != nil {
		t.Fatal(err)
	}

	enrollLis := mustListen(t)
	agentLis := mustListen(t)
	go func() { _ = enrollSrv.Serve(enrollLis) }()
	go func() { _ = agentSrv.Serve(agentLis) }()
	defer enrollSrv.Stop()
	defer agentSrv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// --- 1) ENROLL (tek yönlü TLS) ---
	agentKeyPEM, csrPEM := genKeyCSR(t)
	enrollResp := doEnroll(t, ctx, enrollLis.Addr().String(), caCertPEM, token, csrPEM)
	if enrollResp.GetDeviceId() == "" {
		t.Fatal("enroll device_id boş döndü")
	}
	if len(enrollResp.GetClientCertPem()) == 0 {
		t.Fatal("enroll istemci sertifikası döndürmedi")
	}
	t.Logf("enroll OK: device_id=%s", enrollResp.GetDeviceId())

	// --- 1.5) SERTİFİKA YENİLEME (mTLS ile, token'sız) ---
	renewCli, renewConn := dialEnrollMTLS(t, enrollLis.Addr().String(), enrollResp.GetClientCertPem(), agentKeyPEM, caCertPEM)
	_, renewCSR := genKeyCSR(t)
	renewResp, err := renewCli.RenewCertificate(ctx, &xemsv1.RenewRequest{CsrPem: renewCSR})
	renewConn.Close()
	if err != nil {
		t.Fatalf("yenileme başarısız: %v", err)
	}
	if renewResp.GetDeviceId() != enrollResp.GetDeviceId() {
		t.Fatalf("yenileme aynı device_id'yi korumalı: %s != %s", renewResp.GetDeviceId(), enrollResp.GetDeviceId())
	}
	rBlock, _ := pem.Decode(renewResp.GetClientCertPem())
	rCert, err := x509.ParseCertificate(rBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if rCert.Subject.CommonName != enrollResp.GetDeviceId() {
		t.Fatalf("yenilenen sertifika CN'i device_id olmalı: %s", rCert.Subject.CommonName)
	}
	t.Log("yenileme OK: yeni sertifika aynı kimlikle imzalandı")

	// Sertifikasız (token'sız) yenileme reddedilmeli: enroll'a mTLS'siz bağlan.
	noCertConn, err := grpc.NewClient(enrollLis.Addr().String(), grpc.WithTransportCredentials(
		credentials.NewTLS(&tls.Config{RootCAs: certPool(caCertPEM), ServerName: serverName, MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	_, err = xemsv1.NewEnrollmentServiceClient(noCertConn).RenewCertificate(ctx, &xemsv1.RenewRequest{CsrPem: renewCSR})
	noCertConn.Close()
	if err == nil {
		t.Fatal("istemci sertifikası olmadan yenileme reddedilmeliydi")
	}
	t.Log("yenileme kimlik kapısı OK: sertifikasız istek reddedildi")

	// --- 2) mTLS DIAL + HEARTBEAT ---
	cli, conn := dialAgent(t, agentLis.Addr().String(), enrollResp.GetClientCertPem(), agentKeyPEM, caCertPEM)
	defer conn.Close()

	hb, err := cli.Heartbeat(ctx, &xemsv1.HeartbeatRequest{
		Identity:             &xemsv1.AgentIdentity{DeviceId: enrollResp.GetDeviceId(), AgentVersion: "test", OsPlatform: "test"},
		CurrentPolicyVersion: "",
	})
	if err != nil {
		t.Fatalf("heartbeat başarısız: %v", err)
	}
	if hb.GetServerTime() == nil {
		t.Fatal("heartbeat sunucu saati (server_time) döndürmedi")
	}
	t.Logf("heartbeat OK: server_time=%s", hb.GetServerTime().AsTime())

	// --- 3) OLAY GÖNDERİMİ (store-and-forward + ack) ---
	stream, err := cli.ReportEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&xemsv1.EventBatch{
		Identity: &xemsv1.AgentIdentity{DeviceId: enrollResp.GetDeviceId()},
		Events: []*xemsv1.Event{{
			Sequence:   1,
			Category:   xemsv1.EventCategory_EVENT_CATEGORY_SECURITY,
			Severity:   xemsv1.Severity_SEVERITY_HIGH,
			Message:    "e2e test olayı",
			OccurredAt: timestamppb.New(time.Now()),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatal(err)
	}
	if ack.GetLastAcceptedSequence() != 1 {
		t.Fatalf("ack sırası 1 beklenirdi, %d", ack.GetLastAcceptedSequence())
	}
	if got := store.eventCount(); got != 1 {
		t.Fatalf("store'da 1 olay beklenirdi, %d", got)
	}
	// Kimlik mTLS sertifikasından alınmalı: kaydedilen olay doğru device_id'de mi?
	if store.eventsFor(enrollResp.GetDeviceId()) != 1 {
		t.Fatal("olay, sertifikadan çıkarılan device_id'ye yazılmadı")
	}
	t.Logf("olay OK: ack=%d, store'da kayıtlı", ack.GetLastAcceptedSequence())

	// --- 3.5) POLİTİKA DAĞITIMI (StreamPolicies) ---
	store.setPolicy(&xemsv1.PolicyBundle{
		PolicyVersion: "v1",
		Rules: []*xemsv1.PolicyRule{{
			RuleId:      "r1",
			Type:        xemsv1.PolicyRule_RULE_TYPE_APP_TIME_BLOCK,
			TargetValue: "game.exe",
			StartTime:   "18:00",
			EndTime:     "08:00",
			ActiveDays:  []uint32{1, 2, 3, 4, 5},
		}},
	})
	// Uzun-ömürlü akış: kendi iptal edilebilir context'i.
	psCtx, psCancel := context.WithCancel(ctx)
	defer psCancel()
	ps, err := cli.StreamPolicies(psCtx, &xemsv1.PolicySubscribeRequest{
		Identity: &xemsv1.AgentIdentity{DeviceId: enrollResp.GetDeviceId()}, CurrentPolicyVersion: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ps.Recv()
	if err != nil {
		t.Fatalf("politika alınamadı: %v", err)
	}
	if bundle.GetPolicyVersion() != "v1" || len(bundle.GetRules()) != 1 || bundle.GetRules()[0].GetTargetValue() != "game.exe" {
		t.Fatalf("beklenmeyen politika paketi: %+v", bundle)
	}
	t.Logf("politika OK (ilk): sürüm=%s, kural=%d", bundle.GetPolicyVersion(), len(bundle.GetRules()))

	// ANLIK PUSH: politika v2'ye güncellenip Publish edilince akış hemen almalı.
	// (İlk paketi aldığımıza göre sunucu tarafı abonelik aktif.)
	store.setPolicy(&xemsv1.PolicyBundle{PolicyVersion: "v2"})
	notifier.Publish(enrollResp.GetDeviceId())
	pushed, err := ps.Recv()
	if err != nil {
		t.Fatalf("push paketi alınamadı: %v", err)
	}
	if pushed.GetPolicyVersion() != "v2" {
		t.Fatalf("push v2 olmalıydı: %s", pushed.GetPolicyVersion())
	}
	t.Log("politika push OK: v2 anında itildi")
	psCancel() // akışı kapat

	// --- 3.6) OTA: İMZALI GÜNCELLEME MANİFESTOSU (CheckUpdate) ---
	otaPub, otaPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ota.NewSigner(otaPriv)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("XEMS agent 1.4.0 ikilisi")
	man := otawire.Manifest{
		TargetVersion: "1.4.0",
		SHA256Hex:     ota.SHA256Hex(payload),
		DownloadURL:   "https://c2/updates/1.4.0",
		Mandatory:     false,
	}
	store.setUpdate(&xemsv1.UpdateManifest{
		UpdateAvailable: true,
		TargetVersion:   man.TargetVersion,
		DownloadUrl:     man.DownloadURL,
		Sha256Hex:       man.SHA256Hex,
		Signature:       signer.Sign(man),
		Mandatory:       man.Mandatory,
		RolloutPercent:  100, // tam dağıtım
	})
	upd, err := cli.CheckUpdate(ctx, &xemsv1.UpdateCheckRequest{
		Identity: &xemsv1.AgentIdentity{DeviceId: enrollResp.GetDeviceId(), AgentVersion: "0.1.0-dev", OsPlatform: "test"},
	})
	if err != nil || !upd.GetUpdateAvailable() {
		t.Fatalf("güncelleme dönmedi: %v", err)
	}
	// Ajanın yapacağı doğrulama: imza gömülü public key ile geçmeli.
	recon := otawire.Manifest{TargetVersion: upd.GetTargetVersion(), SHA256Hex: upd.GetSha256Hex(), DownloadURL: upd.GetDownloadUrl(), Mandatory: upd.GetMandatory()}
	if !ed25519.Verify(otaPub, otawire.CanonicalBytes(recon), upd.GetSignature()) {
		t.Fatal("imzalı manifesto ajan tarafında doğrulanamadı")
	}
	// Saldırgan URL'yi değiştirirse imza tutmamalı.
	recon.DownloadURL = "https://evil/payload"
	if ed25519.Verify(otaPub, otawire.CanonicalBytes(recon), upd.GetSignature()) {
		t.Fatal("değiştirilmiş manifesto imzası doğrulanmamalıydı")
	}
	t.Logf("OTA OK: imzalı manifesto doğrulandı (sürüm=%s), değiştirilmiş reddedildi", upd.GetTargetVersion())

	// Kademeli dağıtım kapısı: rollout %0 iken bu cihaza güncelleme SUNULMAMALI.
	store.setUpdate(&xemsv1.UpdateManifest{
		UpdateAvailable: true, TargetVersion: "1.4.0", DownloadUrl: man.DownloadURL,
		Sha256Hex: man.SHA256Hex, Signature: signer.Sign(man), RolloutPercent: 0,
	})
	gated, err := cli.CheckUpdate(ctx, &xemsv1.UpdateCheckRequest{
		Identity: &xemsv1.AgentIdentity{DeviceId: enrollResp.GetDeviceId(), OsPlatform: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gated.GetUpdateAvailable() {
		t.Fatal("rollout %0 iken güncelleme sunulmamalıydı")
	}
	t.Log("rollout OK: %0 dağıtımda güncelleme sunulmadı")

	// --- 3.7) KOMUT TESLİMİ (karantina) — heartbeat üzerinden, en-fazla-bir-kez ---
	store.enqueueCmd(&xemsv1.Command{CommandId: "c1", Type: xemsv1.Command_COMMAND_TYPE_QUARANTINE})
	hb2, err := cli.Heartbeat(ctx, &xemsv1.HeartbeatRequest{
		Identity: &xemsv1.AgentIdentity{DeviceId: enrollResp.GetDeviceId()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hb2.GetPendingCommands()) != 1 || hb2.GetPendingCommands()[0].GetType() != xemsv1.Command_COMMAND_TYPE_QUARANTINE {
		t.Fatalf("QUARANTINE komutu teslim edilmeliydi: %+v", hb2.GetPendingCommands())
	}
	// Aynı komut ikinci heartbeat'te TEKRAR gelmemeli (en-fazla-bir-kez).
	hb3, err := cli.Heartbeat(ctx, &xemsv1.HeartbeatRequest{Identity: &xemsv1.AgentIdentity{DeviceId: enrollResp.GetDeviceId()}})
	if err != nil {
		t.Fatal(err)
	}
	if len(hb3.GetPendingCommands()) != 0 {
		t.Fatalf("komut yalnız bir kez teslim edilmeliydi, tekrar geldi: %+v", hb3.GetPendingCommands())
	}
	t.Log("komut teslimi OK: QUARANTINE bir kez teslim edildi")

	// --- 4) TEK-KULLANIMLIK TOKEN: aynı token ikinci kez reddedilmeli ---
	_, csr2 := genKeyCSR(t)
	if _, err := doEnrollErr(ctx, enrollLis.Addr().String(), caCertPEM, token, csr2); err == nil {
		t.Fatal("ikinci enroll (aynı token) reddedilmeliydi")
	}
	t.Log("tek-kullanımlık token OK: ikinci deneme reddedildi")

	// --- 5) SERTİFİKA İPTALİ: iptal edilen sertifikayla yeni bağlantı reddedilmeli ---
	certBlock, _ := pem.Decode(enrollResp.GetClientCertPem())
	fp := sha256.Sum256(certBlock.Bytes)
	revCache.Replace([][]byte{fp[:]})

	revokedCli, revokedConn := dialAgent(t, agentLis.Addr().String(), enrollResp.GetClientCertPem(), agentKeyPEM, caCertPEM)
	defer revokedConn.Close()
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rcancel()
	if _, err := revokedCli.Heartbeat(rctx, &xemsv1.HeartbeatRequest{
		Identity: &xemsv1.AgentIdentity{DeviceId: enrollResp.GetDeviceId()},
	}); err == nil {
		t.Fatal("iptal edilmiş sertifikayla bağlantı reddedilmeliydi")
	}
	t.Log("iptal OK: iptal edilen sertifikayla yeni mTLS bağlantısı reddedildi")
}

// --- Bellek-içi store (tüm sunucu-tarafı depolama arayüzlerini karşılar) ---

type memStore struct {
	mu       sync.Mutex
	tokens   map[string]bool
	used     map[string]bool
	devices  map[string]bool
	events   map[string]int
	policy   *xemsv1.PolicyBundle
	update   *xemsv1.UpdateManifest
	pendCmds []*xemsv1.Command
	seq      int
}

func newMemStore() *memStore {
	return &memStore{tokens: map[string]bool{}, used: map[string]bool{}, devices: map[string]bool{}, events: map[string]int{}}
}

func (m *memStore) addToken(idx []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[string(idx)] = true
}

func (m *memStore) ConsumeEnrollmentToken(_ context.Context, idx []byte, _ time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := string(idx)
	if !m.tokens[k] || m.used[k] {
		return "", enroll.ErrInvalidToken
	}
	m.used[k] = true
	return "", nil
}

func (m *memStore) UpsertEnrollingDevice(_ context.Context, in enroll.DeviceEnrollment) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := in.PreferredDeviceID
	if id == "" {
		m.seq++
		id = "dev-" + itoa(m.seq)
	}
	m.devices[id] = true
	return id, nil
}

func (m *memStore) SaveCertificate(_ context.Context, _ enroll.CertRecord) error { return nil }
func (m *memStore) DeviceHasActiveCert(_ context.Context, _ string) (bool, error) {
	return true, nil // e2e yenileme-iptal senaryosunu test etmez; aktif kabul
}

func (m *memStore) TouchHeartbeat(_ context.Context, deviceID, _, _ string, _ time.Time) (string, error) {
	return "", nil
}

func (m *memStore) enqueueCmd(c *xemsv1.Command) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendCmds = append(m.pendCmds, c)
}

func (m *memStore) PendingCommands(_ context.Context, _ string) ([]*xemsv1.Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.pendCmds
	m.pendCmds = nil // teslim edildi: en-fazla-bir-kez
	return out, nil
}

func (m *memStore) setPolicy(b *xemsv1.PolicyBundle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy = b
}

func (m *memStore) CurrentPolicy(_ context.Context, _ string) (*xemsv1.PolicyBundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.policy, nil
}

func (m *memStore) setUpdate(u *xemsv1.UpdateManifest) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.update = u
}

func (m *memStore) LatestUpdate(_ context.Context, _, _, _ string) (*xemsv1.UpdateManifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.update, nil
}

func (m *memStore) SaveEvents(_ context.Context, deviceID string, evs []model.Event) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var last uint64
	for _, e := range evs {
		m.events[deviceID]++
		if e.Sequence > last {
			last = e.Sequence
		}
	}
	return last, nil
}

func (m *memStore) eventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.events {
		n += c
	}
	return n
}

func (m *memStore) eventsFor(deviceID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events[deviceID]
}

// Derleme-zamanı arayüz kontrolleri.
var (
	_ enroll.Store         = (*memStore)(nil)
	_ xgrpc.DeviceRegistry = (*memStore)(nil)
	_ xgrpc.EventSink      = (*memStore)(nil)
	_ xgrpc.PolicyProvider = (*memStore)(nil)
	_ xgrpc.UpdateProvider = (*memStore)(nil)
)

// --- İstemci-tarafı yardımcılar (satır içi; gerçek transport internal olduğu için) ---

func doEnroll(t *testing.T, ctx context.Context, addr string, caPEM []byte, token string, csrPEM []byte) *xemsv1.EnrollResponse {
	t.Helper()
	resp, err := doEnrollErr(ctx, addr, caPEM, token, csrPEM)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return resp
}

func doEnrollErr(ctx context.Context, addr string, caPEM []byte, token string, csrPEM []byte) (*xemsv1.EnrollResponse, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS13})
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return xemsv1.NewEnrollmentServiceClient(conn).Enroll(ctx, &xemsv1.EnrollRequest{
		EnrollmentToken: token, CsrPem: csrPEM, Hostname: "test-host", MacAddress: "aa:bb:cc:dd:ee:ff", OsInfo: "test",
	})
}

func dialAgent(t *testing.T, addr string, clientCertPEM, clientKeyPEM, caPEM []byte) (xemsv1.AgentServiceClient, *grpc.ClientConn) {
	t.Helper()
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS13,
	})
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	return xemsv1.NewAgentServiceClient(conn), conn
}

func dialEnrollMTLS(t *testing.T, addr string, clientCertPEM, clientKeyPEM, caPEM []byte) (xemsv1.EnrollmentServiceClient, *grpc.ClientConn) {
	t.Helper()
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS13,
	})
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	return xemsv1.NewEnrollmentServiceClient(conn), conn
}

func genKeyCSR(t *testing.T) (keyPEM, csrPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// --- CA / sunucu sertifikası üretimi ---

func makeCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "E2E CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func makeServerCert(t *testing.T, caCertPEM, caKeyPEM []byte) (certPEM, keyPEM []byte) {
	t.Helper()
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	kBlock, _ := pem.Decode(caKeyPEM)
	caKeyAny, err := x509.ParsePKCS8PrivateKey(kBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caKey := caKeyAny.(*ecdsa.PrivateKey)

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{serverName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(srvKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func certPool(caPEM []byte) *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(caPEM)
	return p
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return lis
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":    "aa:bb:cc:dd:ee:ff",
		"AABBCCDDEEFF":      "aa:bb:cc:dd:ee:ff",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, beklenen %q", in, got, want)
		}
	}
}

func TestBlindIndexDeterministicAndKeyed(t *testing.T) {
	b1 := NewBlindIndexer([]byte("anahtar-1-32-baytlik-gizli-anahtar!!"))
	b2 := NewBlindIndexer([]byte("anahtar-2-farkli-gizli-anahtar-32byt!"))

	mac := NormalizeMAC("AA:BB:CC:11:22:33")
	got1a := b1.Compute(mac)
	got1b := b1.Compute(mac)
	if !Equal(got1a, got1b) {
		t.Fatal("aynı anahtar+değer farklı indeks üretti (deterministik olmalı)")
	}
	if Equal(got1a, b2.Compute(mac)) {
		t.Fatal("farklı anahtarlar aynı indeksi üretti (keyed olmalı)")
	}
	if len(got1a) != 32 {
		t.Fatalf("blind index 32 bayt olmalı, %d", len(got1a))
	}
}

func TestFieldCipherRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := NewFieldCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := "WORKSTATION-07 / 00:1A:2B:3C:4D:5E"
	blob, err := c.EncryptString(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) == plain {
		t.Fatal("çıktı şifrelenmemiş görünüyor")
	}
	out, err := c.DecryptString(blob)
	if err != nil {
		t.Fatal(err)
	}
	if out != plain {
		t.Fatalf("round-trip uyuşmadı: %q != %q", out, plain)
	}
	// Bozulan ciphertext GCM tag doğrulamasında başarısız olmalı.
	blob[len(blob)-1] ^= 0xFF
	if _, err := c.Decrypt(blob); err == nil {
		t.Fatal("bozulmuş ciphertext hatasız çözüldü (GCM bütünlüğü başarısız)")
	}
}

func TestCASignCSR(t *testing.T) {
	ca := newTestCA(t)

	// Ajan tarafı: anahtar çifti + CSR üret.
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "istemcinin-istedigi-cn"}},
		agentKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	deviceID := "550e8400-e29b-41d4-a716-446655440000"
	signed, err := ca.SignCSR(csrPEM, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(signed.CertPEM)
	if block == nil {
		t.Fatal("imzalı sertifika PEM'i çözülemedi")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Kimliği SUNUCU belirler: CN, CSR'daki değil atanan device_id olmalı.
	if cert.Subject.CommonName != deviceID {
		t.Errorf("CN = %q, beklenen %q (sunucu kimliği dayatmalı)", cert.Subject.CommonName, deviceID)
	}
	// İstemci kimlik doğrulama amacı taşımalı.
	foundClientAuth := false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
		}
	}
	if !foundClientAuth {
		t.Error("sertifikada ClientAuth ExtKeyUsage yok")
	}
}

// newTestCA, test için kendinden imzalı bir CA üretir.
func newTestCA(t *testing.T) *CA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "XEMS Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

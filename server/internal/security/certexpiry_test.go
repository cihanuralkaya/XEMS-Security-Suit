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

// mkCertPEM, verilen NotAfter ile kendinden-imzalı bir test sertifikası PEM'i üretir.
func mkCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertExpiryAndDaysRemaining(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	na := now.Add(100 * 24 * time.Hour)
	pemB := mkCertPEM(t, na)

	got, err := CertExpiry(pemB)
	if err != nil {
		t.Fatalf("CertExpiry: %v", err)
	}
	if !got.Equal(na) {
		t.Fatalf("NotAfter %v beklenirdi, %v", na, got)
	}
	if d, _ := CertDaysRemaining(pemB, now); d != 100 {
		t.Fatalf("100 gün beklenirdi, %d", d)
	}
	// Süresi geçmiş sertifika → negatif.
	expired := mkCertPEM(t, now.Add(-5*24*time.Hour))
	if d, _ := CertDaysRemaining(expired, now); d >= 0 {
		t.Fatalf("süresi geçmiş → negatif beklenirdi, %d", d)
	}
}

func TestCertExpiryBadPEM(t *testing.T) {
	if _, err := CertExpiry([]byte("not a cert")); err == nil {
		t.Fatal("geçersiz PEM hata döndürmeli")
	}
}

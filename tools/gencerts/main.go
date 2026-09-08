// Command gencerts, GELİŞTİRME için bir CA ve sunucu sertifikası üretir.
//
// ÜRETİMDE KULLANMAYIN: gerçek dağıtımda CA özel anahtarı bir HSM/sır
// yöneticisinde tutulmalı ve sertifikalar kurumsal PKI ile üretilmelidir.
// Bu araç yalnız lokal C2↔ajan denemesi içindir.
//
// Kullanım:
//
//	go run ./tools/gencerts -out ./dev-certs -name xems-c2
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	out := flag.String("out", "./dev-certs", "sertifikaların yazılacağı dizin")
	name := flag.String("name", "xems-c2", "sunucu adı (TLS SAN / doğrulama adı)")
	days := flag.Int("days", 825, "geçerlilik süresi (gün)")
	flag.Parse()

	if err := run(*out, *name, *days); err != nil {
		log.Fatal(err)
	}
}

func run(outDir, serverName string, days int) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	notAfter := time.Now().AddDate(0, 0, days)

	// --- CA ---
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          bigSerial(),
		Subject:               pkix.Name{CommonName: "XEMS Dev CA", Organization: []string{"XEMS"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCertPEM := certPEM(caDER)
	caKeyPEM, err := keyPEM(caKey)
	if err != nil {
		return err
	}

	// --- Sunucu sertifikası (CA tarafından imzalı) ---
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: bigSerial(),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{serverName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	srvCertPEM := certPEM(srvDER)
	srvKeyPEM, err := keyPEM(srvKey)
	if err != nil {
		return err
	}

	files := map[string][]byte{
		"ca.crt":     caCertPEM,
		"ca.key":     caKeyPEM,
		"server.crt": srvCertPEM,
		"server.key": srvKeyPEM,
	}
	for name, data := range files {
		perm := os.FileMode(0o644)
		if filepath.Ext(name) == ".key" {
			perm = 0o600
		}
		if err := os.WriteFile(filepath.Join(outDir, name), data, perm); err != nil {
			return err
		}
	}

	// 32 baytlık rastgele ana anahtar (base64) — XEMS_MASTER_KEY için öneri.
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		return err
	}

	fmt.Printf("Sertifikalar yazıldı: %s\n", outDir)
	fmt.Println("  ca.crt, ca.key, server.crt, server.key")
	fmt.Printf("\nÖnerilen ortam değişkenleri (geliştirme):\n")
	fmt.Printf("  export XEMS_MASTER_KEY=%s\n", base64.StdEncoding.EncodeToString(master))
	fmt.Printf("  export XEMS_CA_CERT=%s\n", filepath.Join(outDir, "ca.crt"))
	fmt.Printf("  export XEMS_CA_KEY=%s\n", filepath.Join(outDir, "ca.key"))
	fmt.Printf("  export XEMS_SERVER_CERT=%s\n", filepath.Join(outDir, "server.crt"))
	fmt.Printf("  export XEMS_SERVER_KEY=%s\n", filepath.Join(outDir, "server.key"))
	fmt.Printf("  # ajan tarafı: XEMS_CA_PEM=%s  XEMS_SERVER_NAME=%s\n",
		filepath.Join(outDir, "ca.crt"), serverName)
	return nil
}

func bigSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, _ := rand.Int(rand.Reader, limit)
	return n
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Command detectsign, bir tespit-kuralı dosyasını (JSON) Ed25519 ile imzalar.
// İmza `<rules>.sig` olarak yazılır; C2 XEMS_DETECT_RULES_PUBKEY ile doğrular
// (XEMS_DETECT_RULES_FILE imzalıysa kurcalamaya karşı fail-closed yüklenir).
//
//	go run ./server/cmd/detectsign -key ./ota-keys/detect_ed25519.key -rules detect-rules.json
//
// Anahtar formatı otasign -genkey ile aynıdır (base64 Ed25519 özel anahtar). İmza,
// kural JSON baytlarının TAMAMI üzerinedir (YARA kuralı / anomali modeli desenİyle aynı).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"xems.corp/suite/server/internal/detect"
)

func main() {
	keyPath := flag.String("key", "", "Ed25519 özel anahtar dosyası (base64)")
	rulesPath := flag.String("rules", "", "tespit kuralı JSON dosyası")
	flag.Parse()

	if *keyPath == "" || *rulesPath == "" {
		log.Fatal("-key ve -rules zorunlu")
	}
	rawKey, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(string(rawKey))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		log.Fatal("geçersiz Ed25519 özel anahtar")
	}
	data, err := os.ReadFile(*rulesPath)
	if err != nil {
		log.Fatal(err)
	}
	// İmzalamadan önce kuralları doğrula (bozuk kuralı imzalama).
	if _, err := detect.LoadRulesFile(*rulesPath); err != nil {
		log.Fatalf("kural doğrulaması başarısız: %v", err)
	}

	sig := ed25519.Sign(ed25519.PrivateKey(priv), data)
	sigPath := *rulesPath + ".sig"
	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("İmza yazıldı: %s\n", sigPath)
}

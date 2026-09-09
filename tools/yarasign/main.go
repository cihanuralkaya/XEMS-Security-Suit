// Command yarasign, bir içerik-tarama (YARA-tarzı) kural dosyasını Ed25519 ile
// imzalar. İmza `<rules>.sig` olarak yazılır; ajan XEMS_YARA_PUBKEY ile doğrular.
//
//	go run ./tools/yarasign -key ./ota-keys/scan_ed25519.key -rules ./rules.json
//
// Anahtar formatı otasign -genkey ile aynıdır (base64 Ed25519 özel anahtar).
// İmza, kural JSON baytlarının TAMAMI üzerinedir (anomali modeli imzasıyla aynı
// desen). Kuralları düzenleyen ama imzalayamayan biri ajan tarafından reddedilir.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"xems.corp/suite/contentscan"
)

func main() {
	keyPath := flag.String("key", "", "Ed25519 özel anahtar dosyası (base64)")
	rulesPath := flag.String("rules", "", "kural JSON dosyası")
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
	if _, err := contentscan.ParseRules(data); err != nil {
		log.Fatalf("kural doğrulaması başarısız: %v", err)
	}

	sig := ed25519.Sign(ed25519.PrivateKey(priv), data)
	sigPath := *rulesPath + ".sig"
	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("İmza yazıldı: %s\n", sigPath)
}

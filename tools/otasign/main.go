// Command otasign, OTA güncelleme imzalama araçlarını sağlar.
//
// Anahtar üretimi:
//
//	go run ./tools/otasign -genkey -out ./ota-keys
//	  -> ota_ed25519.key (özel, gizli) ve public key'i base64 basar.
//	     Public key ajanlara XEMS_UPDATE_PUBKEY olarak gömülür.
//
// Sürüm imzalama:
//
//	go run ./tools/otasign -key ./ota-keys/ota_ed25519.key \
//	    -file ./dist/agent-1.4.0.exe -version 1.4.0 \
//	    -url https://c2/updates/1.4.0/agent.exe -platform windows
//	  -> SHA-256, base64 imza ve ota_releases için INSERT SQL basar.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"xems.corp/suite/otawire"
)

func main() {
	genkey := flag.Bool("genkey", false, "yeni Ed25519 anahtar çifti üret")
	out := flag.String("out", "./ota-keys", "genkey: çıktı dizini")
	keyPath := flag.String("key", "", "imzalama: Ed25519 özel anahtar dosyası")
	file := flag.String("file", "", "imzalama: güncelleme paketi (ikili)")
	version := flag.String("version", "", "imzalama: sürüm etiketi")
	url := flag.String("url", "", "imzalama: indirme URL'i")
	platform := flag.String("platform", "windows", "imzalama: hedef platform")
	mandatory := flag.Bool("mandatory", false, "imzalama: zorunlu güncelleme")
	flag.Parse()

	var err error
	if *genkey {
		err = doGenKey(*out)
	} else {
		err = doSign(*keyPath, *file, *version, *url, *platform, *mandatory)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func doGenKey(outDir string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	keyFile := filepath.Join(outDir, "ota_ed25519.key")
	// Özel anahtar ham (seed+pub, 64 bayt) base64 olarak, yalnız sahibe okunur.
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		return err
	}
	fmt.Printf("Özel anahtar yazıldı: %s (GİZLİ TUT)\n", keyFile)
	fmt.Printf("Ajanlara gömülecek public key:\n  XEMS_UPDATE_PUBKEY=%s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func doSign(keyPath, file, version, url, platform string, mandatory bool) error {
	if keyPath == "" || file == "" || version == "" {
		return fmt.Errorf("imzalama için -key, -file ve -version zorunlu")
	}
	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	privBytes, err := base64.StdEncoding.DecodeString(string(rawKey))
	if err != nil {
		return fmt.Errorf("özel anahtar base64 çözülemedi: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return errors.New("geçersiz Ed25519 özel anahtar boyutu")
	}
	priv := ed25519.PrivateKey(privBytes)
	payload, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	m := otawire.Manifest{
		TargetVersion: version,
		SHA256Hex:     hex.EncodeToString(sum[:]),
		DownloadURL:   url,
		Mandatory:     mandatory,
	}
	sig := ed25519.Sign(priv, otawire.CanonicalBytes(m))

	fmt.Printf("SHA-256: %s\n", m.SHA256Hex)
	fmt.Printf("İmza (base64): %s\n\n", base64.StdEncoding.EncodeToString(sig))
	fmt.Printf("ota_releases INSERT (imza bytea olarak decode edilir):\n")
	fmt.Printf("INSERT INTO ota_releases (version, os_platform, download_url, sha256_hex, signature, mandatory)\n")
	fmt.Printf("VALUES ('%s', '%s', '%s', '%s', decode('%s','base64'), %v);\n",
		version, platform, url, m.SHA256Hex, base64.StdEncoding.EncodeToString(sig), mandatory)
	return nil
}

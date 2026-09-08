// Command offboard, bir cihaz için ÇEVRİMDIŞI emekliye-ayırma (stand-down)
// jetonu üretir ve Ed25519 ile imzalar.
//
//	go run ./tools/offboard -key ./ota-keys/offboard_ed25519.key \
//	    -device dev-42 -ttl 168h
//
// Üretilen tek satırlık jeton, hedef cihaza XEMS_OFFBOARD_TOKEN olarak (veya
// dosyayla) verilir. Ajan, gömülü XEMS_OFFBOARD_PUBKEY ile doğrular; geçerliyse
// tamper-korumasını BİLİNÇLİ olarak durdurur (stand-down) ve çıkar.
//
// Anahtar formatı otasign -genkey ile aynıdır (base64 Ed25519 özel anahtar).
// Public key ajanlara XEMS_OFFBOARD_PUBKEY olarak gömülür.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"xems.corp/suite/offboard"
)

func main() {
	keyPath := flag.String("key", "", "Ed25519 özel anahtar dosyası (base64)")
	device := flag.String("device", "", "hedef cihaz kimliği (DeviceID)")
	ttl := flag.Duration("ttl", 168*time.Hour, "jeton geçerlilik süresi (0 = süresiz)")
	flag.Parse()

	if *keyPath == "" || *device == "" {
		log.Fatal("-key ve -device zorunlu")
	}
	rawKey, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(string(rawKey))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		log.Fatal("geçersiz Ed25519 özel anahtar")
	}

	var expiresAt int64
	if *ttl > 0 {
		expiresAt = time.Now().Add(*ttl).Unix()
	}
	tok := offboard.Token{DeviceID: *device, ExpiresAt: expiresAt}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), offboard.CanonicalBytes(tok))
	enc := offboard.Encode(tok, sig)

	if expiresAt == 0 {
		fmt.Fprintln(os.Stderr, "UYARI: süresiz jeton üretildi (-ttl 0) — sızması durumunda geçerliliği bitmez.")
	} else {
		fmt.Fprintf(os.Stderr, "Cihaz %q için jeton, %s tarihine kadar geçerli.\n",
			*device, time.Unix(expiresAt, 0).Format(time.RFC3339))
	}
	fmt.Println(enc)
}

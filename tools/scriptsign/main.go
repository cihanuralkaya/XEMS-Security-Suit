// Command scriptsign, bir otomasyon scriptini Ed25519 ile imzalar (RUN_SIGNED_SCRIPT).
//
//	go run ./tools/scriptsign -key ./ota-keys/ota_ed25519.key \
//	    -interp cmd -file ./temizle.cmd -arg /verbose
//
// Anahtar formatı otasign -genkey ile aynıdır (base64 Ed25519 özel anahtar).
// Public key ajanlara XEMS_SCRIPT_PUBKEY olarak gömülür.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"xems.corp/suite/scriptwire"
)

type argList []string

func (a *argList) String() string { return fmt.Sprint(*a) }
func (a *argList) Set(v string) error {
	*a = append(*a, v)
	return nil
}

func main() {
	keyPath := flag.String("key", "", "Ed25519 özel anahtar dosyası (base64)")
	interp := flag.String("interp", "", "yorumlayıcı: powershell | sh | bash | cmd | node")
	file := flag.String("file", "", "script gövdesi dosyası")
	var args argList
	flag.Var(&args, "arg", "script argümanı (tekrarlanabilir)")
	flag.Parse()

	if *keyPath == "" || *interp == "" || *file == "" {
		log.Fatal("-key, -interp ve -file zorunlu")
	}
	rawKey, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(string(rawKey))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		log.Fatal("geçersiz Ed25519 özel anahtar")
	}
	body, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}

	s := scriptwire.Script{Interpreter: *interp, Body: string(body), Args: args}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), scriptwire.CanonicalBytes(s))

	fmt.Printf("İmza (base64): %s\n", base64.StdEncoding.EncodeToString(sig))
	fmt.Println("\nKomut params (JSON) — Command.params Struct alanları:")
	fmt.Printf("  interpreter = %q\n  body        = <dosya içeriği>\n  signature   = <yukarıdaki base64>\n", *interp)
	if len(args) > 0 {
		fmt.Printf("  args        = %v\n", []string(args))
	}
}

// Command auditverify, /api/audit/export ile alınan KURCALAMA-KANITLI denetim
// dışa aktarımını (JSONL) C2'DEN BAĞIMSIZ doğrular: hash zincirini yeniden
// hesaplar ve (public key verilirse) manifest imzasını kontrol eder.
//
//	go run ./server/cmd/auditverify -file audit-export.jsonl
//	go run ./server/cmd/auditverify -file audit-export.jsonl -pub <base64-ed25519-pub>
//
// Sıfır çıkış kodu = zincir (ve varsa imza) geçerli. Denetçi/WORM arşivinde
// düzenli çalıştırılabilir.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"xems.corp/suite/server/internal/auditexport"
)

func main() {
	file := flag.String("file", "", "doğrulanacak JSONL dışa aktarım dosyası")
	pubB64 := flag.String("pub", "", "opsiyonel Ed25519 açık anahtar (base64) — imza doğrulaması için")
	flag.Parse()

	if *file == "" {
		log.Fatal("-file zorunlu")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}
	var pub ed25519.PublicKey
	if *pubB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(*pubB64)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			log.Fatal("geçersiz Ed25519 açık anahtar")
		}
		pub = ed25519.PublicKey(raw)
	}
	if err := auditexport.Verify(data, pub); err != nil {
		fmt.Printf("DOĞRULAMA BAŞARISIZ: %v\n", err)
		os.Exit(1)
	}
	if pub != nil {
		fmt.Println("OK: hash zinciri + imza geçerli.")
	} else {
		fmt.Println("OK: hash zinciri geçerli (imza doğrulanmadı — -pub verilmedi).")
	}
}

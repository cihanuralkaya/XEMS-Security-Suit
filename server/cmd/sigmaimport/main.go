// Command sigmaimport, Sigma tespit kurallarını (YAML) XEMS yerel tespit kural
// biçimine (JSON) çevirir. Çıktı, XEMS_DETECT_RULES_FILE ile C2'ye verilebilir.
//
//	go run ./server/cmd/sigmaimport -in rules.yml > detect-rules.json
//	go run ./server/cmd/sigmaimport -in ./sigma-dir/ -out detect-rules.json
//
// Çok-belgeli YAML (--- ayraçlı) ve dizin (özyinelemesiz *.yml/*.yaml) desteklenir.
// Desteklenmeyen Sigma yapıları (OR/NOT/1-of/liste değerleri) GÜVENLE atlanır ve
// stderr'e neden yazılır (sessizce yanlış içe aktarma yok).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"xems.corp/suite/server/internal/detect"
	"xems.corp/suite/server/internal/sigma"
)

func main() {
	in := flag.String("in", "", "Sigma YAML dosyası veya dizini")
	out := flag.String("out", "", "çıktı JSON dosyası (boş → stdout)")
	flag.Parse()

	if *in == "" {
		log.Fatal("-in zorunlu")
	}
	files, err := gatherFiles(*in)
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatal("Sigma YAML dosyası bulunamadı")
	}

	var rules []detect.Rule
	totalSkips := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("okunamadı %s: %v", f, err)
			continue
		}
		rs, skips, err := sigma.ConvertMulti(data)
		if err != nil {
			log.Printf("çevrilemedi %s: %v", f, err)
			continue
		}
		rules = append(rules, rs...)
		for _, s := range skips {
			fmt.Fprintf(os.Stderr, "ATLANDI [%s] %s\n", filepath.Base(f), s)
			totalSkips++
		}
	}

	// Çevrilen kuralların motor doğrulamasından geçtiğini teyit et.
	if _, err := detect.LoadRules(strings.NewReader(mustJSON(rules))); err != nil {
		log.Fatalf("çevrilen kurallar motor doğrulamasından geçmedi: %v", err)
	}

	payload := mustJSON(rules)
	if *out == "" {
		fmt.Println(payload)
	} else if err := os.WriteFile(*out, []byte(payload+"\n"), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "%d kural çevrildi, %d belge atlandı.\n", len(rules), totalSkips)
}

func gatherFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.ToLower(e.Name())
		if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
			files = append(files, filepath.Join(path, e.Name()))
		}
	}
	return files, nil
}

func mustJSON(rules []detect.Rule) string {
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}

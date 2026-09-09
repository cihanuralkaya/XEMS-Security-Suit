// Package contentscan, dosya içeriğini imza (pattern) kurallarına karşı tarayan
// saf-Go, YARA-tarzı bir motordur. Her kural adlandırılmış bayt desenleri
// (literal metin veya hex) ve bir KOŞUL taşır (any | all | N-of); içerik koşulu
// karşılarsa eşleşme üretir.
//
// TASARIM: Motor SAF ve testlidir (exec yok, OS'e bağımlı değil). Kötü amaçlı
// örüntüler ASLA ikiliye gömülmez — kurallar çalışma zamanında İMZALI harici
// dosyadan yüklenir (bkz. rules.go). Bu hem kural güncellemesini imza gerektiren
// bir işlem yapar (kurcalamaya karşı) hem de AV sezgisel tespitlerini önler
// (ikilide gömülü zararlı-yazılım string'i yok).
package contentscan

import "bytes"

// Rule, adlandırılmış bir tarama kuralıdır.
type Rule struct {
	Name      string   // benzersiz kural adı (olay mesajında görünür)
	Severity  string   // eşleşme önem derecesi: HIGH | MEDIUM | LOW
	Condition string   // "any" (varsayılan) | "all" | N-of eşiği için pozitif tamsayı string'i (ör. "2")
	Patterns  [][]byte // aranacak ham bayt desenleri (literal veya hex'ten çözülmüş)
}

// Match, tek bir kuralın bir içerikle eşleşmesidir.
type Match struct {
	Rule     string // eşleşen kural adı
	Severity string // kuralın önem derecesi
	Hits     int    // eşleşen desen sayısı
}

// RuleSet, derlenmiş kural kümesidir.
type RuleSet struct {
	Rules []Rule
}

// threshold, bir kuralın koşulunu eşleşen-desen sayısına göre değerlendirir.
// Dönen değer, eşleşme için gereken MİNİMUM desen sayısıdır (0 = geçersiz kural).
func threshold(r Rule) int {
	n := len(r.Patterns)
	if n == 0 {
		return 0
	}
	switch r.Condition {
	case "", "any":
		return 1
	case "all":
		return n
	default:
		// N-of: pozitif tamsayı; desen sayısıyla sınırlanır.
		k := atoiSafe(r.Condition)
		if k <= 0 {
			return 0 // tanınmayan koşul → kural devre dışı (fail-closed)
		}
		if k > n {
			k = n
		}
		return k
	}
}

// atoiSafe, basit pozitif tamsayı ayrıştırır (strconv'a bağımlılık olmadan);
// geçersizse 0 döner.
func atoiSafe(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// Scan, veriyi tüm kurallara karşı tarar ve eşleşmeleri (kural sırasına göre) döner.
func (rs RuleSet) Scan(data []byte) []Match {
	var out []Match
	for _, r := range rs.Rules {
		need := threshold(r)
		if need == 0 {
			continue // geçersiz/boş kural
		}
		hits := 0
		for _, p := range r.Patterns {
			if len(p) == 0 {
				continue
			}
			if bytes.Contains(data, p) {
				hits++
			}
		}
		if hits >= need {
			sev := r.Severity
			if sev == "" {
				sev = "MEDIUM"
			}
			out = append(out, Match{Rule: r.Name, Severity: sev, Hits: hits})
		}
	}
	return out
}

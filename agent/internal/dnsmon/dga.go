// Package dnsmon, uç noktanın DNS sorgu telemetrisini toplar ve Alan-Üretim
// Algoritması (DGA) olasılığı yüksek alan adlarını saf-Go istatistiksel
// sezgilerle işaretler. DGA alanları (bot ağı C2 rendezvous) genellikle YÜKSEK
// entropili, uzun, sesli-harf oranı düşük ve/veya rakam yoğun olur.
//
// Skorlama SAF ve testlidir (exec/OS yok); toplama OS-özel dosyalarda yapılır.
package dnsmon

import (
	"math"
	"strings"
)

// DGAScore, bir alan adının DGA-benzerlik ölçümüdür.
type DGAScore struct {
	Domain          string
	Label           string  // skorlanan etiket (ikinci seviye)
	Entropy         float64 // Shannon entropisi (bit/karakter)
	VowelRatio      float64
	DigitRatio      float64
	Length          int
	MaxConsonantRun int // en uzun ardışık ünsüz dizisi (DGA'da tipik olarak yüksek)
	Suspicious      bool
}

// vowels, sesli harf kümesi.
const vowels = "aeiou"

// ScoreDomain, bir alan adının DGA-benzerlik skorunu hesaplar. Skorlanan etiket,
// üst-düzey alanın (son nokta) solundaki ikinci-seviye etikettir (PSL olmadan
// yaklaşık). Boş/geçersiz → Suspicious=false.
func ScoreDomain(domain string) DGAScore {
	d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	label := secondLevelLabel(d)
	// Yalnız harf/rakam say (tire vb. gürültüyü çıkar).
	clean := keepAlnum(label)
	s := DGAScore{Domain: d, Label: label, Length: len(clean)}
	if len(clean) == 0 {
		return s
	}
	s.Entropy = shannonEntropy(clean)
	var vowelN, digitN int
	for _, r := range clean {
		switch {
		case strings.ContainsRune(vowels, r):
			vowelN++
		case r >= '0' && r <= '9':
			digitN++
		}
	}
	s.VowelRatio = float64(vowelN) / float64(len(clean))
	s.DigitRatio = float64(digitN) / float64(len(clean))
	s.MaxConsonantRun = maxConsonantRun(clean)

	// Üç muhafazakâr kural (yanlış pozitifi düşük tutmak için birleşik koşullar):
	//  1) Uzun + yüksek entropi + düşük sesli-harf oranı (klasik rastgele alan).
	//  2) Orta uzunluk + rakam yoğun + orta-yüksek entropi (rakam karışımlı DGA).
	//  3) Uzun + çok uzun ünsüz dizisi (gerçek alanlar 5+ ardışık ünsüz nadiren taşır).
	if (s.Length >= 10 && s.Entropy >= 3.5 && s.VowelRatio <= 0.30) ||
		(s.Length >= 8 && s.DigitRatio >= 0.30 && s.Entropy >= 3.0) ||
		(s.Length >= 8 && s.MaxConsonantRun >= 5) {
		s.Suspicious = true
	}
	return s
}

// maxConsonantRun, verilen (temizlenmiş) etikette en uzun ardışık ünsüz (harf,
// sesli olmayan) dizisinin uzunluğunu döner. Rakamlar diziyi keser.
func maxConsonantRun(clean string) int {
	best, cur := 0, 0
	for _, r := range clean {
		if r >= 'a' && r <= 'z' && !strings.ContainsRune(vowels, r) {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 0
		}
	}
	return best
}

// secondLevelLabel, "a.b.example.com" → "example" (son noktanın solundaki etiket).
// Nokta yoksa girdinin kendisi.
func secondLevelLabel(d string) string {
	parts := strings.Split(d, ".")
	switch len(parts) {
	case 0:
		return d
	case 1:
		return parts[0]
	default:
		return parts[len(parts)-2]
	}
}

func keepAlnum(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// shannonEntropy, bir dizenin karakter başına Shannon entropisini (bit) döner.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

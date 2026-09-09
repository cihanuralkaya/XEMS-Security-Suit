// Package sigma, topluluk Sigma tespit kurallarını (YAML) XEMS'in yerel tespit
// kural modeline (detect.Rule) çevirir. Böylece kuruluşlar yaygın Sigma içeriğini
// koda dokunmadan içe aktarabilir.
//
// KAPSAM (v1, dürüst alt küme): detect motoru alan-alt-dize (AND) + mesaj-alt-dize
// (AND) eşleşmesi yaptığından, Sigma'nın YALNIZ bununla ifade edilebilen alt kümesi
// desteklenir:
//   - Tek seçim (selection) ya da "and"/"all of them" ile birleştirilen seçimler
//     (mantıksal AND).
//   - Skaler alan değerleri (opsiyonel |contains/|startswith/|endswith değiştirici
//     — hepsi alt-dize olarak eşlenir, motor yalnız alt-dize destekler).
//
// DESTEKLENMEYEN (güvenli reddedilir, sessizce YANLIŞ içe aktarılmaz): OR (liste
// değerleri veya "or"), "not"/filtreler, "1 of", regex/|re, |all listeleri. Bu
// yapılar hata döndürür; ConvertMulti bunları atlanan-neden olarak raporlar.
package sigma

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"xems.corp/suite/server/internal/detect"
	"xems.corp/suite/server/internal/mitre"
)

// sigmaDoc, desteklenen Sigma alanlarıdır.
type sigmaDoc struct {
	Title     string         `yaml:"title"`
	ID        string         `yaml:"id"`
	Level     string         `yaml:"level"`
	Tags      []string       `yaml:"tags"`
	Detection map[string]any `yaml:"detection"`
}

// levelToSeverity, Sigma level'ını XEMS önem düzeyine eşler.
func levelToSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	case "informational", "info":
		return "INFO"
	default:
		return "MEDIUM" // level yoksa makul varsayılan
	}
}

// techniqueFromTags, "attack.tNNNN" biçimli ilk etiketten bir MITRE tekniği (yalnız
// ID) çıkarır. Eşleşme yoksa boş Technique döner.
func techniqueFromTags(tags []string) mitre.Technique {
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if strings.HasPrefix(t, "attack.t") {
			id := strings.ToUpper(strings.TrimPrefix(t, "attack."))
			return mitre.Technique{ID: id}
		}
	}
	return mitre.Technique{}
}

var (
	// ErrNoDetection, kuralda detection/condition yoksa döner.
	ErrNoDetection = errors.New("sigma: detection/condition yok")
	// ErrUnsupported, kural desteklenmeyen bir yapı içerdiğinde döner.
	ErrUnsupported = errors.New("sigma: desteklenmeyen yapı")
	// ErrEmptyRule, çevrilen kuralın hiç eşleşme koşulu olmadığında döner.
	ErrEmptyRule = errors.New("sigma: boş kural (eşleşme koşulu yok)")
)

// Convert, tek bir Sigma YAML belgesini bir detect.Rule'a çevirir.
func Convert(data []byte) (detect.Rule, error) {
	var doc sigmaDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return detect.Rule{}, fmt.Errorf("sigma: YAML çözülemedi: %w", err)
	}
	return convertDoc(doc)
}

func convertDoc(doc sigmaDoc) (detect.Rule, error) {
	if strings.TrimSpace(doc.Title) == "" {
		return detect.Rule{}, errors.New("sigma: title zorunlu")
	}
	if doc.Detection == nil {
		return detect.Rule{}, ErrNoDetection
	}
	condRaw, ok := doc.Detection["condition"]
	if !ok {
		return detect.Rule{}, ErrNoDetection
	}
	cond, ok := condRaw.(string)
	if !ok {
		return detect.Rule{}, ErrUnsupported
	}
	selNames, err := selectionsFromCondition(cond, doc.Detection)
	if err != nil {
		return detect.Rule{}, err
	}

	fields := map[string]string{}
	var contains []string
	for _, name := range selNames {
		block, ok := doc.Detection[name]
		if !ok {
			return detect.Rule{}, fmt.Errorf("%w: bilinmeyen seçim %q", ErrUnsupported, name)
		}
		if err := mergeSelection(block, fields, &contains); err != nil {
			return detect.Rule{}, err
		}
	}
	if len(fields) == 0 && len(contains) == 0 {
		return detect.Rule{}, ErrEmptyRule
	}

	id := strings.TrimSpace(doc.ID)
	if id == "" {
		id = slug(doc.Title)
	}
	return detect.Rule{
		ID:        "sigma:" + id,
		Name:      doc.Title,
		Severity:  levelToSeverity(doc.Level),
		Fields:    nonEmptyMap(fields),
		Contains:  contains,
		Technique: techniqueFromTags(doc.Tags),
	}, nil
}

// selectionsFromCondition, condition'ı AND ile birleştirilecek seçim adlarına
// çözer. Desteklenen: tek ad; "a and b"; "all of them". Diğerleri (or/not/1 of/
// parantez) reddedilir.
func selectionsFromCondition(cond string, detection map[string]any) ([]string, error) {
	c := strings.ToLower(strings.TrimSpace(cond))
	if c == "" {
		return nil, ErrNoDetection
	}
	if strings.Contains(c, " or ") || strings.Contains(c, "not ") ||
		strings.Contains(c, "1 of") || strings.Contains(c, "(") || strings.Contains(c, "|") {
		return nil, fmt.Errorf("%w: koşul %q", ErrUnsupported, cond)
	}
	if c == "all of them" {
		var names []string
		for k := range detection {
			if k != "condition" {
				names = append(names, k)
			}
		}
		if len(names) == 0 {
			return nil, ErrNoDetection
		}
		return names, nil
	}
	// "a and b and c" → [a b c]; tek ad → [a].
	var names []string
	for _, part := range strings.Split(c, " and ") {
		p := strings.TrimSpace(part)
		if p == "" || strings.Contains(p, " ") {
			return nil, fmt.Errorf("%w: koşul %q", ErrUnsupported, cond)
		}
		names = append(names, p)
	}
	return names, nil
}

// mergeSelection, bir seçim bloğunu (map[field]value) fields/contains'e AND olarak
// ekler. Liste değerleri (OR) ve tanınmayan biçimler reddedilir.
func mergeSelection(block any, fields map[string]string, contains *[]string) error {
	m, ok := toStringMap(block)
	if !ok {
		return fmt.Errorf("%w: seçim bir alan haritası değil", ErrUnsupported)
	}
	for rawKey, val := range m {
		field, mod, _ := strings.Cut(rawKey, "|")
		switch strings.ToLower(mod) {
		case "", "contains", "startswith", "endswith":
			// hepsi alt-dize olarak eşlenir
		default:
			return fmt.Errorf("%w: değiştirici |%s", ErrUnsupported, mod)
		}
		s, ok := scalarString(val)
		if !ok {
			return fmt.Errorf("%w: alan %q liste/karmaşık değer", ErrUnsupported, field)
		}
		// message/keywords alanları mesaja, diğerleri Details alanına eşlenir.
		lf := strings.ToLower(field)
		if lf == "message" || lf == "keywords" || lf == "keyword" {
			*contains = append(*contains, s)
		} else {
			fields[field] = s
		}
	}
	return nil
}

// toStringMap, bir YAML haritasını map[string]any'ye normalize eder (yaml.v3
// map[string]any üretir; bu yardımcı güvenli tip kontrolüdür).
func toStringMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// scalarString, skaler bir YAML değerini string'e çevirir; liste/harita ise false.
func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case int:
		return fmt.Sprintf("%d", x), true
	case int64:
		return fmt.Sprintf("%d", x), true
	case float64:
		return fmt.Sprintf("%v", x), true
	case bool:
		return fmt.Sprintf("%v", x), true
	default:
		return "", false
	}
}

func nonEmptyMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

// slug, başlıktan kararlı bir kimlik üretir (harf/rakam korunur, gerisi '-').
func slug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// ConvertMulti, çok-belgeli bir Sigma YAML'ını (--- ayraçlı) çevirir. Başarılı
// kuralları + atlanan belgelerin nedenlerini döner (tek bir kötü belge tüm içe
// aktarımı bozmaz).
func ConvertMulti(data []byte) ([]detect.Rule, []string, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var rules []detect.Rule
	var skips []string
	idx := 0
	for {
		var doc sigmaDoc
		err := dec.Decode(&doc)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Bozuk belge: atla, raporla, devam et.
			skips = append(skips, fmt.Sprintf("belge #%d: %v", idx, err))
			idx++
			// Decoder hatadan sonra ilerleyemeyebilir; güvenli çıkış.
			break
		}
		idx++
		// Tamamen boş belgeleri atla.
		if doc.Title == "" && doc.Detection == nil {
			continue
		}
		r, err := convertDoc(doc)
		if err != nil {
			skips = append(skips, fmt.Sprintf("%q: %v", doc.Title, err))
			continue
		}
		rules = append(rules, r)
	}
	return rules, skips, nil
}

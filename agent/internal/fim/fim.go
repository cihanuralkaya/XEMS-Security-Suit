// Package fim, dosya bütünlüğü izleme (File Integrity Monitoring) sağlar: politika
// ile tanımlı kritik yolların (sistem dizinleri, ajanın kendi ikilisi/yapılandırması,
// hassas uygulama config'leri) SHA-256 özetini periyodik alır ve taban çizgisine göre
// ekleme/değiştirme/silme değişikliklerini raporlar. Kalıcılık/tamper ve fidye-
// yazılımı-tarzı toplu değişiklik için temel EDR/uyum (PCI/CIS) kontrolüdür.
//
// Saf Go (crypto/sha256 + filepath.Walk); fsnotify bağımlılığı GEREKMEZ (yoklama
// tabanlı taban çizgisi). Tarama (OS okuma) Scan'de, saf fark mantığı Tracker.Diff'te
// tutulur (test edilebilirlik — netconn/usbmon deseniyle aynı).
package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// ChangeType, bir dosya bütünlüğü değişikliğinin türüdür.
type ChangeType string

const (
	Added    ChangeType = "added"
	Modified ChangeType = "modified"
	Deleted  ChangeType = "deleted"
)

// Change, izlenen bir yoldaki tek bir bütünlük değişikliğidir.
type Change struct {
	Path    string
	Type    ChangeType
	Hash    string // yeni SHA-256 (silmede boş)
	OldHash string // önceki SHA-256 (eklemede boş)
}

// maxFileBytes, hash için okunacak tek dosyanın üst sınırıdır (çok büyük dosyalar
// atlanır; FIM meta-değişikliği yakalar, veri boşaltmaz).
const maxFileBytes = 50 << 20 // 50 MiB

// hashFile, bir dosyanın SHA-256'sını hex döndürür. Okunamazsa ("", false).
func hashFile(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, f, maxFileBytes); err != nil && err != io.EOF {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// Scan, verilen yolları okur (dizinler yinelemeli gezilir) ve yol→SHA-256 döner.
// Erişilemeyen yollar sessizce atlanır (silme, sonraki Diff'te yakalanır).
func Scan(paths []string) map[string]string {
	out := map[string]string{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			_ = filepath.WalkDir(p, func(fp string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if h, ok := hashFile(fp); ok {
					out[fp] = h
				}
				return nil
			})
			continue
		}
		if h, ok := hashFile(p); ok {
			out[p] = h
		}
	}
	return out
}

// Tracker, dosya bütünlüğü taban çizgisini tutar ve değişiklikleri raporlar.
type Tracker struct {
	baseline  map[string]string
	baselined bool
}

// Diff, mevcut taramayı taban çizgisiyle karşılaştırır ve değişiklikleri
// (deterministik, yola göre sıralı) döner. İLK çağrı taban çizgisidir: değişiklik
// üretmez, yalnız durumu kaydeder.
func (t *Tracker) Diff(current map[string]string) []Change {
	if !t.baselined {
		t.baseline = current
		t.baselined = true
		return nil
	}
	var ch []Change
	for p, h := range current {
		if old, ok := t.baseline[p]; !ok {
			ch = append(ch, Change{Path: p, Type: Added, Hash: h})
		} else if old != h {
			ch = append(ch, Change{Path: p, Type: Modified, Hash: h, OldHash: old})
		}
	}
	for p, old := range t.baseline {
		if _, ok := current[p]; !ok {
			ch = append(ch, Change{Path: p, Type: Deleted, OldHash: old})
		}
	}
	sort.Slice(ch, func(i, j int) bool { return ch[i].Path < ch[j].Path })
	t.baseline = current
	return ch
}

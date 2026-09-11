// Package secrets, hassas değerlerin (DB kimlik bilgileri, API anahtarları, imzalama
// ve CA anahtarları, bildirim kimlikleri) düz-metin yapılandırmada tutulmadan; ortam,
// dosya ya da (ileride) KMS/Vault gibi kaynaklardan çözülmesini sağlayan SAĞLAYICI-
// BAĞIMSIZ bir arayüzdür (§13). Çağıranlar kaynak değişse de aynı Provider arayüzünü
// kullanır. Ayrıca anahtar-rotasyonu (KeyRing) ve loglama için maskeleme (Redact) sağlar.
//
// Saf-Go, dış bağımlılık yok. Ortam/dosya erişimleri enjekte edilebilir (test dostu).
package secrets

import (
	"os"
	"strings"
	"sync"
)

// Provider, ada göre bir sırrı çözer. ok=false → bu sağlayıcıda yok (hata değil).
type Provider interface {
	Get(name string) (value string, ok bool, err error)
}

// EnvProvider, ortam değişkenlerinden sır okur: os.Getenv(Prefix+name). lookup
// enjekte edilebilir (test gerçek ortama dokunmadan).
type EnvProvider struct {
	Prefix string
	lookup func(string) (string, bool) // nil → os.LookupEnv
}

// NewEnvProvider, verilen önekle bir ortam sağlayıcısı kurar (ör. "XEMS_").
func NewEnvProvider(prefix string) *EnvProvider { return &EnvProvider{Prefix: prefix} }

// SetLookup, ortam arama işlevini değiştirir (test). Zincirlenebilir.
func (p *EnvProvider) SetLookup(f func(string) (string, bool)) *EnvProvider {
	p.lookup = f
	return p
}

func (p *EnvProvider) Get(name string) (string, bool, error) {
	look := p.lookup
	if look == nil {
		look = os.LookupEnv
	}
	v, ok := look(p.Prefix + name)
	return v, ok, nil
}

// FileProvider, Docker/K8s tarzı dosya-sırlarını okur: <Dir>/<name> (kırpılmış).
// name'de yol ayracı veya ".." olmasını reddeder (dizin-dışına kaçış koruması).
type FileProvider struct {
	Dir  string
	read func(string) ([]byte, error) // nil → os.ReadFile
}

// NewFileProvider, verilen dizinden okuyan bir dosya sağlayıcısı kurar.
func NewFileProvider(dir string) *FileProvider { return &FileProvider{Dir: dir} }

// SetReader, dosya okuma işlevini değiştirir (test). Zincirlenebilir.
func (p *FileProvider) SetReader(f func(string) ([]byte, error)) *FileProvider {
	p.read = f
	return p
}

func (p *FileProvider) Get(name string) (string, bool, error) {
	if !safeName(name) {
		return "", false, nil // güvensiz ad → yok say (kaçışa izin verme)
	}
	read := p.read
	if read == nil {
		read = os.ReadFile
	}
	b, err := read(p.Dir + "/" + name)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil // dosya yok → bu sağlayıcıda yok (hata değil)
		}
		return "", false, err
	}
	return strings.TrimSpace(string(b)), true, nil
}

// safeName, sır adının dizin-dışına kaçış içermediğini doğrular.
func safeName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return false
	}
	return true
}

// MapProvider, bellek-içi bir sır haritasıdır (test/varsayılan).
type MapProvider map[string]string

func (m MapProvider) Get(name string) (string, bool, error) {
	v, ok := m[name]
	return v, ok, nil
}

// Chain, sağlayıcıları sırayla dener ve İLK bulanı döner (geri-düşüş çözücü).
type Chain struct {
	providers []Provider
}

// NewChain, verilen sağlayıcılardan (öncelik sırasıyla) bir zincir kurar.
func NewChain(providers ...Provider) *Chain { return &Chain{providers: providers} }

func (c *Chain) Get(name string) (string, bool, error) {
	for _, p := range c.providers {
		v, ok, err := p.Get(name)
		if err != nil {
			return "", false, err
		}
		if ok {
			return v, true, nil
		}
	}
	return "", false, nil
}

// Rotatable, çalışma-zamanı anahtar rotasyonunu destekleyen sağlayıcı arayüzüdür.
type Rotatable interface {
	Rotate(name string) error
}

// KeyRing, güncel + önceki anahtar malzemesini tutar (rotasyon örtüşmesi: yeni ile
// imzala, eski ile de doğrula). Eşzamanlı-güvenli.
type KeyRing struct {
	mu      sync.RWMutex
	current string            // güncel sürüm etiketi
	order   []string          // ekleme sırası (en yeni sonda)
	keys    map[string][]byte // sürüm → anahtar
	max     int               // tutulacak azami sürüm (eski olanlar tahliye)
}

// NewKeyRing, en çok max sürüm tutan bir anahtar halkası kurar (max<1 → 2).
func NewKeyRing(max int) *KeyRing {
	if max < 1 {
		max = 2
	}
	return &KeyRing{keys: map[string][]byte{}, max: max}
}

// Add, bir sürümü ekler ve güncel yapar. Aynı sürüm varsa anahtarını günceller.
func (k *KeyRing) Add(version string, key []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, exists := k.keys[version]; !exists {
		k.order = append(k.order, version)
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	k.keys[version] = cp
	k.current = version
	// Azami aşıldıysa en eski sürümleri tahliye et.
	for len(k.order) > k.max {
		oldest := k.order[0]
		k.order = k.order[1:]
		delete(k.keys, oldest)
	}
}

// Current, güncel sürüm etiketini ve anahtarını döner (imzalama/şifreleme için).
func (k *KeyRing) Current() (version string, key []byte) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current, k.copyLocked(k.current)
}

// Get, belirli bir sürümün anahtarını döner (eski imzayı doğrulama için).
func (k *KeyRing) Get(version string) ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if _, ok := k.keys[version]; !ok {
		return nil, false
	}
	return k.copyLocked(version), true
}

// Versions, tutulan sürümleri ekleme sırasıyla (en eski→en yeni) döner.
func (k *KeyRing) Versions() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]string, len(k.order))
	copy(out, k.order)
	return out
}

func (k *KeyRing) copyLocked(version string) []byte {
	key, ok := k.keys[version]
	if !ok {
		return nil
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	return cp
}

// Redact, bir sırrı loglama için maskeler: ilk 2 + son 2 karakter korunur, orta
// yıldızlanır. Çok kısa değerler tamamen maskelenir. Tam değeri asla döndürmez.
func Redact(s string) string {
	n := len(s)
	if n == 0 {
		return ""
	}
	if n <= 4 {
		return strings.Repeat("*", n)
	}
	return s[:2] + strings.Repeat("*", n-4) + s[n-2:]
}

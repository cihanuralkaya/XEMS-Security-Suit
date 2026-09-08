// Package usbmon, çıkarılabilir medyayı (USB depolama) tespit eder — veri-sızıntısı
// / kötü-amaçlı-medya görünürlüğü (DLP-bitişik). OS-özel sorgular exec/sysfs ile
// yapılır; ayrıştırma platform-bağımsız ve test edilebilir tutulur (inventory/
// resource ile aynı desen). Politika: denetle (varsayılan) veya engelle
// (XEMS_USB_POLICY; engelleme güvenli-mod KAPALIYKEN uygulanır).
package usbmon

import (
	"errors"
	"strings"
)

// ErrBlockUnsupported, çıkarılabilir-medya engelleme bu platformda desteklenmediğinde döner.
var ErrBlockUnsupported = errors.New("usbmon: engelleme bu platformda desteklenmiyor")

// Drive, çıkarılabilir bir depolama aygıtıdır.
type Drive struct {
	ID    string // Windows sürücü harfi (E:) veya Linux aygıtı (/dev/sdb)
	Label string // birim etiketi (varsa)
}

// Key, tekilleştirme anahtarıdır (yeni-takma takibi için).
func (d Drive) Key() string { return d.ID }

// Scanner, OS-özel çıkarılabilir-medya numaralandırması sağlar.
type Scanner interface {
	// Scan, takılı çıkarılabilir sürücüleri döner. Alınamazsa boş.
	Scan() []Drive
}

// Scan, mevcut platformun çıkarılabilir sürücülerini döner.
func Scan() []Drive { return NewScanner().Scan() }

// parseWinDrives, Windows PowerShell çıktısını ("drive=E:|USB STICK" satırları)
// ayrıştırır. Etiket boş olabilir.
func parseWinDrives(out string) []Drive {
	var ds []Drive
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "drive=") {
			continue
		}
		rest := strings.TrimPrefix(line, "drive=")
		id, label := rest, ""
		if i := strings.IndexByte(rest, '|'); i >= 0 {
			id = strings.TrimSpace(rest[:i])
			label = strings.TrimSpace(rest[i+1:])
		}
		if id != "" {
			ds = append(ds, Drive{ID: id, Label: label})
		}
	}
	return ds
}

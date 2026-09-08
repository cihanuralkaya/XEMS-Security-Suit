// Package standdown, imzalı çevrimdışı offboard sonrası bırakılan "stand-down"
// işaret dosyasını yönetir.
//
// Akış: ajan geçerli (imzası + cihaz + expiry doğrulanmış) bir offboard jetonu
// gördüğünde bu işaret dosyasını yazar ve çıkar. Watchdog, ajanı yeniden
// başlatmadan ÖNCE işareti kontrol eder; varsa gözetimi bırakır. Böylece
// tamper-koruması (karşılıklı yeniden başlatma) yalnız YETKİLİ imzalı bir
// eylemle sonlandırılabilir — kaza veya saldırıyla değil.
package standdown

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// markerName, dataDir içindeki işaret dosyasının adıdır.
const markerName = "offboard.standdown"

// Path, verilen ajan veri dizinindeki işaret dosyasının tam yolunu döndürür.
func Path(dataDir string) string {
	return filepath.Join(dataDir, markerName)
}

// Write, işaret dosyasını yazar. İçerik yalnız denetim (audit) içindir; varlığı
// belirleyicidir. Zaten varsa üzerine yazılır (idempotent).
func Write(dataDir, deviceID, reason string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	body := "device=" + deviceID + "\n" +
		"at=" + time.Now().UTC().Format(time.RFC3339) + "\n" +
		"reason=" + strings.ReplaceAll(reason, "\n", " ") + "\n"
	return os.WriteFile(Path(dataDir), []byte(body), 0o600)
}

// Exists, işaret dosyasının var olup olmadığını döndürür.
func Exists(dataDir string) bool {
	_, err := os.Stat(Path(dataDir))
	return err == nil
}

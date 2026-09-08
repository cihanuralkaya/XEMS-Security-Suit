// Package deviceaction, MDM uzaktan cihaz eylemlerini (ekran kilitleme, yeniden
// başlatma, veri silme) OS-özel olarak uygular. Yıkıcı eylemler (RESTART/WIPE)
// yalnız güvenli-mod KAPALIYKEN çağrılır (çağıran katman güvenli-modu denetler).
//
// WIPE, geri döndürülemez KRİPTO-SİLME'dir: disk şifreleme anahtarını yok ederek
// tüm veriyi anında kurtarılamaz kılar (Windows: BitLocker koruyucuları + zorla
// kurtarma; Linux: cryptsetup luksErase). GERİ DÖNÜŞÜ YOKTUR. Bu yüzden ÜÇ bağımsız
// güvenlik katmanı gerekir: (1) sunucu RBAC (WIPE → ADMIN), (2) ajan güvenli-mod
// KAPALI, (3) ajan açıkça ARM'lı (XDR_ALLOW_WIPE=1). Üçü de sağlanmadıkça WIPE yalnız
// bir olay üretir, veri SİLİNMEZ — kazara/yanlış-yapılandırma kaynaklı veri kaybını önler.
package deviceaction

import (
	"errors"
	"os"
)

// ErrWipeNotArmed, WIPE komutu alındığında ama ajan gerçek silmeye ARM'lanmadığında
// (XDR_ALLOW_WIPE=1 değil) döner — kazara veri kaybını önleyen üçüncü güvenlik katmanı.
var ErrWipeNotArmed = errors.New("deviceaction: WIPE ARM'lanmadı — gerçek silme için ajanda XDR_ALLOW_WIPE=1 gerekir")

// ErrActionUnsupported, eylem bu platformda desteklenmediğinde döner.
var ErrActionUnsupported = errors.New("deviceaction: bu eylem bu platformda desteklenmiyor")

// WipeArmed, ajanın gerçek (yıkıcı) silmeye açıkça izin verilip verilmediğini döner.
// Yalnız XDR_ALLOW_WIPE=1 iken true. Sunucu RBAC'ı ve güvenli-moddan BAĞIMSIZ EK bir
// kilittir; üretim-dışı/yanlış yapılandırılmış dağıtımlarda kazara wipe'ı önler.
func WipeArmed() bool { return os.Getenv("XDR_ALLOW_WIPE") == "1" }

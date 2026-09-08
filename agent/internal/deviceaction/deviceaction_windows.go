//go:build windows

package deviceaction

import "os/exec"

// Lock, çalışma istasyonunun ekranını kilitler (LockWorkStation).
func Lock() error {
	return exec.Command("rundll32.exe", "user32.dll,LockWorkStation").Run()
}

// Restart, cihazı 60 sn gecikmeyle yeniden başlatır (kullanıcıya uyarı penceresi).
func Restart() error {
	return exec.Command("shutdown", "/r", "/t", "60", "/c", "XEMS uzaktan yeniden baslatma").Run()
}

// Wipe, sistem sürücüsünü (C:) KRİPTO-SİLME ile geri döndürülemez kılar: BitLocker
// anahtar koruyucularını (kurtarma anahtarı dahil) siler ve zorla kurtarma moduna
// alır. Anahtar yok + kurtarma anahtarı yok → şifreli veri kurtarılamaz. GERİ
// DÖNÜŞÜ YOKTUR. Yalnız ARM'lı (XEMS_ALLOW_WIPE=1) ve güvenli-mod KAPALI iken
// çağrılır — çağıran (agent) bu katmanları denetler. BitLocker etkin değilse
// koruyucu-silme etkisizdir; bu sürüm şifrelenmemiş diskte gerçek veri imhası
// yapmaz (kripto-silme şifreleme gerektirir) — zorla kurtarma yine de erişimi kilitler.
func Wipe() error {
	// Tüm BitLocker anahtar koruyucularını sil → şifreleme anahtarı yeniden
	// türetilemez (kurtarma anahtarı dahil kaldırılır).
	_ = exec.Command("manage-bde", "-protectors", "-delete", "C:").Run()
	// Zorla kurtarma: yeniden başlatmada sürücü kilitlenir; anahtar olmadan açılamaz.
	return exec.Command("manage-bde", "-forcerecovery", "C:").Run()
}

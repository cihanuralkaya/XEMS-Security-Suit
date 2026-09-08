//go:build linux

package deviceaction

import (
	"errors"
	"os"
	"os/exec"
)

// Lock, oturumları kilitler (loginctl lock-sessions).
func Lock() error {
	return exec.Command("loginctl", "lock-sessions").Run()
}

// Restart, cihazı yeniden başlatır (systemctl reboot).
func Restart() error {
	return exec.Command("systemctl", "reboot").Run()
}

// Wipe, LUKS şifreli aygıtın anahtar slotlarını yok ederek (cryptsetup luksErase)
// veriyi geri döndürülemez kılar — KRİPTO-SİLME. Master anahtar imha edilir; şifreli
// veri kurtarılamaz. GERİ DÖNÜŞÜ YOKTUR. Yanlış aygıtı silmeyi önlemek için hedef
// LUKS aygıtı AÇIKÇA XEMS_WIPE_DEVICE ile verilmelidir (otomatik tahmin YOK). Yalnız
// ARM'lı (XEMS_ALLOW_WIPE=1) ve güvenli-mod KAPALI iken çağrılır (agent denetler).
func Wipe() error {
	dev := os.Getenv("XEMS_WIPE_DEVICE")
	if dev == "" {
		return errors.New("deviceaction: XEMS_WIPE_DEVICE ayarlı değil (silinecek LUKS aygıtı; yanlış-aygıt koruması)")
	}
	return exec.Command("cryptsetup", "luksErase", "--batch-mode", dev).Run()
}

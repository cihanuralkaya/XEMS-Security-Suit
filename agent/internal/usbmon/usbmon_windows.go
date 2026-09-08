//go:build windows

package usbmon

import "os/exec"

type winScanner struct{}

// NewScanner, mevcut platform için tarayıcı döner.
func NewScanner() Scanner { return winScanner{} }

// psScript, DriveType=2 (Removable) mantıksal diskleri key=value biçiminde döndürür.
const psScript = `Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" | ForEach-Object { Write-Output ("drive="+$_.DeviceID+"|"+$_.VolumeName) }`

// Scan, çıkarılabilir mantıksal diskleri (CIM) toplar.
func (winScanner) Scan() []Drive {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript).Output()
	if err != nil {
		return nil
	}
	return parseWinDrives(string(out))
}

// Block, verilen çıkarılabilir sürücüyü (sürücü harfi, ör. "E:") bağlama noktasını
// kaldırıp dismount ederek erişime kapatır (mountvol /p). HEDEFLİDİR (yalnız bu
// sürücü) ve GERİ DÖNÜŞTÜRÜLEBİLİR (yeniden takma ile erişim geri gelir). Yalnız
// güvenli-mod KAPALIYKEN ve politika "block" iken çağrılır (çağıran denetler).
func Block(driveID string) error {
	return exec.Command("mountvol", driveID, "/p").Run()
}

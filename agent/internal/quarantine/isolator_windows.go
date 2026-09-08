//go:build windows

package quarantine

import (
	"fmt"
	"os/exec"
)

// winIsolator, Windows Defender Firewall ile izolasyon uygular.
//
// Yaklaşım: varsayılan çıkış/giriş politikasını BLOK yap, sonra yalnız C2'ye
// ALLOW kuralı ekle. (Açık block kuralı allow'dan önceliklidir; bu yüzden
// "block-all" kuralı yerine VARSAYILAN POLİTİKA blok'a alınır ve allow kuralları
// istisna oluşturur.)
//
// UYARI: Yönetici (SYSTEM) yetkisi gerektirir ve makinenin ağını gerçekten
// keser. Bu kod CANLI TEST EDİLMEDİ; yalnız derleme ile doğrulanmıştır.
type winIsolator struct{}

// NewIsolator, mevcut platform için izolatör döner.
func NewIsolator() Isolator { return winIsolator{} }

const allowRulePrefix = "XEMS-Quarantine-Allow-C2"

func (winIsolator) Isolate(allowC2 []string) error {
	// Varsayılan politikayı blok yap.
	if err := netsh("advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"); err != nil {
		return err
	}
	// C2 adreslerine istisna (hem giriş hem çıkış).
	for i, ip := range allowC2 {
		if ip == "" {
			continue
		}
		nameOut := fmt.Sprintf("%s-out-%d", allowRulePrefix, i)
		nameIn := fmt.Sprintf("%s-in-%d", allowRulePrefix, i)
		if err := netsh("advfirewall", "firewall", "add", "rule", "name="+nameOut, "dir=out", "action=allow", "remoteip="+ip); err != nil {
			return err
		}
		if err := netsh("advfirewall", "firewall", "add", "rule", "name="+nameIn, "dir=in", "action=allow", "remoteip="+ip); err != nil {
			return err
		}
	}
	return nil
}

func (winIsolator) Release() error {
	// Varsayılan politikayı normale (çıkışa izin) döndür.
	if err := netsh("advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"); err != nil {
		return err
	}
	// XEMS allow kurallarını temizle (indeksli; makul bir üst sınıra kadar).
	for i := 0; i < 32; i++ {
		_ = netsh("advfirewall", "firewall", "delete", "rule", "name="+fmt.Sprintf("%s-out-%d", allowRulePrefix, i))
		_ = netsh("advfirewall", "firewall", "delete", "rule", "name="+fmt.Sprintf("%s-in-%d", allowRulePrefix, i))
	}
	return nil
}

func netsh(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %v: %w: %s", args, err, out)
	}
	return nil
}

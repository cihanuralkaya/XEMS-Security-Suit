//go:build !windows

package quarantine

import (
	"fmt"
	"os/exec"
)

// iptIsolator, Linux'ta iptables ile izolasyon uygular.
//
// Yaklaşım: özel bir XEMS-QUARANTINE zinciri oluşturulur — loopback ve C2'ye
// ACCEPT, geri kalan her şeye DROP — ve OUTPUT zincirinin başına eklenir.
// Release, atlamayı kaldırıp zinciri temizler.
//
// UYARI: root yetkisi gerektirir ve ağı gerçekten keser. CANLI TEST EDİLMEDİ;
// yalnız derleme ile doğrulanmıştır. macOS'ta iptables yoktur (pf gerekir).
type iptIsolator struct{}

// NewIsolator, mevcut platform için izolatör döner.
func NewIsolator() Isolator { return iptIsolator{} }

const chain = "XEMS-QUARANTINE"

func (iptIsolator) Isolate(allowC2 []string) error {
	_ = ipt("-N", chain) // zincir varsa hata yok sayılır
	if err := ipt("-F", chain); err != nil {
		return err
	}
	if err := ipt("-A", chain, "-o", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	for _, ip := range allowC2 {
		if ip == "" {
			continue
		}
		if err := ipt("-A", chain, "-d", ip, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	if err := ipt("-A", chain, "-j", "DROP"); err != nil {
		return err
	}
	// Zinciri OUTPUT'un başına ekle (yoksa).
	if err := ipt("-C", "OUTPUT", "-j", chain); err != nil {
		return ipt("-I", "OUTPUT", "-j", chain)
	}
	return nil
}

func (iptIsolator) Release() error {
	_ = ipt("-D", "OUTPUT", "-j", chain)
	_ = ipt("-F", chain)
	_ = ipt("-X", chain)
	return nil
}

func ipt(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v: %w: %s", args, err, out)
	}
	return nil
}

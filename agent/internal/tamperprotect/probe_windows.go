//go:build windows

package tamperprotect

import (
	"os"
	"path/filepath"
)

// defaultDriverName, gelecekteki XEMS MiniFilter koruma sürücüsünün adıdır.
const defaultDriverName = "xemsflt"

// KernelDriverProbe, çekirdek koruma sürücüsünün mevcut olup olmadığını YOKLAR:
// %SystemRoot%\System32\drivers\<name>.sys var mı? Ayrıcalıksız, güvenli kontrol.
// Sürücü ayrı bir C/C++ + WHQL projesi olduğundan bu depoda sürücü SEVK EDİLMEZ →
// pratikte false döner; ancak sürücü kurulursa seam otomatik "kernel" seviyesine geçer.
func KernelDriverProbe() (present bool, name string) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	p := filepath.Join(root, "System32", "drivers", defaultDriverName+".sys")
	if _, err := os.Stat(p); err == nil {
		return true, defaultDriverName
	}
	return false, ""
}

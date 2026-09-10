//go:build !windows

package tamperprotect

// KernelDriverProbe, Windows-dışı platformlarda çekirdek koruma sürücüsü olmadığını
// döner (XEMS MiniFilter yalnız Windows'tur). Linux/macOS'ta userland savunma-derinliği
// (watchdog, canlılık, FIM, öz-tasdik) geçerlidir.
func KernelDriverProbe() (present bool, name string) { return false, "" }

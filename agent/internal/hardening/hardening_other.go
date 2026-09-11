//go:build !linux

package hardening

import "runtime"

// probe, Linux-dışı platformlarda (ör. Windows) seccomp/NoNewPrivs kavramları
// olmadığından bilinmeyen/uygulanamaz bir duruş döner. Windows'ta hizmet-seviyesi
// sertleştirme (korumalı hizmet, WDAC) ayrı bir mekanizmayla değerlendirilir
// (bkz. deploy/HARDENING.md); bu paket Linux çalışma-zamanı sinyallerine odaklanır.
func probe() Posture {
	// Ayrıcalık tespiti (Windows admin/UAC) güvenilir biçimde ek syscall gerektirir;
	// bu sürümde belirsiz bırakılır (false). Linux çalışma-zamanı sinyalleri (seccomp/
	// NoNewPrivs) burada uygulanamaz.
	return Posture{
		Platform:   runtime.GOOS,
		Seccomp:    SeccompUnknown,
		NoNewPrivs: false,
		Privileged: false,
	}
}

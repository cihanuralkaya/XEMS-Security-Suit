// Package tamperprotect, ajanın KURCALAMA-KORUMA DURUŞUNU (tamper-protection posture)
// raporlar: hangi savunmalar aktif ve çekirdek-seviye koruma sürücüsü mevcut mu.
//
// GERÇEK çekirdek-seviye koruma (Windows MiniFilter + PPL/ELAM) Go kod tabanının
// DIŞINDA, ayrı bir C/C++ + WHQL-imzalı sürücü projesidir (bkz. docs/KERNEL-TAMPER.md).
// Bu paket, o sürücünün varlığını SORGULAYAN kararlı bir arayüz (seam) sağlar ve
// sürücü yokken ajanın USERLAND savunma-derinliğini (watchdog, çift-süreç canlılık,
// dosya bütünlüğü, öz-tasdik, imzalı OTA) özetler. Böylece savunmacı, uç noktanın
// gerçek koruma durumunu bilir — "ilk savunma" mı yoksa "çekirdek-destekli" mi.
//
// Assess SAF ve testlidir; çekirdek-sürücü yoklaması platforma özgüdür (probe.go).
package tamperprotect

import (
	"sort"
	"strings"
)

// Posture, bir uç noktanın kurcalama-koruma durumudur.
type Posture struct {
	Userland         []string `json:"userland"`           // aktif userland savunmaları (sıralı)
	KernelDriver     bool     `json:"kernel_driver"`      // çekirdek koruma sürücüsü mevcut mu
	KernelDriverName string   `json:"kernel_driver_name"` // varsa sürücü adı
	Level            string   `json:"level"`              // "none" | "userland" | "kernel"
	Summary          string   `json:"summary"`            // insan-okur özet (olay mesajı)
	// Aşağıdakiler yalnız çekirdek sürücüsü YÜKLÜ ve iletişim portu erişilebilirse
	// (DriverStatus) doldurulur — "diskte mevcut"tan "yüklü + filtreliyor"a yükseltir.
	KernelActive    bool   `json:"kernel_active,omitempty"`     // sürücü yüklü + filtreliyor mu
	KernelDeniedOps uint64 `json:"kernel_denied_ops,omitempty"` // çekirdekte engellenen kurcalama sayısı
}

// TamperEvent, çekirdek sürücüsünün ilettiği tek bir kurcalama-engelleme olayıdır
// (StreamTamperEvents ile alınır). Platform-bağımsız tanımlı (Windows-dışında kullanılmaz).
type TamperEvent struct {
	Kind     uint32 // XEMSFLT_EVENT_KIND (inc/xemsflt_ioctl.h)
	ActorPID uint32 // kurcalamayı deneyen süreç
	Target   string // hedef yol ya da "protected-process"
}

// Defenses, hangi userland savunmalarının etkin olduğunu belirtir (ajan main'den gelir).
type Defenses struct {
	Watchdog   bool // çift-süreç gözetim + swap/rollback
	Liveness   bool // çift-süreç karşılıklı canlılık (peerguard/beacon)
	FIM        bool // dosya bütünlüğü izleme
	SelfAttest bool // ikili takas/yama öz-tasdiki
	SignedOTA  bool // Ed25519 imzalı güncelleme (sahte güncelleme reddi)
}

// Assess, etkin userland savunmaları ve çekirdek-sürücü durumundan bir Posture üretir.
// Level: sürücü varsa "kernel"; yoksa en az bir userland savunması varsa "userland";
// hiçbiri yoksa "none". SAF fonksiyon.
func Assess(d Defenses, kernelPresent bool, kernelName string) Posture {
	var ul []string
	if d.Watchdog {
		ul = append(ul, "watchdog")
	}
	if d.Liveness {
		ul = append(ul, "dual-process-liveness")
	}
	if d.FIM {
		ul = append(ul, "file-integrity")
	}
	if d.SelfAttest {
		ul = append(ul, "self-attestation")
	}
	if d.SignedOTA {
		ul = append(ul, "signed-ota")
	}
	sort.Strings(ul)

	p := Posture{Userland: ul, KernelDriver: kernelPresent, KernelDriverName: kernelName}
	switch {
	case kernelPresent:
		p.Level = "kernel"
		name := kernelName
		if name == "" {
			name = "present"
		}
		p.Summary = "kurcalama koruması: ÇEKİRDEK-destekli (sürücü: " + name + ") + userland: " + join(ul)
	case len(ul) > 0:
		p.Level = "userland"
		p.Summary = "kurcalama koruması: USERLAND savunma-derinliği (" + join(ul) + "); çekirdek sürücüsü yok"
	default:
		p.Level = "none"
		p.Summary = "kurcalama koruması: ETKİN DEĞİL"
	}
	return p
}

func join(s []string) string {
	if len(s) == 0 {
		return "yok"
	}
	return strings.Join(s, ", ")
}

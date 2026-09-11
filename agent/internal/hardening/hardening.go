// Package hardening, ajanın ÇALIŞMA-ZAMANI SERTLEŞTİRME DURUŞUNU (hardening posture)
// raporlar (§10): süreç yeni-ayrıcalık kazanabilir mi (NoNewPrivs), seccomp filtresi
// etkin mi, ayrıcalıklı (root/admin) mı çalışıyor. Böylece SOC, her uç noktanın OS-
// seviye sertleştirme durumunu bilir — systemd birimi (deploy/systemd) uygulanabilir
// korumaları zorlar; bu paket bunların GERÇEKTEN etkin olup olmadığını doğrular.
//
// Ayrıştırma SAF ve testlidir; OS okuması platforma özgüdür (hardening_linux.go /
// hardening_other.go). Dış bağımlılık yok.
package hardening

import (
	"sort"
	"strings"
)

// SeccompMode, sürecin seccomp durumudur.
type SeccompMode string

const (
	SeccompDisabled SeccompMode = "disabled" // seccomp yok
	SeccompStrict   SeccompMode = "strict"   // SECCOMP_MODE_STRICT
	SeccompFilter   SeccompMode = "filter"   // SECCOMP_MODE_FILTER (BPF filtresi)
	SeccompUnknown  SeccompMode = "unknown"  // belirlenemedi (ör. Windows/eski çekirdek)
)

// Posture, ajanın sertleştirme durumudur.
type Posture struct {
	Platform   string      `json:"platform"`     // "linux" | "windows" | ...
	NoNewPrivs bool        `json:"no_new_privs"` // ayrıcalık yükseltme engelli mi
	Seccomp    SeccompMode `json:"seccomp"`      // seccomp kipi
	Privileged bool        `json:"privileged"`   // root/admin mı çalışıyor
	Measures   []string    `json:"measures"`     // etkin sertleştirme önlemleri (sıralı)
	Summary    string      `json:"summary"`      // insan-okunur özet (olay mesajı)
}

// Summarize, duruş alanlarından etkin önlem listesini ve özet cümlesini türetir.
// SAF fonksiyon (platform okumasından bağımsız test edilebilir).
func Summarize(p Posture) Posture {
	var m []string
	if p.NoNewPrivs {
		m = append(m, "no-new-privs")
	}
	switch p.Seccomp {
	case SeccompFilter:
		m = append(m, "seccomp-filter")
	case SeccompStrict:
		m = append(m, "seccomp-strict")
	}
	if !p.Privileged {
		m = append(m, "unprivileged")
	}
	sort.Strings(m)
	p.Measures = m

	lvl := "zayıf"
	switch {
	case p.NoNewPrivs && (p.Seccomp == SeccompFilter || p.Seccomp == SeccompStrict):
		lvl = "güçlü"
	case p.NoNewPrivs || p.Seccomp == SeccompFilter:
		lvl = "orta"
	}
	if len(m) == 0 {
		p.Summary = "sertleştirme duruşu: " + lvl + " (önlem yok)"
	} else {
		p.Summary = "sertleştirme duruşu: " + lvl + " (" + strings.Join(m, ", ") + ")"
	}
	return p
}

// Detect, geçerli sürecin sertleştirme duruşunu OS'tan okuyup özetleyerek döner
// (platform Probe'unu çağırır).
func Detect() Posture {
	return Summarize(probe())
}

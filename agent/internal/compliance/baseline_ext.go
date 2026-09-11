package compliance

// baseline_ext.go — GELİŞMİŞ MDM/UEM uyum kontrolleri (§31). Mevcut Checker'ı BOZMADAN,
// OPSİYONEL bir ExtendedChecker arayüzü ekler: bir platform bu ek sinyalleri (yama
// durumu, otomatik güncelleme, ekran kilidi, parola politikası, uygulama-kontrolü)
// sağlayabiliyorsa taban değerlendirmesine eklenir; sağlamıyorsa atlanır (geriye uyumlu).

// Ek sinyal sabitleri (on/off/current/outdated). unknown → skora dahil edilmez.
const (
	PatchCurrent  = "current"
	PatchOutdated = "outdated"
	SignalOn      = "on"
	SignalOff     = "off"
)

// ExtendedChecker, bir platform-checker'ının OPSİYONEL olarak sağlayabileceği ek MDM
// sinyalleridir. Checker bunu da uyguluyorsa Evaluate ek kontrolleri dahil eder.
// Her metot "on"/"off"/"unknown" (ya da yama için "current"/"outdated"/"unknown") döner.
type ExtendedChecker interface {
	// PatchStatus, işletim sistemi/güvenlik yamalarının güncel olup olmadığını döner.
	PatchStatus() string
	// AutoUpdate, otomatik güncellemenin etkin olup olmadığını döner.
	AutoUpdate() string
	// ScreenLock, oturum/ekran kilidinin (parola/zaman aşımı) etkin olup olmadığını döner.
	ScreenLock() string
	// PasswordPolicy, parola politikasının (karmaşıklık/uzunluk) uygulanıp uygulanmadığını döner.
	PasswordPolicy() string
	// AppControl, uygulama-kontrolü/allowlisting'in (WDAC/AppLocker/fapolicyd) etkin olup
	// olmadığını döner.
	AppControl() string
}

// extendedCatalog, ExtendedChecker sinyallerini CIS-tarzı kontrol satırlarına çevirir.
// chk ExtendedChecker DEĞİLSE boş döner (kontrol eklenmez).
func extendedCatalog(chk Checker) []catalogRow {
	ext, ok := chk.(ExtendedChecker)
	if !ok {
		return nil
	}
	return []catalogRow{
		{"CIS-3.1", "İşletim sistemi/güvenlik yamaları güncel", SevHigh, ext.PatchStatus(), PatchCurrent, PatchOutdated},
		{"CIS-3.2", "Otomatik güncelleme etkin", SevMedium, ext.AutoUpdate(), SignalOn, SignalOff},
		{"CIS-5.1", "Ekran/oturum kilidi etkin", SevMedium, ext.ScreenLock(), SignalOn, SignalOff},
		{"CIS-5.2", "Parola politikası uygulanıyor", SevMedium, ext.PasswordPolicy(), SignalOn, SignalOff},
		{"CIS-2.1", "Uygulama-kontrolü (allowlisting) etkin", SevHigh, ext.AppControl(), SignalOn, SignalOff},
	}
}

// catalogRow, tek bir kontrol katalog satırıdır (baseline.go ile paylaşılır).
type catalogRow struct {
	id, title, sev string
	signal         string
	on, off        string
}

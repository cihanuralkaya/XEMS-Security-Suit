# xemsflt — XEMS Tamper-Protection MiniFilter (kernel driver)

**Bu alt-ağaç Go değildir ve Go CI'ı tarafından derlenmez.** İçinde hiç `.go` dosyası
yoktur; `go build/test ./...`, gofmt, govulncheck, gosec ve release scripti bu dizini
**görmez** (Go araç zinciri `.go` içermeyen dizinleri atlar). Derlenmiş/imzalı `xemsflt.sys`
**asla commit edilmez** (`.gitignore`); yalnız kaynak sürülür.

> Bu bir **iskelettir** (correctness-of-intent). Gerçek kullanım öncesi Driver Verifier +
> adanmış test VM'de QA şarttır. **BSOD riski gerçektir.**

## Ne yapar

Windows çekirdeğinde kurcalamaya karşı koruma (userland savunmalarını tamamlar):
- **Süreç öldürme koruması** (`obcallbacks.c`): `ObRegisterCallbacks` ile ajan/watchdog
  süreçlerine açılan handle'lardan `PROCESS_TERMINATE`/`VM_WRITE`/`CREATE_THREAD`/
  `SUSPEND_RESUME` haklarını sıyırır → başka süreç ajanı öldüremez/enjekte edemez.
- **Dosya koruması** (`xemsflt.c`): ajan ikilisi + config üzerinde yazma/silme/rename
  IRP'lerini (`IRP_MJ_CREATE`, `IRP_MJ_SET_INFORMATION`) `STATUS_ACCESS_DENIED` ile reddeder.
- **User↔kernel port** (`comms.c`): `\XemsFltPort` üzerinden ajana durum + engellenen
  kurcalama olayları iletir (`inc/xemsflt_ioctl.h` ABI'si).

## Neden ayrı proje

C/C++ + WDK, çekirdek modu, **EV kod-imzalama sertifikası**, Microsoft **WHQL/attestation**
imzalaması ve **BSOD** riski gerektirir. Bkz. `../../docs/KERNEL-TAMPER.md`.

## Derleme (DEV)

EWDK ISO mount (LaunchBuildEnv.cmd) veya VS + "Windows Driver Kit" gerekir.

```powershell
.\build.ps1 -Config Release -Platform x64 -TestSign
```

## Dev imzalama + kurulum (yalnız test VM)

```powershell
bcdedit /set testsigning on        # yeniden başlat gerekir
.\build.ps1 -Release -TestSign     # sign-dev.ps1'i zincirler
.\install-dev.ps1 -Action install  # sc create + fltmc load
fltmc filters                      # xemsflt eklendi mi doğrula
.\install-dev.ps1 -Action uninstall
```

Sürücü `System32\drivers\xemsflt.sys`'e kopyalanınca, Go ajanının
`tamperprotect.KernelDriverProbe()` fonksiyonu `(true,"xemsflt")` döner ve başlangıç
SECURITY olayı `tamper_level="kernel"` gösterir (kod değişikliği gerekmez).

## Ajan arayüzü

`inc/xemsflt_ioctl.h` = paylaşılan ABI. Go tarafı:
`agent/internal/tamperprotect/driverclient_windows.go` (`fltlib.dll` üzerinden
`FilterConnectCommunicationPort`/`FilterSendMessage`/`FilterGetMessage`) — sürücüden
canlı durum (`GET_STATUS`) okur ve kurcalama olaylarını akıtır.

## Altitude

`385200` bir **yer-tutucudur** (Anti-Virus aralığı, yalnız dev). Üretim için Microsoft'tan
(`fsfcomm@microsoft.com`) kalıcı bir altitude talep edip `src/xemsflt.h` + `xemsflt.inf`
içinde değiştirin.

## Risk & kurtarma

- Sürücü `demand-start` + `ErrorControl=normal` → boot'u ASLA bloklamaz, opt-in.
- Bozulursa: `fltmc unload xemsflt` + `sc delete xemsflt`; kaldıramazsa **Safe Mode**'da
  `sc delete` + `.sys` sil; en kötü durumda `bcdedit /set testsigning off`.
- Ajan sürücüyü yalnız **algılar**, asla kurmaz.

## Üretim yapılacaklar (kullanıcı aksiyonu)

1. EV kod-imzalama sertifikası satın al (kuruluş kimlik doğrulaması).
2. Microsoft Partner Center kaydı (EV sertifikasıyla).
3. `fsfcomm@microsoft.com`'dan kalıcı altitude al; `385200`'ü değiştir.
4. `xemsflt.sys`'i attestation/WHQL imzalamasına gönder; Microsoft-imzalı katalog dağıt.

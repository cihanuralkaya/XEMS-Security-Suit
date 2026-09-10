//go:build windows

package tamperprotect

// Windows filter-manager (fltlib.dll) istemcisi: xemsflt.sys ile \XemsFltPort
// üzerinden konuşur — canlı durum (GET_STATUS) okur ve kurcalama olaylarını akıtır.
// ABI, driver/xemsflt/inc/xemsflt_ioctl.h ile BAYT-UYUMLU olmalıdır.
// Yeni bağımlılık YOK (golang.org/x/sys/windows zaten mevcut). Sürücü yoksa bağlantı
// hata döner ve çağıran dosya-yoklamasına (KernelDriverProbe) geri düşer.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fltlib               = windows.NewLazySystemDLL("fltlib.dll")
	procFilterConnect    = fltlib.NewProc("FilterConnectCommunicationPort")
	procFilterSend       = fltlib.NewProc("FilterSendMessage")
	procFilterGetMessage = fltlib.NewProc("FilterGetMessage")
)

const driverPortName = `\XemsFltPort`

// xemsRequest ~ XEMSFLT_REQUEST
type xemsRequest struct {
	Command uint32
	Arg     uint32
}

// xemsStatus ~ XEMSFLT_STATUS
type xemsStatus struct {
	Version        uint32
	Active         uint32
	ProtectedPids  uint32
	ProtectedPaths uint32
	DeniedOps      uint64
}

// filterMessageHeader ~ FILTER_MESSAGE_HEADER (ReplyLength ULONG + MessageId ULONGLONG).
type filterMessageHeader struct {
	ReplyLength uint32
	MessageID   uint64
}

// xemsEvent ~ XEMSFLT_EVENT (packed; doğal hizalama zaten dolgusuz).
type xemsEvent struct {
	Kind         uint32
	ActorPid     uint32
	TimestampQpc uint64
	Target       [260]uint16
}

// tamperMessage, FilterGetMessage'ın döndürdüğü tampon: header + olay.
type tamperMessage struct {
	Header filterMessageHeader
	Event  xemsEvent
}

func hrFail(r uintptr) bool { return int32(r) < 0 }

// DriverStatus, \XemsFltPort'a bağlanır ve GET_STATUS ister. Başarıda
// (active, deniedOps, nil) döner. Hata = sürücü erişilemez (yüklü değil / port yok);
// çağıran dosya-yoklaması sonucuna geri düşmelidir.
func DriverStatus() (active bool, deniedOps uint64, err error) {
	name, err := windows.UTF16PtrFromString(driverPortName)
	if err != nil {
		return false, 0, err
	}
	var port windows.Handle
	r, _, _ := procFilterConnect.Call(
		uintptr(unsafe.Pointer(name)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&port)))
	if hrFail(r) {
		return false, 0, fmt.Errorf("FilterConnectCommunicationPort: hresult 0x%08x", uint32(r))
	}
	defer windows.CloseHandle(port)

	in := xemsRequest{Command: 1} // XemsFltCmdGetStatus
	var out xemsStatus
	var retLen uint32
	r, _, _ = procFilterSend.Call(
		uintptr(port),
		uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in),
		uintptr(unsafe.Pointer(&out)), unsafe.Sizeof(out),
		uintptr(unsafe.Pointer(&retLen)))
	if hrFail(r) {
		return false, 0, fmt.Errorf("FilterSendMessage: hresult 0x%08x", uint32(r))
	}
	return out.Active != 0, out.DeniedOps, nil
}

// StreamTamperEvents, sürücü portuna bağlanır ve iletilen her kurcalama olayı için
// onEvent'i çağırır; port kapanana ya da hata olana dek BLOKLAR (kendi goroutine'inde
// çalıştırın). Olaylar mevcut olay hattına SECURITY olayı olarak beslenebilir.
func StreamTamperEvents(onEvent func(TamperEvent)) error {
	name, err := windows.UTF16PtrFromString(driverPortName)
	if err != nil {
		return err
	}
	var port windows.Handle
	r, _, _ := procFilterConnect.Call(
		uintptr(unsafe.Pointer(name)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&port)))
	if hrFail(r) {
		return fmt.Errorf("FilterConnectCommunicationPort: hresult 0x%08x", uint32(r))
	}
	defer windows.CloseHandle(port)

	for {
		var msg tamperMessage
		r, _, _ := procFilterGetMessage.Call(
			uintptr(port), uintptr(unsafe.Pointer(&msg)), unsafe.Sizeof(msg), 0)
		if hrFail(r) {
			return fmt.Errorf("FilterGetMessage: hresult 0x%08x", uint32(r))
		}
		onEvent(TamperEvent{
			Kind:     msg.Event.Kind,
			ActorPID: msg.Event.ActorPid,
			Target:   windows.UTF16ToString(msg.Event.Target[:]),
		})
	}
}

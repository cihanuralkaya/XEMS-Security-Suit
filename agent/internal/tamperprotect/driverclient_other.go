//go:build !windows

package tamperprotect

import "errors"

// errNoDriver, Windows-dışı platformlarda çekirdek sürücüsü olmadığını belirtir.
var errNoDriver = errors.New("tamperprotect: kernel driver client only available on windows")

// DriverStatus, Windows-dışında desteklenmez (XEMS MiniFilter yalnız Windows).
func DriverStatus() (active bool, deniedOps uint64, err error) {
	return false, 0, errNoDriver
}

// StreamTamperEvents, Windows-dışında desteklenmez.
func StreamTamperEvents(onEvent func(TamperEvent)) error {
	return errNoDriver
}

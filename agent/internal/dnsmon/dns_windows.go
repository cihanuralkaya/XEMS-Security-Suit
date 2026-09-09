//go:build windows

package dnsmon

import "os/exec"

type winScanner struct{}

// NewScanner, Windows DNS istemci önbelleğini okuyan bir tarayıcı döner.
func NewScanner() Scanner { return winScanner{} }

// Scan, `ipconfig /displaydns` çıktısındaki kayıt adlarını döner.
func (winScanner) Scan() []string {
	out, err := exec.Command("ipconfig", "/displaydns").Output()
	if err != nil {
		return nil
	}
	return parseIpconfigDisplayDNS(string(out))
}

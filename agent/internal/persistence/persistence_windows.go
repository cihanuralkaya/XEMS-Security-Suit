//go:build windows

package persistence

import "os/exec"

type winScanner struct{}

// NewScanner, mevcut platform için tarayıcı döner.
func NewScanner() Scanner { return winScanner{} }

// Scan, Run anahtarlarını (HKLM+HKCU) ve zamanlanmış görevleri toplar.
func (winScanner) Scan() []Entry {
	var es []Entry
	for _, root := range []string{
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
	} {
		if out, err := exec.Command("reg", "query", root).Output(); err == nil {
			es = append(es, parseRunKeys(string(out))...)
		}
	}
	if out, err := exec.Command("schtasks", "/query", "/fo", "csv", "/nh").Output(); err == nil {
		es = append(es, parseSchtasks(string(out))...)
	}
	return es
}

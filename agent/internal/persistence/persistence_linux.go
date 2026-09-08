//go:build linux

package persistence

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type linuxScanner struct{}

// NewScanner, mevcut platform için tarayıcı döner.
func NewScanner() Scanner { return linuxScanner{} }

// Scan, cron girdilerini (/etc/crontab, /etc/cron.d/*, kullanıcı crontab'ı) ve
// etkin systemd servislerini toplar.
func (linuxScanner) Scan() []Entry {
	var es []Entry
	files := []string{"/etc/crontab"}
	if m, err := filepath.Glob("/etc/cron.d/*"); err == nil {
		files = append(files, m...)
	}
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			es = append(es, parseCron(string(b))...)
		}
	}
	if out, err := exec.Command("crontab", "-l").Output(); err == nil {
		es = append(es, parseCron(string(out))...)
	}
	if out, err := exec.Command("systemctl", "list-unit-files", "--type=service",
		"--state=enabled", "--no-legend", "--no-pager").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.HasSuffix(fields[0], ".service") {
				es = append(es, Entry{Kind: SystemdUnit, Name: fields[0]})
			}
		}
	}
	return es
}

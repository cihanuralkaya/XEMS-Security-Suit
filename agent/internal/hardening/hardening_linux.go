//go:build linux

package hardening

import (
	"os"
	"strings"
)

// probe, Linux'ta /proc/self/status'tan sertleştirme sinyallerini okur.
func probe() Posture {
	p := Posture{Platform: "linux", Seccomp: SeccompUnknown, Privileged: os.Geteuid() == 0}
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		return parseProcStatus(string(data), p.Privileged)
	}
	return p
}

// parseProcStatus, /proc/<pid>/status içeriğini bir Posture'a ayrıştırır. SAF/testli:
// "NoNewPrivs:\t1" ve "Seccomp:\t2" (0=disabled,1=strict,2=filter) satırlarını okur.
func parseProcStatus(content string, privileged bool) Posture {
	p := Posture{Platform: "linux", Seccomp: SeccompUnknown, Privileged: privileged}
	for _, line := range strings.Split(content, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "NoNewPrivs":
			p.NoNewPrivs = val == "1"
		case "Seccomp":
			switch val {
			case "0":
				p.Seccomp = SeccompDisabled
			case "1":
				p.Seccomp = SeccompStrict
			case "2":
				p.Seccomp = SeccompFilter
			}
		}
	}
	return p
}

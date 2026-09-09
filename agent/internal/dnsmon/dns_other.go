//go:build !windows

package dnsmon

// Windows dışı platformlarda standart bir DNS önbellek okuma yolu olmadığından
// toplama şu an desteklenmez (skorlama motoru yine de kullanılabilir). İleride
// journald/systemd-resolved veya pcap tabanlı toplama eklenebilir.
type noopScanner struct{}

// NewScanner, Windows-dışı için boş tarayıcı döner.
func NewScanner() Scanner { return noopScanner{} }

func (noopScanner) Scan() []string { return nil }

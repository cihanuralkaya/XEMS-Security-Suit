package dnsmon

import "strings"

// Scanner, OS DNS önbelleğinden sorgulanan alan adlarını toplar.
type Scanner interface {
	// Scan, önbellekteki benzersiz alan adlarını döner (hata → boş).
	Scan() []string
}

// parseIpconfigDisplayDNS, Windows `ipconfig /displaydns` çıktısından kayıt
// adlarını ("Record Name . . . : example.com") ayrıştırır. Türkçe Windows'ta
// "Kayıt Adı" da desteklenir. Sonuç benzersiz + küçük harftir.
func parseIpconfigDisplayDNS(out string) []string {
	seen := map[string]bool{}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if !strings.HasPrefix(low, "record name") && !strings.HasPrefix(low, "kayıt adı") {
			continue
		}
		// ": " sonrası alan adı.
		idx := strings.LastIndex(l, ":")
		if idx < 0 || idx+1 >= len(l) {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(l[idx+1:]))
		name = strings.TrimSuffix(name, ".")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// parseResolvectlStatistics, Linux `resolvectl --no-pager statistics` gibi
// çıktılarda alan adı çıkmadığından KULLANILMAZ; Linux toplama şu an
// desteklenmez (dns_other.go boş döner). Bu yorum, ileride journald/pcap tabanlı
// toplama için yer tutucudur.

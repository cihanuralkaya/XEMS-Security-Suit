package beacon

import (
	"net"
	"sort"
	"time"
)

// Bu dosya, YANAL HAREKET (lateral movement) / iç-ağ tarama tespiti sağlar: bir uç
// noktanın kısa bir pencerede ÇOK SAYIDA farklı İÇ (private) ana bilgisayara giden
// bağlantısı, klasik bir yanal-hareket / keşif imzasıdır (beacon periyodikliğinden
// FARKLI bir sinyal — burada dağılma/fan-out sayılır). Saf istatistik, testli.

// FanOutFinding, olası bir yanal-hareket bulgusudur.
type FanOutFinding struct {
	DeviceID      string        // kaynak uç nokta
	DistinctPeers int           // pencerede ulaşılan farklı iç IP sayısı
	Window        time.Duration // değerlendirme penceresi
}

// isPrivateIP, bir IP'nin RFC1918/ULA özel (iç ağ) olup olmadığını döner. Loopback
// ve genel IP'ler sayılmaz (yanal hareket iç ağı hedefler).
func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsPrivate()
}

// AnalyzeFanOut, her cihaz için herhangi bir `window` uzunluğundaki kayan pencerede
// ulaşılan AZAMİ farklı İÇ IP sayısını hesaplar; bu sayı minPeers'ı aşan cihazları
// olası yanal-hareket olarak döner. Yalnız özel (private) hedefler sayılır. Sonuç
// deterministik (cihaz kimliğine göre sıralı).
func AnalyzeFanOut(conns []Conn, minPeers int, window time.Duration) []FanOutFinding {
	if minPeers < 2 {
		minPeers = 2
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	type ev struct {
		ip string
		at time.Time
	}
	byDev := map[string][]ev{}
	for _, c := range conns {
		if !isPrivateIP(c.RemoteIP) {
			continue
		}
		byDev[c.DeviceID] = append(byDev[c.DeviceID], ev{c.RemoteIP, c.At})
	}

	devs := make([]string, 0, len(byDev))
	for d := range byDev {
		devs = append(devs, d)
	}
	sort.Strings(devs)

	var out []FanOutFinding
	for _, dev := range devs {
		evs := byDev[dev]
		sort.Slice(evs, func(i, j int) bool { return evs[i].at.Before(evs[j].at) })
		best, lo := 0, 0
		counts := map[string]int{}
		for hi := 0; hi < len(evs); hi++ {
			counts[evs[hi].ip]++
			for evs[hi].at.Sub(evs[lo].at) > window {
				counts[evs[lo].ip]--
				if counts[evs[lo].ip] == 0 {
					delete(counts, evs[lo].ip)
				}
				lo++
			}
			if len(counts) > best {
				best = len(counts)
			}
		}
		if best >= minPeers {
			out = append(out, FanOutFinding{DeviceID: dev, DistinctPeers: best, Window: window})
		}
	}
	return out
}

package beacon

import (
	"testing"
	"time"
)

func TestAnalyzeFanOutDetectsLateral(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var conns []Conn
	// d1: 5 farklı iç IP'ye 2 dk içinde → yanal hareket (eşik 4, pencere 5dk).
	for i := 0; i < 5; i++ {
		conns = append(conns, Conn{DeviceID: "d1", RemoteIP: "10.0.0." + itoaByte(i+1), At: base.Add(time.Duration(i) * 20 * time.Second)})
	}
	f := AnalyzeFanOut(conns, 4, 5*time.Minute)
	if len(f) != 1 || f[0].DeviceID != "d1" || f[0].DistinctPeers < 5 {
		t.Fatalf("d1 yanal hareket bulunmalı, %+v", f)
	}
}

func TestAnalyzeFanOutIgnoresPublicIPs(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var conns []Conn
	// Genel IP'lere çok bağlantı (ör. CDN) → sayılmaz.
	for i := 0; i < 6; i++ {
		conns = append(conns, Conn{DeviceID: "d1", RemoteIP: "8.8.8." + itoaByte(i+1), At: base.Add(time.Duration(i) * time.Second)})
	}
	if f := AnalyzeFanOut(conns, 4, 5*time.Minute); len(f) != 0 {
		t.Fatalf("genel IP'ler yanal hareket sayılmamalı, %+v", f)
	}
}

func TestAnalyzeFanOutWindowRespected(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var conns []Conn
	// 5 iç IP ama zamana yayılmış (her biri 10dk arayla) → pencere (5dk) içinde eşik dolmaz.
	for i := 0; i < 5; i++ {
		conns = append(conns, Conn{DeviceID: "d1", RemoteIP: "192.168.1." + itoaByte(i+1), At: base.Add(time.Duration(i) * 10 * time.Minute)})
	}
	if f := AnalyzeFanOut(conns, 4, 5*time.Minute); len(f) != 0 {
		t.Fatalf("pencereye yayılmış bağlantılar tetiklememeli, %+v", f)
	}
}

func TestAnalyzeFanOutBelowThreshold(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	conns := []Conn{
		{DeviceID: "d1", RemoteIP: "10.0.0.1", At: base},
		{DeviceID: "d1", RemoteIP: "10.0.0.2", At: base.Add(time.Second)},
	}
	if f := AnalyzeFanOut(conns, 4, 5*time.Minute); len(f) != 0 {
		t.Fatalf("2 peer eşiğin (4) altında, tetiklememeli, %+v", f)
	}
}

// itoaByte, 0-255 küçük sayıyı string'e çevirir (test yardımcı).
func itoaByte(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Package logx, sunucu için opsiyonel yapısal (JSON) loglama sağlar. Stdlib
// log/slog kullanır (bağımlılıksız). XEMS_LOG_FORMAT=json ayarlandığında standart
// kütüphane log çıktısı (mevcut log.Printf çağrıları dahil) JSON satırlarına
// yönlendirilir — log toplama/SIEM ingestion için. Varsayılan (text) davranışı
// değiştirmez.
package logx

import (
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
)

// jsonFormat, verilen biçim dizesinin JSON isteyip istemediğini söyler.
func jsonFormat(format string) bool {
	return strings.EqualFold(strings.TrimSpace(format), "json")
}

// slogWriter, standart kütüphane log satırlarını slog üzerinden yeniden yayınlar
// (böylece mevcut log.Printf çağrıları da yapısal olur).
type slogWriter struct{ l *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	w.l.Info(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// newJSONLogger, w'ye JSON yazan bir slog.Logger döner (test edilebilir çekirdek).
func newJSONLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// Setup, log biçimini yapılandırır. format "json" ise standart log çıktısı JSON'a
// yönlendirilir (bayrak/prefix temizlenir; slog kendi zaman damgasını ekler).
// Aksi halde metin modunda kalır (verilen prefix + standart bayraklar).
func Setup(format, prefix string) {
	if jsonFormat(format) {
		l := newJSONLogger(os.Stderr)
		slog.SetDefault(l)
		log.SetFlags(0)
		log.SetPrefix("")
		log.SetOutput(slogWriter{l})
		return
	}
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix(prefix)
}

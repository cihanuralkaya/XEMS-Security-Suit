// Package otawire, OTA güncelleme manifestosunun imzalanacak KANONİK bayt
// biçimini tanımlar. Sunucu (imzalayan) ve ajan (doğrulayan) TAM OLARAK aynı
// baytları üretmek zorunda olduğundan bu kodlama tek bir paylaşılan yerde
// (internal olmayan) durur ve her iki tarafça kullanılır.
//
// Kodlama uzunluk-önekli ve deterministiktir: her alan 4 baytlık big-endian
// uzunluk + ham bayt olarak yazılır. Böylece alan içeriği ayraçla çakışamaz.
package otawire

import "encoding/binary"

// Manifest, imzalanan güncelleme alanlarıdır. Yalnız BÜTÜNLÜK/kimlik açısından
// kritik alanlar imzalanır (platform bir seçim kriteridir, imzaya dahil değildir).
type Manifest struct {
	TargetVersion string
	SHA256Hex     string
	DownloadURL   string
	Mandatory     bool
}

const domainTag = "xems-ota-manifest-v1"

// CanonicalBytes, manifestonun imzalanacak deterministik bayt dizisini üretir.
func CanonicalBytes(m Manifest) []byte {
	var out []byte
	out = appendField(out, []byte(domainTag))
	out = appendField(out, []byte(m.TargetVersion))
	out = appendField(out, []byte(m.SHA256Hex))
	out = appendField(out, []byte(m.DownloadURL))
	var mb byte
	if m.Mandatory {
		mb = 1
	}
	out = appendField(out, []byte{mb})
	return out
}

func appendField(dst, field []byte) []byte {
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(field)))
	dst = append(dst, lp[:]...)
	return append(dst, field...)
}

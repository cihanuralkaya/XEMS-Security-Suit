// Package scriptwire, imzalı otomasyon scriptlerinin kanonik (imzalanacak) bayt
// biçimini tanımlar. Sunucu (imzalayan) ve ajan (doğrulayan) TAM OLARAK aynı
// baytları üretmek zorunda olduğundan bu kodlama internal-dışı paylaşılır.
//
// Uzunluk-önekli ve deterministik: her alan 4 baytlık big-endian uzunluk + ham
// bayt; args sayısı da öneklenir. Böylece tek bayt değişikliği imzayı bozar.
package scriptwire

import "encoding/binary"

// Script, imzalanan bir otomasyon scriptidir.
type Script struct {
	Interpreter string // "powershell" | "sh" | "bash" | "cmd" | "node"
	Body        string // script gövdesi
	Args        []string
}

const domainTag = "xems-signed-script-v1"

// CanonicalBytes, scriptin imzalanacak deterministik baytlarını üretir.
func CanonicalBytes(s Script) []byte {
	var out []byte
	out = field(out, []byte(domainTag))
	out = field(out, []byte(s.Interpreter))
	out = field(out, []byte(s.Body))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s.Args)))
	out = append(out, n[:]...)
	for _, a := range s.Args {
		out = field(out, []byte(a))
	}
	return out
}

func field(dst, f []byte) []byte {
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(f)))
	dst = append(dst, lp[:]...)
	return append(dst, f...)
}

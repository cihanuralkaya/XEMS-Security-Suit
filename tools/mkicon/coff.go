package main

import (
	"bytes"
	"encoding/binary"
)

// coff.go — ikon görüntülerinden bir COFF `.syso` nesnesi üretir. Go bağlayıcısı
// (internal linker, windows/amd64) main paket dizinindeki `*_windows_amd64.syso`
// dosyasını otomatik alır ve `.rsrc` bölümünü PE'ye gömer; böylece exe kendi
// ikonunu taşır. Dış araç (rsrc/goversioninfo) YOK — yalnız stdlib.
//
// Yapı: tek `.rsrc` bölümü = [kaynak dizin ağacı][veri girdileri][ham veri].
// Her yaprak IMAGE_RESOURCE_DATA_ENTRY.OffsetToData alanı, bölüm sembolüne karşı
// bir ADDR32NB yeniden-konumlama (relocation) ile RVA'ya çevrilir.

const (
	rtIcon      = 3  // RT_ICON
	rtGroupIcon = 14 // RT_GROUP_ICON
	langNeutral = 0x0409

	relAMD64Addr32NB = 0x0003     // IMAGE_REL_AMD64_ADDR32NB
	symClassStatic   = 3          // IMAGE_SYM_CLASS_STATIC
	scnRsrc          = 0x40000040 // CNT_INITIALIZED_DATA | MEM_READ

	dirSz = 16 // IMAGE_RESOURCE_DIRECTORY
	entSz = 8  // IMAGE_RESOURCE_DIRECTORY_ENTRY
	deSz  = 16 // IMAGE_RESOURCE_DATA_ENTRY
)

// groupDir, RT_GROUP_ICON verisini (GRPICONDIR) üretir; her girdi bir RT_ICON
// kaynak kimliğine (1..N) işaret eder.
func groupDir(imgs []iconImage) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(0))         // idReserved
	binary.Write(&b, binary.LittleEndian, uint16(1))         // idType = icon
	binary.Write(&b, binary.LittleEndian, uint16(len(imgs))) // idCount
	for i, im := range imgs {
		dim := im.size
		if dim >= 256 {
			dim = 0
		}
		b.WriteByte(byte(dim))                                     // bWidth
		b.WriteByte(byte(dim))                                     // bHeight
		b.WriteByte(0)                                             // bColorCount
		b.WriteByte(0)                                             // bReserved
		binary.Write(&b, binary.LittleEndian, uint16(1))           // wPlanes
		binary.Write(&b, binary.LittleEndian, uint16(32))          // wBitCount
		binary.Write(&b, binary.LittleEndian, uint32(len(im.png))) // dwBytesInRes
		binary.Write(&b, binary.LittleEndian, uint16(i+1))         // nID (RT_ICON id)
	}
	return b.Bytes()
}

func resDir(b *bytes.Buffer, idEntries int) {
	binary.Write(b, binary.LittleEndian, uint32(0)) // Characteristics
	binary.Write(b, binary.LittleEndian, uint32(0)) // TimeDateStamp
	binary.Write(b, binary.LittleEndian, uint16(0)) // MajorVersion
	binary.Write(b, binary.LittleEndian, uint16(0)) // MinorVersion
	binary.Write(b, binary.LittleEndian, uint16(0)) // NumberOfNamedEntries
	binary.Write(b, binary.LittleEndian, uint16(uint16(idEntries)))
}

func dirEntry(b *bytes.Buffer, nameOrID uint32, offset int, isDir bool) {
	off := uint32(offset)
	if isDir {
		off |= 0x80000000
	}
	binary.Write(b, binary.LittleEndian, nameOrID)
	binary.Write(b, binary.LittleEndian, off)
}

// writeSyso, ikon görüntülerinden (kimlikler 1..N) bir amd64 COFF `.syso` üretir.
func writeSyso(imgs []iconImage) []byte {
	n := len(imgs)
	grp := groupDir(imgs)

	// --- .rsrc bölümü içi ofsetler ---
	posType3 := dirSz + 2*entSz
	posType14 := posType3 + dirSz + n*entSz
	iconIDDir := make([]int, n)
	baseIcon := posType14 + dirSz + entSz
	for i := 0; i < n; i++ {
		iconIDDir[i] = baseIcon + i*(dirSz+entSz)
	}
	posGroupIDDir := baseIcon + n*(dirSz+entSz)
	posDataEntries := posGroupIDDir + dirSz + entSz

	deIcon := make([]int, n)
	for i := 0; i < n; i++ {
		deIcon[i] = posDataEntries + i*deSz
	}
	deGroup := posDataEntries + n*deSz
	posRaw := posDataEntries + (n+1)*deSz

	rawIcon := make([]int, n)
	o := posRaw
	for i := 0; i < n; i++ {
		rawIcon[i] = o
		o += len(imgs[i].png)
	}
	rawGroup := o
	o += len(grp)
	sectionSize := o

	// --- .rsrc bölüm içeriği (ofset sırasıyla) ---
	var s bytes.Buffer
	// 1) kök dizin: type RT_ICON, RT_GROUP_ICON (ID artan sırada)
	resDir(&s, 2)
	dirEntry(&s, rtIcon, posType3, true)
	dirEntry(&s, rtGroupIcon, posType14, true)
	// 2) RT_ICON dizini: N ikon kimliği
	resDir(&s, n)
	for i := 0; i < n; i++ {
		dirEntry(&s, uint32(i+1), iconIDDir[i], true)
	}
	// 3) RT_GROUP_ICON dizini: tek grup (ID 1)
	resDir(&s, 1)
	dirEntry(&s, 1, posGroupIDDir, true)
	// 4) her ikon kimliği için dil dizini → yaprak
	for i := 0; i < n; i++ {
		resDir(&s, 1)
		dirEntry(&s, langNeutral, deIcon[i], false)
	}
	// 5) grup için dil dizini → yaprak
	resDir(&s, 1)
	dirEntry(&s, langNeutral, deGroup, false)
	// 6) veri girdileri (OffsetToData = ham veri ofseti; relocation ile RVA olur)
	for i := 0; i < n; i++ {
		binary.Write(&s, binary.LittleEndian, uint32(rawIcon[i])) // OffsetToData
		binary.Write(&s, binary.LittleEndian, uint32(len(imgs[i].png)))
		binary.Write(&s, binary.LittleEndian, uint32(0)) // CodePage
		binary.Write(&s, binary.LittleEndian, uint32(0)) // Reserved
	}
	binary.Write(&s, binary.LittleEndian, uint32(rawGroup))
	binary.Write(&s, binary.LittleEndian, uint32(len(grp)))
	binary.Write(&s, binary.LittleEndian, uint32(0))
	binary.Write(&s, binary.LittleEndian, uint32(0))
	// 7) ham veri
	for i := 0; i < n; i++ {
		s.Write(imgs[i].png)
	}
	s.Write(grp)
	section := s.Bytes()
	if len(section) != sectionSize {
		panic("mkicon: .rsrc bölüm boyutu tutarsız")
	}

	// --- relocations: her veri girdisinin OffsetToData alanı için biri ---
	nreloc := n + 1
	relocOff := 60 + sectionSize
	symOff := relocOff + nreloc*10

	var out bytes.Buffer
	// IMAGE_FILE_HEADER (20)
	binary.Write(&out, binary.LittleEndian, uint16(0x8664)) // Machine amd64
	binary.Write(&out, binary.LittleEndian, uint16(1))      // NumberOfSections
	binary.Write(&out, binary.LittleEndian, uint32(0))      // TimeDateStamp
	binary.Write(&out, binary.LittleEndian, uint32(symOff)) // PointerToSymbolTable
	binary.Write(&out, binary.LittleEndian, uint32(2))      // NumberOfSymbols (sym+aux)
	binary.Write(&out, binary.LittleEndian, uint16(0))      // SizeOfOptionalHeader
	binary.Write(&out, binary.LittleEndian, uint16(0))      // Characteristics

	// IMAGE_SECTION_HEADER (.rsrc, 40)
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0})
	binary.Write(&out, binary.LittleEndian, uint32(0))           // VirtualSize
	binary.Write(&out, binary.LittleEndian, uint32(0))           // VirtualAddress
	binary.Write(&out, binary.LittleEndian, uint32(sectionSize)) // SizeOfRawData
	binary.Write(&out, binary.LittleEndian, uint32(60))          // PointerToRawData
	binary.Write(&out, binary.LittleEndian, uint32(relocOff))    // PointerToRelocations
	binary.Write(&out, binary.LittleEndian, uint32(0))           // PointerToLinenumbers
	binary.Write(&out, binary.LittleEndian, uint16(nreloc))      // NumberOfRelocations
	binary.Write(&out, binary.LittleEndian, uint16(0))           // NumberOfLinenumbers
	binary.Write(&out, binary.LittleEndian, uint32(scnRsrc))     // Characteristics

	// bölüm ham verisi
	out.Write(section)

	// relocations (her biri 10 bayt, paketli)
	writeReloc := func(va int) {
		binary.Write(&out, binary.LittleEndian, uint32(va)) // VirtualAddress
		binary.Write(&out, binary.LittleEndian, uint32(0))  // SymbolTableIndex (.rsrc sembolü)
		binary.Write(&out, binary.LittleEndian, uint16(relAMD64Addr32NB))
	}
	for i := 0; i < n; i++ {
		writeReloc(deIcon[i])
	}
	writeReloc(deGroup)

	// sembol tablosu: `.rsrc` bölüm sembolü (+ aux bölüm tanımı)
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0}) // Name
	binary.Write(&out, binary.LittleEndian, uint32(0))  // Value
	binary.Write(&out, binary.LittleEndian, int16(1))   // SectionNumber
	binary.Write(&out, binary.LittleEndian, uint16(0))  // Type
	out.WriteByte(symClassStatic)                       // StorageClass
	out.WriteByte(1)                                    // NumberOfAuxSymbols
	// aux (18)
	binary.Write(&out, binary.LittleEndian, uint32(sectionSize)) // Length
	binary.Write(&out, binary.LittleEndian, uint16(nreloc))      // NumberOfRelocations
	binary.Write(&out, binary.LittleEndian, uint16(0))           // NumberOfLinenumbers
	binary.Write(&out, binary.LittleEndian, uint32(0))           // CheckSum
	binary.Write(&out, binary.LittleEndian, uint16(1))           // Number (section)
	out.WriteByte(0)                                             // Selection
	out.Write([]byte{0, 0, 0})                                   // padding

	// string table (yalnız 4-baytlık boyut alanı; uzun ad yok)
	binary.Write(&out, binary.LittleEndian, uint32(4))

	return out.Bytes()
}

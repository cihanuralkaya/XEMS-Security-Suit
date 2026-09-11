package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// testImgs, sentetik (küçük) ikon görüntüleri üretir — gerçek logoya gerek yok.
func testImgs(t *testing.T, sizes []int) []iconImage {
	t.Helper()
	sq := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			sq.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 4), G: uint8(y * 4), B: 200, A: 255})
		}
	}
	imgs, err := encodePNGs(sq, sizes)
	if err != nil {
		t.Fatalf("encodePNGs: %v", err)
	}
	return imgs
}

func TestWriteICO(t *testing.T) {
	sizes := []int{16, 32, 48, 256}
	imgs := testImgs(t, sizes)
	ico := writeICO(imgs)

	if binary.LittleEndian.Uint16(ico[0:]) != 0 || binary.LittleEndian.Uint16(ico[2:]) != 1 {
		t.Fatal("ICONDIR başlığı hatalı (reserved/type)")
	}
	count := int(binary.LittleEndian.Uint16(ico[4:]))
	if count != len(sizes) {
		t.Fatalf("ikon sayısı = %d, beklenen %d", count, len(sizes))
	}
	for i := 0; i < count; i++ {
		e := 6 + i*16
		wantDim := sizes[i]
		if wantDim >= 256 {
			wantDim = 0
		}
		if int(ico[e]) != wantDim {
			t.Errorf("girdi %d genişlik baytı = %d, beklenen %d", i, ico[e], wantDim)
		}
		size := binary.LittleEndian.Uint32(ico[e+8:])
		off := binary.LittleEndian.Uint32(ico[e+12:])
		blob := ico[off : off+size]
		img, err := png.Decode(bytes.NewReader(blob))
		if err != nil {
			t.Fatalf("girdi %d PNG çözülemedi: %v", i, err)
		}
		if img.Bounds().Dx() != sizes[i] {
			t.Errorf("girdi %d boyut = %d, beklenen %d", i, img.Bounds().Dx(), sizes[i])
		}
	}
}

// walkRsrc, syso COFF'unun `.rsrc` bölümünü ayıklar (ham bölüm baytları).
func rsrcSection(t *testing.T, syso []byte) []byte {
	t.Helper()
	// bölüm başlığı 20. ofsette; SizeOfRawData +16, PointerToRawData +20
	sh := 20
	size := binary.LittleEndian.Uint32(syso[sh+16:])
	ptr := binary.LittleEndian.Uint32(syso[sh+20:])
	return syso[ptr : ptr+size]
}

func TestWriteSyso(t *testing.T) {
	sizes := []int{16, 32, 48, 64, 128, 256}
	imgs := testImgs(t, sizes)
	syso := writeSyso(imgs)

	// COFF başlık: makine amd64, tek bölüm
	if binary.LittleEndian.Uint16(syso[0:]) != 0x8664 {
		t.Fatal("COFF makinesi amd64 değil")
	}
	if binary.LittleEndian.Uint16(syso[2:]) != 1 {
		t.Fatal("bölüm sayısı 1 değil")
	}
	data := rsrcSection(t, syso)

	readDir := func(off uint32) uint16 { return binary.LittleEndian.Uint16(data[off+14:]) }
	entry := func(dirOff uint32, i uint16) (id, sub uint32) {
		e := dirOff + 16 + uint32(i)*8
		return binary.LittleEndian.Uint32(data[e:]), binary.LittleEndian.Uint32(data[e+4:])
	}

	if got := readDir(0); got != 2 {
		t.Fatalf("kök tip sayısı = %d, beklenen 2 (RT_ICON, RT_GROUP_ICON)", got)
	}
	var sawIcon, sawGroup bool
	for i := uint16(0); i < 2; i++ {
		id, sub := entry(0, i)
		subOff := sub & 0x7fffffff
		cnt := readDir(subOff)
		switch id {
		case rtIcon:
			sawIcon = true
			if int(cnt) != len(sizes) {
				t.Errorf("RT_ICON sayısı = %d, beklenen %d", cnt, len(sizes))
			}
		case rtGroupIcon:
			sawGroup = true
			if cnt != 1 {
				t.Errorf("RT_GROUP_ICON sayısı = %d, beklenen 1", cnt)
			}
			// grup → dil dizini → veri girdisi → GRPICONDIR
			_, gsub := entry(subOff, 0)
			gOff := gsub & 0x7fffffff
			_, ld := entry(gOff, 0)
			deOff := ld & 0x7fffffff
			rawOff := binary.LittleEndian.Uint32(data[deOff:]) // OffsetToData (RVA=0 tabanlı; addend)
			gc := binary.LittleEndian.Uint16(data[rawOff+4:])
			if int(gc) != len(sizes) {
				t.Errorf("GRPICONDIR girdi sayısı = %d, beklenen %d", gc, len(sizes))
			}
			for k := 0; k < int(gc); k++ {
				nid := binary.LittleEndian.Uint16(data[rawOff+6+uint32(k)*14+12:])
				if int(nid) != k+1 {
					t.Errorf("GRPICONDIR[%d] nID = %d, beklenen %d", k, nid, k+1)
				}
			}
		default:
			t.Errorf("beklenmeyen tip id %d", id)
		}
	}
	if !sawIcon || !sawGroup {
		t.Fatal("RT_ICON veya RT_GROUP_ICON eksik")
	}
}

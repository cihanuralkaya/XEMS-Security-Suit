package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
)

// iconImage, tek bir ikon boyutunun PNG-kodlu baytları + ölçüsüdür.
type iconImage struct {
	size int
	png  []byte
}

// encodePNGs, verilen kare görüntüyü her hedef boyuta ölçekler ve PNG kodlar.
func encodePNGs(square *image.NRGBA, sizes []int) ([]iconImage, error) {
	imgs := make([]iconImage, 0, len(sizes))
	for _, s := range sizes {
		scaled := resizeArea(square, s)
		var buf bytes.Buffer
		if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, scaled); err != nil {
			return nil, err
		}
		imgs = append(imgs, iconImage{size: s, png: append([]byte(nil), buf.Bytes()...)})
	}
	return imgs, nil
}

// writeICO, ikon görüntülerinden bir .ico dosyası (PNG-gömülü) üretir.
// Windows Vista+ .ico içinde PNG girdilerini destekler.
func writeICO(imgs []iconImage) []byte {
	var buf bytes.Buffer
	// ICONDIR
	binary.Write(&buf, binary.LittleEndian, uint16(0))         // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))         // type = icon
	binary.Write(&buf, binary.LittleEndian, uint16(len(imgs))) // count

	// Görüntü verisi, tüm dizin girdilerinden SONRA başlar.
	offset := 6 + 16*len(imgs)
	for _, im := range imgs {
		dim := im.size
		if dim >= 256 {
			dim = 0 // 256 → 0 (tek bayt alan)
		}
		buf.WriteByte(byte(dim))                                     // width
		buf.WriteByte(byte(dim))                                     // height
		buf.WriteByte(0)                                             // color count (0 = >=8bpp)
		buf.WriteByte(0)                                             // reserved
		binary.Write(&buf, binary.LittleEndian, uint16(1))           // planes
		binary.Write(&buf, binary.LittleEndian, uint16(32))          // bit count
		binary.Write(&buf, binary.LittleEndian, uint32(len(im.png))) // bytes in resource
		binary.Write(&buf, binary.LittleEndian, uint32(offset))      // image offset
		offset += len(im.png)
	}
	for _, im := range imgs {
		buf.Write(im.png)
	}
	return buf.Bytes()
}

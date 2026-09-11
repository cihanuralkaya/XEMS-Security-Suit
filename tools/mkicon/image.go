package main

import (
	"image"
	"image/color"
)

// cropSquare, kaynaktan (cx,cy) merkezli, kenarı size olan kare bir bölge keser.
// Bölge kaynak sınırlarını aşarsa kaynağa kırpılır (taşma güvenli).
func cropSquare(src image.Image, cx, cy, size int) *image.NRGBA {
	half := size / 2
	x0, y0 := cx-half, cy-half
	b := src.Bounds()
	out := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		sy := y0 + y
		for x := 0; x < size; x++ {
			sx := x0 + x
			if sx < b.Min.X || sx >= b.Max.X || sy < b.Min.Y || sy >= b.Max.Y {
				continue // sınır dışı → şeffaf
			}
			out.Set(x, y, src.At(sx, sy))
		}
	}
	return out
}

// resizeArea, alan-ortalama (box) örnekleme ile ölçekler. Büyük küçültmelerde
// bilinear'dan daha temiz sonuç verir (her hedef piksel = kaynak ayak izinin ortalaması).
func resizeArea(src *image.NRGBA, dst int) *image.NRGBA {
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	out := image.NewNRGBA(image.Rect(0, 0, dst, dst))
	for dy := 0; dy < dst; dy++ {
		sy0 := dy * sh / dst
		sy1 := (dy + 1) * sh / dst
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for dx := 0; dx < dst; dx++ {
			sx0 := dx * sw / dst
			sx1 := (dx + 1) * sw / dst
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}
			var r, g, b, a uint64
			var n uint64
			for yy := sy0; yy < sy1; yy++ {
				for xx := sx0; xx < sx1; xx++ {
					c := src.NRGBAAt(sb.Min.X+xx, sb.Min.Y+yy)
					r += uint64(c.R)
					g += uint64(c.G)
					b += uint64(c.B)
					a += uint64(c.A)
					n++
				}
			}
			if n == 0 {
				n = 1
			}
			out.SetNRGBA(dx, dy, color.NRGBA{
				R: uint8(r / n), G: uint8(g / n), B: uint8(b / n), A: uint8(a / n),
			})
		}
	}
	return out
}

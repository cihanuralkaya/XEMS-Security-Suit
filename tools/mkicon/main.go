// Command mkicon, XEMS logosundan (kaynak PNG) uygulama ikonlarını üretir:
//   - assets/xems.ico            (çok-boyutlu, PNG-gömülü Windows ikonu)
//   - assets/xems-icon-256.png   (kare önizleme / sosyal görsel)
//   - <main-paket>/icon_windows_amd64.syso  (exe'ye gömülü kaynak)
//
// Yalnız standart kütüphane kullanır (dış araç/bağımlılık yok). Kalkan bölgesi,
// logo bandından kare olarak kırpılır; bayrağlarla ayarlanabilir.
//
// Kullanım:
//
//	go run ./tools/mkicon [-src assets/xems-logo.png] [-cx 825 -cy 390 -side 720]
package main

import (
	"flag"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"os"
	"path/filepath"
)

// sysoTargets, ikonun gömüleceği main paket dizinleridir (release'te derlenen exe'ler).
var sysoTargets = []string{
	"server/cmd/c2",
	"agent/cmd/agent",
	"agent/cmd/watchdog",
	"tools/gencerts",
}

var iconSizes = []int{16, 32, 48, 64, 128, 256}

func main() {
	src := flag.String("src", "assets/xems-logo.png", "kaynak logo (PNG/JPEG)")
	cx := flag.Int("cx", 825, "kalkan merkez X")
	cy := flag.Int("cy", 390, "kalkan merkez Y")
	side := flag.Int("side", 720, "kare kenar uzunluğu (piksel)")
	root := flag.String("root", ".", "depo kök dizini")
	flag.Parse()

	if err := run(*src, *root, *cx, *cy, *side); err != nil {
		fmt.Fprintln(os.Stderr, "mkicon:", err)
		os.Exit(1)
	}
}

func run(src, root string, cx, cy, side int) error {
	f, err := os.Open(filepath.Join(root, src))
	if err != nil {
		return err
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return fmt.Errorf("kaynak çözülemedi: %w", err)
	}

	square := cropSquare(img, cx, cy, side)

	imgs, err := encodePNGs(square, iconSizes)
	if err != nil {
		return err
	}

	// assets/xems.ico
	ico := writeICO(imgs)
	if err := os.WriteFile(filepath.Join(root, "assets", "xems.ico"), ico, 0o644); err != nil {
		return err
	}
	fmt.Printf("yazıldı  assets/xems.ico            (%d boyut, %d bayt)\n", len(imgs), len(ico))

	// assets/xems-icon-256.png (kare önizleme)
	preview := resizeArea(square, 256)
	pf, err := os.Create(filepath.Join(root, "assets", "xems-icon-256.png"))
	if err != nil {
		return err
	}
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(pf, preview); err != nil {
		pf.Close()
		return err
	}
	pf.Close()
	fmt.Println("yazıldı  assets/xems-icon-256.png")

	// her hedef main paketine .syso
	syso := writeSyso(imgs)
	for _, t := range sysoTargets {
		p := filepath.Join(root, filepath.FromSlash(t), "icon_windows_amd64.syso")
		if err := os.WriteFile(p, syso, 0o644); err != nil {
			return err
		}
		fmt.Printf("yazıldı  %s (%d bayt)\n", filepath.ToSlash(p), len(syso))
	}
	return nil
}

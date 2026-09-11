# Marka ve uygulama ikonu / Branding & application icon

## Türkçe

XEMS logosu ve türetilen uygulama ikonları `assets/` altında bulunur:

| Dosya | Açıklama |
|-------|----------|
| `assets/xems-logo.png` | Ana logo bandı (1697×927) — README başlığı, sosyal önizleme. |
| `assets/xems.ico` | Çok-boyutlu Windows ikonu (16/32/48/64/128/256, PNG-gömülü). |
| `assets/xems-icon-256.png` | Kare ikon önizlemesi (kalkan) — 256×256. |

### İkon üretimi

İkonlar, saf-Go bir araçla (`tools/mkicon`, **dış bağımlılık yok**) logodan üretilir:

```bash
make icons        # = go run ./tools/mkicon
```

Araç şunları yapar:
1. Logo bandından kalkan bölgesini kare olarak kırpar (alan-ortalama ölçekleme).
2. `assets/xems.ico` ve `assets/xems-icon-256.png` yazar.
3. Her `main` paketine (`c2`, `agent`, `watchdog`, `gencerts`) bir
   `icon_windows_amd64.syso` COFF kaynağı yazar. Go bağlayıcısı bu dosyayı
   otomatik alıp `.rsrc` bölümünü PE'ye gömer — böylece **exe kendi ikonunu taşır**
   (Windows Gezgini/görev çubuğunda görünür). `_windows_amd64` soneki sayesinde
   Linux derlemeleri bu dosyayı yok sayar.

Logo değişirse `make icons` yeniden çalıştırılır ve üretilen dosyalar commit edilir.
Kırpma bölgesi bayrağlarla ayarlanabilir: `go run ./tools/mkicon -cx 825 -cy 390 -side 720`.

## English

The XEMS logo and derived application icons live under `assets/`:

| File | Purpose |
|------|---------|
| `assets/xems-logo.png` | Master logo banner (1697×927) — README header, social preview. |
| `assets/xems.ico` | Multi-size Windows icon (16/32/48/64/128/256, PNG-embedded). |
| `assets/xems-icon-256.png` | Square icon preview (shield) — 256×256. |

### Icon generation

Icons are generated from the logo by a pure-Go tool (`tools/mkicon`, **no external
dependency**):

```bash
make icons        # = go run ./tools/mkicon
```

The tool: (1) crops the shield region into a square (area-average resampling);
(2) writes `assets/xems.ico` and `assets/xems-icon-256.png`; (3) writes an
`icon_windows_amd64.syso` COFF resource into each `main` package (`c2`, `agent`,
`watchdog`, `gencerts`). The Go linker picks these up automatically and embeds the
`.rsrc` section into the PE, so **each executable carries its own icon** (visible in
Explorer / taskbar). The `_windows_amd64` suffix makes Linux builds ignore the file.

Re-run `make icons` when the logo changes and commit the regenerated files. The crop
region is adjustable via flags: `go run ./tools/mkicon -cx 825 -cy 390 -side 720`.

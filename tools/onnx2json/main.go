// Command onnx2json, ÇEVRİMDIŞI eğitilmiş bir ONNX modelini (sıralı MLP: Gemm +
// Relu/Sigmoid) XEMS anomali motorunun taşınabilir JSON ağırlık formatına çevirir.
// Böylece "kenar cihazda eğitilmiş model çalıştırma" hedefi, onnxruntime'ın C
// bağımlılığı OLMADAN karşılanır (CGO_ENABLED=0 cross-compile ve saf-Go CI korunur;
// bkz. docs/ONNX.md). Üretilen JSON, agent/internal/anomaly.LoadModelJSON ile
// yüklenir; imzalamak için mevcut Ed25519 akışı kullanılır (LoadModelSigned).
//
//	go run ./tools/onnx2json -in model.onnx -out model.json \
//	    -mean 0,12,0,3 -std 1,6,4,2
//
// Bu araç YALNIZ tools/ altındadır; çalışan ikiliye, go.mod'a, CI'a ya da CGO
// duruşuna hiçbir etkisi yoktur (araştırma: Seçenek D, DÜŞÜK risk).
//
// Desteklenen: Gemm (transB dahil) ve MatMul+Add kalıbı, Relu/Sigmoid aktivasyonları,
// FLOAT ağırlık/bias initializer'ları. Desteklenmeyen op → GÜRÜLTÜLÜ hata (sessiz
// yanlış model üretmez).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	in := flag.String("in", "", "girdi .onnx dosyası (zorunlu)")
	out := flag.String("out", "", "çıktı .json dosyası (boş → stdout)")
	meanCSV := flag.String("mean", "", "öznitelik ortalamaları (virgülle; boş → hepsi 0)")
	stdCSV := flag.String("std", "", "öznitelik std sapmaları (virgülle; boş → hepsi 1)")
	typ := flag.String("type", "mlp", "model türü etiketi (mlp|logistic)")
	signKey := flag.String("sign-key", "", "Ed25519 özel anahtar dosyası (base64) — verilirse <out>.sig imzası yazılır")
	flag.Parse()

	if *in == "" {
		fmt.Fprintln(os.Stderr, "onnx2json: -in zorunlu")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "onnx2json: girdi okunamadı: %v\n", err)
		os.Exit(1)
	}
	m, err := Convert(raw, *typ, parseFloatsCSV(*meanCSV), parseFloatsCSV(*stdCSV))
	if err != nil {
		fmt.Fprintf(os.Stderr, "onnx2json: dönüştürme hatası: %v\n", err)
		os.Exit(1)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "onnx2json: JSON: %v\n", err)
		os.Exit(1)
	}
	b = append(b, '\n')
	if *out == "" {
		if *signKey != "" {
			fmt.Fprintln(os.Stderr, "onnx2json: -sign-key -out gerektirir (stdout imzalanamaz)")
			os.Exit(2)
		}
		os.Stdout.Write(b)
	} else {
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "onnx2json: yazılamadı: %v\n", err)
			os.Exit(1)
		}
		if *signKey != "" {
			if err := signModel(*out, b, *signKey); err != nil {
				fmt.Fprintf(os.Stderr, "onnx2json: imzalama hatası: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "onnx2json: imza yazıldı: %s.sig (ajanda XEMS_ANOMALY_PUBKEY ile doğrulanır)\n", *out)
		}
	}
	fmt.Fprintf(os.Stderr, "onnx2json: %d katman dönüştürüldü (giriş boyutu %d)\n", len(m.Layers), len(m.FeatureMean))
}

// signModel, model baytlarını Ed25519 ile imzalar ve <out>.sig'e base64 yazar
// (anomaly.LoadModelSigned ile aynı format: imza ham JSON baytları üzerine).
func signModel(out string, data []byte, keyPath string) error {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("özel anahtar okunamadı: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("özel anahtar base64 çözülemedi: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("özel anahtar boyutu %d, beklenen %d", len(priv), ed25519.PrivateKeySize)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), data)
	return os.WriteFile(out+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0o644)
}

// modelJSON, agent/internal/anomaly modelJSON şemasının aynısıdır (o paket
// internal olmadığından burada yeniden tanımlanır; alan adları JSON'da eşleşir).
type modelJSON struct {
	Type        string      `json:"type"`
	FeatureMean []float64   `json:"feature_mean"`
	FeatureStd  []float64   `json:"feature_std"`
	Layers      []layerJSON `json:"layers"`
}

type layerJSON struct {
	Weights    [][]float64 `json:"weights"`
	Bias       []float64   `json:"bias"`
	Activation string      `json:"activation"`
}

// Convert, bir ONNX ModelProto baytını modelJSON'a çevirir. mean/std verilmezse
// giriş boyutuna göre 0/1 ile doldurulur.
func Convert(onnx []byte, typ string, mean, std []float64) (modelJSON, error) {
	graph, err := modelGraph(onnx)
	if err != nil {
		return modelJSON{}, err
	}
	nodes, inits, err := parseGraph(graph)
	if err != nil {
		return modelJSON{}, err
	}

	var layers []layerJSON
	inDim := 0
	for _, n := range nodes {
		switch n.op {
		case "Gemm", "MatMul":
			w, b, wOK := gemmWeights(n, inits)
			if !wOK {
				return modelJSON{}, fmt.Errorf("%s düğümü için ağırlık initializer'ı bulunamadı (inputs=%v)", n.op, n.inputs)
			}
			layers = append(layers, layerJSON{Weights: w, Bias: b, Activation: "linear"})
			if inDim == 0 {
				inDim = len(w[0])
			}
		case "Relu", "Sigmoid":
			if len(layers) == 0 {
				return modelJSON{}, fmt.Errorf("%s aktivasyonu bir Gemm katmanından önce geldi", n.op)
			}
			layers[len(layers)-1].Activation = strings.ToLower(n.op)
		case "Identity", "Flatten", "Cast", "Reshape":
			// yapısal/no-op — atla (girdi şeklini değiştirmez varsayımıyla).
		default:
			return modelJSON{}, fmt.Errorf("desteklenmeyen ONNX op: %q (yalnız Gemm/MatMul + Relu/Sigmoid desteklenir)", n.op)
		}
	}
	if len(layers) == 0 {
		return modelJSON{}, fmt.Errorf("çevrilebilir katman (Gemm/MatMul) bulunamadı")
	}
	if last := layers[len(layers)-1]; len(last.Weights) != 1 {
		return modelJSON{}, fmt.Errorf("son katman tek çıkış (anomali skoru) üretmeli, %d nöron", len(last.Weights))
	}

	if len(mean) == 0 {
		mean = make([]float64, inDim)
	}
	if len(std) == 0 {
		std = make([]float64, inDim)
		for i := range std {
			std[i] = 1
		}
	}
	if len(mean) != inDim || len(std) != inDim {
		return modelJSON{}, fmt.Errorf("mean/std boyutu (%d/%d) giriş boyutuyla (%d) uyuşmuyor", len(mean), len(std), inDim)
	}
	if typ == "" {
		typ = "mlp"
	}
	return modelJSON{Type: typ, FeatureMean: mean, FeatureStd: std, Layers: layers}, nil
}

// gemmWeights, bir Gemm/MatMul düğümünün initializer girdilerinden ağırlık matrisini
// [çıkış][giriş] ve bias'ı döner. transB=1 ise ağırlık zaten [out][in]; değilse
// [in][out] olup transpoze edilir. bias yoksa (MatMul) sıfır bias kullanılır.
func gemmWeights(n node, inits map[string]tensor) (w [][]float64, bias []float64, ok bool) {
	var wt *tensor
	var bt *tensor
	for _, name := range n.inputs {
		t, isInit := inits[name]
		if !isInit {
			continue // veri akışı girdisi (önceki katmanın çıktısı)
		}
		tc := t
		if len(t.dims) == 2 {
			wt = &tc
		} else if len(t.dims) == 1 {
			bt = &tc
		}
	}
	if wt == nil {
		return nil, nil, false
	}
	d0, d1 := int(wt.dims[0]), int(wt.dims[1])
	var outN, inN int
	at := func(r, c, cols int) float64 { return wt.data[r*cols+c] }
	if n.transB {
		outN, inN = d0, d1 // B [out,in]; weights[o][i]=data[o*in+i]
		w = make([][]float64, outN)
		for o := 0; o < outN; o++ {
			w[o] = make([]float64, inN)
			for i := 0; i < inN; i++ {
				w[o][i] = at(o, i, inN)
			}
		}
	} else {
		inN, outN = d0, d1 // B [in,out]; weights[o][i]=data[i*out+o] (transpoze)
		w = make([][]float64, outN)
		for o := 0; o < outN; o++ {
			w[o] = make([]float64, inN)
			for i := 0; i < inN; i++ {
				w[o][i] = at(i, o, outN)
			}
		}
	}
	bias = make([]float64, outN)
	if bt != nil && len(bt.data) == outN {
		copy(bias, bt.data)
	}
	return w, bias, true
}

func parseFloatsCSV(s string) []float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]float64, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}

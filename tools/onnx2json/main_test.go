package main

import (
	"encoding/binary"
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// --- Minimal ONNX kodlayıcı (test fixture'ı için; okuyucuyla simetrik) ---

func f32bytes(vals ...float32) []byte {
	b := make([]byte, 0, 4*len(vals))
	for _, v := range vals {
		var u [4]byte
		binary.LittleEndian.PutUint32(u[:], math.Float32bits(v))
		b = append(b, u[:]...)
	}
	return b
}

func tagBytes(num int, val []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, protowire.Number(num), protowire.BytesType), val)
}
func tagVarint(num int, v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, protowire.Number(num), protowire.VarintType), v)
}

func encTensor(name string, dims []int64, data []float32) []byte {
	var b []byte
	for _, d := range dims {
		b = append(b, tagVarint(1, uint64(d))...) // dims (non-packed)
	}
	b = append(b, tagVarint(2, onnxFLOAT)...)        // data_type=FLOAT
	b = append(b, tagBytes(4, f32bytes(data...))...) // float_data (packed)
	b = append(b, tagBytes(8, []byte(name))...)      // name
	return b
}

func encNode(op string, inputs, outputs []string, transB bool) []byte {
	var b []byte
	for _, in := range inputs {
		b = append(b, tagBytes(1, []byte(in))...)
	}
	for _, o := range outputs {
		b = append(b, tagBytes(2, []byte(o))...)
	}
	b = append(b, tagBytes(4, []byte(op))...)
	if transB {
		attr := append(tagBytes(1, []byte("transB")), tagVarint(3, 1)...)
		b = append(b, tagBytes(5, attr)...)
	}
	return b
}

func encModel(nodes [][]byte, inits [][]byte) []byte {
	var graph []byte
	for _, n := range nodes {
		graph = append(graph, tagBytes(1, n)...) // GraphProto.node
	}
	for _, t := range inits {
		graph = append(graph, tagBytes(5, t)...) // GraphProto.initializer
	}
	return tagBytes(7, graph) // ModelProto.graph
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

// --- Testler ---

func TestConvertSequentialMLP(t *testing.T) {
	// 3→2 (Gemm transB=1, Relu) → 1 (Gemm transB=1, Sigmoid).
	w1 := []float32{0.1, 0.2, 0.3, 0.4, 0.5, 0.6} // [2x3]
	b1 := []float32{0.01, 0.02}
	w2 := []float32{0.7, 0.8} // [1x2]
	b2 := []float32{0.03}
	model := encModel(
		[][]byte{
			encNode("Gemm", []string{"X", "W1", "B1"}, []string{"H0"}, true),
			encNode("Relu", []string{"H0"}, []string{"H1"}, false),
			encNode("Gemm", []string{"H1", "W2", "B2"}, []string{"Y0"}, true),
			encNode("Sigmoid", []string{"Y0"}, []string{"Y"}, false),
		},
		[][]byte{
			encTensor("W1", []int64{2, 3}, w1),
			encTensor("B1", []int64{2}, b1),
			encTensor("W2", []int64{1, 2}, w2),
			encTensor("B2", []int64{1}, b2),
		},
	)

	m, err := Convert(model, "mlp", nil, nil)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if len(m.Layers) != 2 {
		t.Fatalf("2 katman beklenirdi, %d", len(m.Layers))
	}
	// Katman 0: [2x3] relu, transB=1 → ağırlıklar doğrudan.
	l0 := m.Layers[0]
	if l0.Activation != "relu" || len(l0.Weights) != 2 || len(l0.Weights[0]) != 3 {
		t.Fatalf("katman0 yapısı yanlış: %+v", l0)
	}
	if !approx(l0.Weights[0][0], 0.1) || !approx(l0.Weights[1][2], 0.6) || !approx(l0.Bias[1], 0.02) {
		t.Fatalf("katman0 değerleri yanlış: w=%v b=%v", l0.Weights, l0.Bias)
	}
	// Katman 1: [1x2] sigmoid.
	l1 := m.Layers[1]
	if l1.Activation != "sigmoid" || len(l1.Weights) != 1 || len(l1.Weights[0]) != 2 {
		t.Fatalf("katman1 yapısı yanlış: %+v", l1)
	}
	if !approx(l1.Weights[0][0], 0.7) || !approx(l1.Weights[0][1], 0.8) || !approx(l1.Bias[0], 0.03) {
		t.Fatalf("katman1 değerleri yanlış: w=%v b=%v", l1.Weights, l1.Bias)
	}
	// Giriş boyutu 3 → mean/std varsayılan (0/1) 3 uzunlukta.
	if len(m.FeatureMean) != 3 || len(m.FeatureStd) != 3 || m.FeatureStd[0] != 1 || m.FeatureMean[0] != 0 {
		t.Fatalf("varsayılan mean/std yanlış: mean=%v std=%v", m.FeatureMean, m.FeatureStd)
	}
	if m.Type != "mlp" {
		t.Fatalf("type mlp olmalı, %q", m.Type)
	}
}

func TestConvertTransposeWhenNoTransB(t *testing.T) {
	// transB=0: W [in=2, out=1], data layout [i*out+o]. weights[0]=[a,b] (transpoze).
	w := []float32{1.5, 2.5} // [2x1]
	model := encModel(
		[][]byte{encNode("Gemm", []string{"X", "W", "B"}, []string{"Y"}, false)},
		[][]byte{encTensor("W", []int64{2, 1}, w), encTensor("B", []int64{1}, []float32{0.5})},
	)
	m, err := Convert(model, "logistic", []float64{0, 0}, []float64{1, 1})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if len(m.Layers) != 1 || len(m.Layers[0].Weights[0]) != 2 {
		t.Fatalf("tek katman [1x2] beklenirdi: %+v", m.Layers)
	}
	if !approx(m.Layers[0].Weights[0][0], 1.5) || !approx(m.Layers[0].Weights[0][1], 2.5) {
		t.Fatalf("transpoze ağırlıklar yanlış: %v", m.Layers[0].Weights)
	}
}

func TestConvertRejectsUnsupportedOp(t *testing.T) {
	model := encModel(
		[][]byte{encNode("Conv", []string{"X", "W"}, []string{"Y"}, false)},
		[][]byte{encTensor("W", []int64{2, 2}, []float32{1, 2, 3, 4})},
	)
	if _, err := Convert(model, "mlp", nil, nil); err == nil {
		t.Fatal("desteklenmeyen op (Conv) için hata beklenirdi")
	}
}

func TestConvertRejectsMultiOutputFinal(t *testing.T) {
	// Son katman 2 çıkış → reddedilmeli (anomali skoru tek çıkış olmalı).
	model := encModel(
		[][]byte{encNode("Gemm", []string{"X", "W", "B"}, []string{"Y"}, true)},
		[][]byte{encTensor("W", []int64{2, 3}, []float32{1, 2, 3, 4, 5, 6}), encTensor("B", []int64{2}, []float32{0, 0})},
	)
	if _, err := Convert(model, "mlp", nil, nil); err == nil {
		t.Fatal("çok çıkışlı son katman için hata beklenirdi")
	}
}

func TestConvertRawData(t *testing.T) {
	// float_data yerine raw_data kullanan tensör de çözülmeli.
	var b []byte
	b = append(b, tagVarint(1, 1)...)                 // dims [1]
	b = append(b, tagVarint(1, 2)...)                 // dims [1,2]
	b = append(b, tagVarint(2, onnxFLOAT)...)         // data_type
	b = append(b, tagBytes(9, f32bytes(0.9, 0.1))...) // raw_data
	b = append(b, tagBytes(8, []byte("W"))...)
	model := encModel(
		[][]byte{encNode("Gemm", []string{"X", "W", "B"}, []string{"Y"}, true)},
		[][]byte{b, encTensor("B", []int64{1}, []float32{0.2})},
	)
	m, err := Convert(model, "mlp", []float64{0, 0}, []float64{1, 1})
	if err != nil {
		t.Fatalf("Convert raw_data: %v", err)
	}
	if !approx(m.Layers[0].Weights[0][0], 0.9) || !approx(m.Layers[0].Weights[0][1], 0.1) {
		t.Fatalf("raw_data ağırlıkları yanlış: %v", m.Layers[0].Weights)
	}
}

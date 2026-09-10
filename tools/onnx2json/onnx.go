package main

// Minimal ONNX (protobuf) okuyucu — YALNIZ sıralı MLP dönüştürmesi için gereken
// alt küme: ModelProto→GraphProto→(NodeProto, initializer TensorProto). Ağır bir
// onnx protobuf bağımlılığı EKLEMEZ; yalnız zaten var olan protowire düşük-seviye
// tel-format okuyucusunu kullanır (yeni bağımlılık yok, saf-Go korunur).
//
// İlgili ONNX alan numaraları:
//   ModelProto.graph          = 7  (message)
//   GraphProto.node           = 1  (repeated NodeProto)
//   GraphProto.initializer    = 5  (repeated TensorProto)
//   NodeProto.input           = 1  (repeated string)
//   NodeProto.output          = 2  (repeated string)
//   NodeProto.op_type         = 4  (string)
//   NodeProto.attribute       = 5  (repeated AttributeProto)
//   AttributeProto.name       = 1  (string)
//   AttributeProto.i          = 3  (int64)   -- (ONNX: field 3)
//   TensorProto.dims          = 1  (repeated int64)
//   TensorProto.data_type     = 2  (int32)
//   TensorProto.float_data    = 4  (repeated float, packed)
//   TensorProto.name          = 8  (string)
//   TensorProto.raw_data      = 9  (bytes)

import (
	"encoding/binary"
	"errors"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

var errBadWire = errors.New("onnx: bozuk protobuf tel biçimi")

const onnxFLOAT = 1 // TensorProto.DataType.FLOAT

type tensor struct {
	name string
	dims []int64
	data []float64
}

type node struct {
	op      string
	inputs  []string
	outputs []string
	transB  bool
}

// eachField, bir protobuf mesajının alanlarını gezer; her alan için numarayı, tipi,
// (uzunluk-sınırlı alanlar için) baytları ve (varint/fixed için) sayısal değeri verir.
func eachField(b []byte, fn func(num protowire.Number, typ protowire.Type, v []byte, ival uint64) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return errBadWire
		}
		b = b[n:]
		switch typ {
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return errBadWire
			}
			b = b[m:]
			if err := fn(num, typ, v, 0); err != nil {
				return err
			}
		case protowire.VarintType:
			iv, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return errBadWire
			}
			b = b[m:]
			if err := fn(num, typ, nil, iv); err != nil {
				return err
			}
		case protowire.Fixed32Type:
			iv, m := protowire.ConsumeFixed32(b)
			if m < 0 {
				return errBadWire
			}
			b = b[m:]
			if err := fn(num, typ, nil, uint64(iv)); err != nil {
				return err
			}
		case protowire.Fixed64Type:
			iv, m := protowire.ConsumeFixed64(b)
			if m < 0 {
				return errBadWire
			}
			b = b[m:]
			if err := fn(num, typ, nil, iv); err != nil {
				return err
			}
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return errBadWire
			}
			b = b[m:]
		}
	}
	return nil
}

// modelGraph, ModelProto baytından GraphProto baytını (alan 7) çıkarır.
func modelGraph(b []byte) ([]byte, error) {
	var graph []byte
	err := eachField(b, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) error {
		if num == 7 && typ == protowire.BytesType {
			graph = v
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if graph == nil {
		return nil, errors.New("onnx: ModelProto.graph (alan 7) bulunamadı")
	}
	return graph, nil
}

// parseGraph, GraphProto'dan düğümleri (sırayla) ve initializer tensörlerini (ada göre)
// çıkarır.
func parseGraph(b []byte) ([]node, map[string]tensor, error) {
	var nodes []node
	inits := map[string]tensor{}
	err := eachField(b, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) error {
		if typ != protowire.BytesType {
			return nil
		}
		switch num {
		case 1: // node
			n, err := parseNode(v)
			if err != nil {
				return err
			}
			nodes = append(nodes, n)
		case 5: // initializer
			t, err := parseTensor(v)
			if err != nil {
				return err
			}
			inits[t.name] = t
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return nodes, inits, nil
}

func parseNode(b []byte) (node, error) {
	var n node
	err := eachField(b, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) error {
		switch {
		case num == 1 && typ == protowire.BytesType: // input (string)
			n.inputs = append(n.inputs, string(v))
		case num == 2 && typ == protowire.BytesType: // output (string)
			n.outputs = append(n.outputs, string(v))
		case num == 4 && typ == protowire.BytesType: // op_type (string)
			n.op = string(v)
		case num == 5 && typ == protowire.BytesType: // attribute
			name, i, ok := parseAttr(v)
			if ok && name == "transB" && i != 0 {
				n.transB = true
			}
		}
		return nil
	})
	return n, err
}

// parseAttr, AttributeProto'dan (name, i) döner. name=alan 1 (string), i=alan 3 (int64).
func parseAttr(b []byte) (name string, i int64, ok bool) {
	_ = eachField(b, func(num protowire.Number, typ protowire.Type, v []byte, ival uint64) error {
		switch {
		case num == 1 && typ == protowire.BytesType:
			name = string(v)
		case num == 3 && typ == protowire.VarintType:
			i = int64(ival)
			ok = true
		}
		return nil
	})
	return name, i, ok
}

func parseTensor(b []byte) (tensor, error) {
	var t tensor
	dataType := int64(onnxFLOAT)
	var rawData []byte
	err := eachField(b, func(num protowire.Number, typ protowire.Type, v []byte, ival uint64) error {
		switch {
		case num == 1 && typ == protowire.VarintType: // dims (non-packed)
			t.dims = append(t.dims, int64(ival))
		case num == 1 && typ == protowire.BytesType: // dims (packed varints)
			rest := v
			for len(rest) > 0 {
				d, m := protowire.ConsumeVarint(rest)
				if m < 0 {
					return errBadWire
				}
				rest = rest[m:]
				t.dims = append(t.dims, int64(d))
			}
		case num == 2 && typ == protowire.VarintType: // data_type
			dataType = int64(ival)
		case num == 4 && typ == protowire.BytesType: // float_data (packed float32)
			rest := v
			for len(rest) >= 4 {
				t.data = append(t.data, float64(math.Float32frombits(binary.LittleEndian.Uint32(rest[:4]))))
				rest = rest[4:]
			}
		case num == 4 && typ == protowire.Fixed32Type: // float_data (non-packed)
			t.data = append(t.data, float64(math.Float32frombits(uint32(ival))))
		case num == 8 && typ == protowire.BytesType: // name
			t.name = string(v)
		case num == 9 && typ == protowire.BytesType: // raw_data
			rawData = v
		}
		return nil
	})
	if err != nil {
		return tensor{}, err
	}
	// raw_data verilmişse (float_data yerine) little-endian float32 olarak çöz.
	if len(t.data) == 0 && len(rawData) > 0 && dataType == onnxFLOAT {
		for i := 0; i+4 <= len(rawData); i += 4 {
			t.data = append(t.data, float64(math.Float32frombits(binary.LittleEndian.Uint32(rawData[i:i+4]))))
		}
	}
	return t, nil
}

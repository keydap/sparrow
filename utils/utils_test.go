package utils

import (
	"math"
	"testing"
)

func TestSerializeInt(t *testing.T) {
	encodeDecodeInt(1, t)
	encodeDecodeInt(-1, t)
	encodeDecodeInt(0, t)
	encodeDecodeInt(math.MaxInt64, t)
	encodeDecodeInt(math.MinInt64, t)
}

func TestSerializeFloat(t *testing.T) {
	encodeDecodeFloat(1.0, t)
	encodeDecodeFloat(-1.0, t)
	encodeDecodeFloat(0.0, t)
	encodeDecodeFloat(math.MaxFloat64, t)
	encodeDecodeFloat(-math.MaxFloat64, t)
	encodeDecodeFloat(math.SmallestNonzeroFloat64, t)
}

func TestDateTime(t *testing.T) {
	date := DateTime()
	if date[len(date)-1] != 'Z' {
		t.Errorf("Invalid datetime, missing Z char")
	}
}

func encodeDecodeInt(in int64, t *testing.T) {
	data := Itob(in)
	out := Btoi(data)
	if in != out {
		t.Error("failed to decode integer")
	}
}

func encodeDecodeFloat(in float64, t *testing.T) {
	data := Ftob(in)
	out := Btof(data)
	if in != out {
		t.Error("failed to decode float")
	}
}

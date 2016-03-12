package utils

import (
	"crypto/rand"
	"fmt"
	"math"
)

func GenUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func Itob(i int64) []byte {
	var v uint64
	if i < 0 {
		v = uint64(^i<<1) | 1
	} else {
		v = uint64(i << 1)
	}

	return encodeUint(v)
}

func Btoi(data []byte) int64 {
	i := decodeUint(data)
	if i&1 != 0 {
		return ^int64(i >> 1)
	} else {
		return int64(i >> 1)
	}
}

func Ftob(f float64) []byte {
	return encodeUint(math.Float64bits(f))
}

func Btof(data []byte) float64 {
	fVal := decodeUint(data)
	return math.Float64frombits(fVal)
}

func decodeUint(data []byte) uint64 {
	if len(data) > 8 {
		panic("Invalid integer bytes, data length exceeds 8")
	}

	var x uint64
	for _, b := range data {
		x = x<<8 | uint64(b)
	}

	return x
}
func encodeUint(v uint64) []byte {
	data := make([]byte, 8)
	pos := 7
	for v > 0 {
		data[pos] = uint8(v)
		pos--
		v >>= 8
	}

	return data
}

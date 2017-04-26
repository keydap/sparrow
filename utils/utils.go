// Copyright 2017 Keydap. All rights reserved.
// Use of this source code is governed by a Apache
// license that can be found in the LICENSE file.

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	logger "github.com/juju/loggo"
	"math"
	"os"
	"time"
)

const DIR_PERM os.FileMode = 0744 //rwxr--r--

const FILE_PERM os.FileMode = 0644 //rw-r--r--

var log logger.Logger

var urlEncoder = base64.URLEncoding.WithPadding(base64.NoPadding)

func init() {
	log = logger.GetLogger("sparrow.utils")
}

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

	return encodeUint64(v)
}

func Btoi(data []byte) int64 {
	i := decodeUint64(data)
	if i&1 != 0 {
		return ^int64(i >> 1)
	} else {
		return int64(i >> 1)
	}
}

func Ftob(f float64) []byte {
	return encodeUint64(math.Float64bits(f))
}

func Btof(data []byte) float64 {
	fVal := decodeUint64(data)
	return math.Float64frombits(fVal)
}

func decodeUint64(data []byte) uint64 {
	if len(data) > 8 {
		panic("Invalid integer bytes, data length exceeds 8")
	}

	var x uint64
	for _, b := range data {
		x = x<<8 | uint64(b)
	}

	return x
}

func encodeUint64(v uint64) []byte {
	data := make([]byte, 8)
	pos := 7
	for v > 0 {
		data[pos] = uint8(v)
		pos--
		v >>= 8
	}

	return data
}

func EncodeUint32(v uint32) []byte {
	data := make([]byte, 4)
	pos := 3
	for v > 0 {
		data[pos] = uint8(v)
		pos--
		v >>= 8
	}

	return data
}

func DecodeUint32(data []byte) uint32 {
	if len(data) > 4 {
		panic("Invalid integer bytes, data length exceeds 4")
	}

	var x uint32
	for _, b := range data {
		x = x<<8 | uint32(b)
	}

	return x
}

func DateTime() string {
	t := time.Now().UTC()
	return t.Format(time.RFC3339)
}

func DateTimeMillis() int64 {
	t := time.Now().UnixNano() / 1000000
	return t
}

func GetTimeMillis(rfc3339Date string) int64 {
	t, err := time.Parse(time.RFC3339, rfc3339Date)
	if err != nil {
		panic(err)
	}

	millis := t.UnixNano() / 1000000
	return millis
}

func CheckAndCreate(dirName string) {
	finfo, err := os.Stat(dirName)

	if os.IsNotExist(err) {
		err := os.MkdirAll(dirName, DIR_PERM)
		if err != nil {
			log.Criticalf("Failed to create the directory %s [%s]", dirName, err)
			panic(err)
		}
	} else if !finfo.IsDir() {
		s := fmt.Errorf("The file %s already exists and is not a directory, please delete it and retry\n", dirName)
		log.Criticalf(s.Error())
		panic(s)
	}
}

func RandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func Rand32() []byte {
	return RandBytes(32)
}

func NewRandShaStr() string {
	hash := sha256.Sum256(RandBytes(16))
	return B64Encode(hash[:])
}

func B64Encode(data []byte) string {
	return urlEncoder.EncodeToString(data)
}

func B64Decode(val string) []byte {
	data, _ := urlEncoder.DecodeString(val)
	return data
}

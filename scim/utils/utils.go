package utils

import (
	"crypto/rand"
	"fmt"
	logger "github.com/juju/loggo"
	"math"
	"os"
	"strconv"
	"time"
)

var DIR_PERM os.FileMode = 0744 //rwxr--r--

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.scim.utils")
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

func DateTime() string {
	t := time.Now().UTC()
	return t.Format(time.RFC3339)
}

func DateTimeMillis() string {
	t := time.Now().UnixNano() / 1000000
	return strconv.FormatInt(t, 10)
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

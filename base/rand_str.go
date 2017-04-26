package base

import (
	"math/rand"
	"time"
)

// from this http://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang#31832326
// but added 11 additional characters

var strSeed = rand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789"
const (
	letterIdxBits  = 6                    // 6 bits to represent a letter index
	letterIdxMask  = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax   = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	numCharsPerStr = 7
)

func RandStr() string {
	n := numCharsPerStr
	b := make([]byte, n)
	// A strSeed.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, strSeed.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = strSeed.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

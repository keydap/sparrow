// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package utils

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"
)

const salt_size = 8 //64 bits, common size for all salts

type HashType uint

const (
	MD5 HashType = 1 + iota
	SHA1
	SHA256
	SHA512
)

var hashTypeMap = map[HashType]string{
	MD5:    "md5",
	SHA1:   "sha1",
	SHA256: "sha256",
	SHA512: "sha512",
}

var nameHashTypeMap map[string]HashType

func init() {
	nameHashTypeMap = make(map[string]HashType)
	for k, v := range hashTypeMap {
		nameHashTypeMap[v] = k
	}
}

func FindHashType(algoName string) HashType {
	algoName = strings.ToLower(algoName)
	return nameHashTypeMap[algoName]
}

func HashPassword(plaintext string, algo HashType) string {
	salt := RandBytes(salt_size)
	sum := _hashPassword(plaintext, salt, algo)
	return "{" + hashTypeMap[algo] + "}" + B64Encode(sum)
}

func _hashPassword(plaintext string, salt []byte, algo HashType) []byte {
	var instance hash.Hash

	switch algo {
	case MD5:
		instance = md5.New()
	case SHA1:
		instance = sha1.New()
	case SHA256:
		instance = sha256.New()
	case SHA512:
		instance = sha512.New()

	default:
		panic(fmt.Errorf("Unsupported hashing algorithm %s", algo))
	}

	instance.Write([]byte(plaintext))
	if salt != nil {
		instance.Write(salt)
	}
	// sum will be in the order <salt,hash>
	sum := instance.Sum(salt)

	return sum
}

func ComparePassword(plaintext string, hashVal string) bool {
	if !IsPasswordHashed(hashVal) {
		return (plaintext == hashVal)
	}

	end := strings.IndexRune(hashVal, '}')
	hashAlgo := hashVal[1:end]
	hashBytes := B64Decode(hashVal[end+1:])

	var salt []byte
	if len(hashBytes) > salt_size {
		salt = make([]byte, salt_size)
		copy(salt, hashBytes[:salt_size])
	}

	newHash := _hashPassword(plaintext, salt, nameHashTypeMap[hashAlgo])

	return bytes.Equal(newHash, hashBytes)
}

func IsPasswordHashed(password string) bool {
	pLen := len(password)
	if pLen == 0 {
		return false
	}

	if !strings.HasPrefix(password, "{") {
		return false
	}

	endPos := 0
	for i, c := range password[:] { // start from beginning anyway to keep endPos accurate
		endPos = i
		if c == '}' {
			break
		}
	}

	if endPos == (pLen - 1) {
		return false
	}

	algoName := password[1:endPos]
	if FindHashType(algoName) == 0 {
		return false
	}

	return true
}

// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package utils

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strings"
)

const salt_size = 8 //64 bits, common size for all salts

type hashMech struct {
	Name     string
	AlgoName string
	Salted   bool
}

var nameHashMechMap map[string]*hashMech

func init() {
	arr := make([]*hashMech, 7)
	arr[0] = &hashMech{Name: "md5", AlgoName: "md5", Salted: false}
	arr[1] = &hashMech{Name: "sha", AlgoName: "sha", Salted: false}
	arr[2] = &hashMech{Name: "ssha", AlgoName: "sha", Salted: true}
	arr[3] = &hashMech{Name: "sha256", AlgoName: "sha256", Salted: false}
	arr[4] = &hashMech{Name: "ssha256", AlgoName: "sha256", Salted: true}
	arr[5] = &hashMech{Name: "sha512", AlgoName: "sha512", Salted: false}
	arr[6] = &hashMech{Name: "ssha512", AlgoName: "sha512", Salted: true}

	nameHashMechMap = make(map[string]*hashMech)
	for _, v := range arr {
		nameHashMechMap[v.Name] = v
	}
}

func IsHashAlgoSupported(algoName string) bool {
	return (nameHashMechMap[strings.ToLower(algoName)] != nil)
}

func (hm *hashMech) newHash() hash.Hash {
	var instance hash.Hash
	switch hm.AlgoName {
	case "md5":
		instance = md5.New()
	case "sha":
		instance = sha1.New()
	case "sha256":
		instance = sha256.New()
	case "sha512":
		instance = sha512.New()
	}

	return instance
}

func HashPassword(plaintext string, algo string) string {
	algo = strings.ToLower(algo)
	hashMech := nameHashMechMap[algo]

	var salt []byte
	if hashMech.Salted {
		salt = RandBytes(salt_size)
	}

	sum := _hashPassword(plaintext, salt, hashMech)
	return "{" + algo + "}" + B64Encode(sum)
}

func _hashPassword(plaintext string, salt []byte, hashMech *hashMech) []byte {
	instance := hashMech.newHash()
	instance.Write([]byte(plaintext))
	if salt != nil {
		instance.Write(salt)
	}
	// sum will be in the order <salt,hash>
	sum := instance.Sum(salt)

	return sum
}

func ComparePassword(plaintext string, hashVal string) bool {
	hashMech := FindHashMech(hashVal)
	if hashMech == nil {
		return (plaintext == hashVal)
	}

	end := strings.IndexRune(hashVal, '}')
	hashBytes, err := B64Decode(hashVal[end+1:])
	if err != nil {
		return false
	}
	var salt []byte
	if hashMech.Salted {
		salt = make([]byte, salt_size)
		copy(salt, hashBytes[:salt_size])
	}

	newHash := _hashPassword(plaintext, salt, hashMech)

	return bytes.Equal(newHash, hashBytes)
}

func IsPasswordHashed(password string) bool {
	return (FindHashMech(password) != nil)
}

func FindHashMech(password string) *hashMech {
	pLen := len(password)
	if pLen == 0 {
		return nil
	}

	if !strings.HasPrefix(password, "{") {
		return nil
	}

	endPos := strings.IndexRune(password, '}')

	if endPos == (pLen - 1) {
		return nil
	}

	algoName := password[1:endPos]
	algoName = strings.ToLower(algoName)

	return nameHashMechMap[algoName]
}

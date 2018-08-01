// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"time"
)

type CookieKeyCache struct {
	keys     []*cookieKey
	keysById map[uint32]*cookieKey
}

type cookieKey struct {
	id       uint32
	key      []byte
	iv       []byte
	lastUsed time.Time
}

func NewCookieKeyCache() *CookieKeyCache {
	ckc := &CookieKeyCache{}
	ckc.keys = make([]*cookieKey, 0)
	ckc.keysById = make(map[uint32]*cookieKey)

	for i := 0; i < 20; i++ {
		ck := ckc.newCookieKey()
		ckc.keys = append(ckc.keys, ck)
		ckc.keysById[ck.id] = ck
	}

	return ckc
}

func (ckc *CookieKeyCache) Encrypt(value []byte) []byte {
	dataLen := len(value) + 1 // the 1 is for length of padding 0>= p <= 15
	pad := (dataLen % aes.BlockSize)

	// pick a key randomly
	index := rand.Intn(len(ckc.keys))
	key := ckc.keys[index]
	buf := bytes.Buffer{}
	buf.Write(EncodeUint32(key.id)) // these 4 bytes MUST NOT be encrypted

	if pad != 0 {
		pad = (dataLen / aes.BlockSize)
		pad = (pad + 1) * aes.BlockSize
		pad -= dataLen
		padData := make([]byte, pad)
		buf.WriteByte(uint8(pad))
		buf.Write(padData)
	} else {
		buf.WriteByte(0)
	}

	buf.Write(value)

	value = buf.Bytes()
	block, _ := aes.NewCipher(key.key)
	cbc := cipher.NewCBCEncrypter(block, key.iv)
	cbc.CryptBlocks(value[4:], value[4:])

	return value
}

func (ckc *CookieKeyCache) Decrypt(b64value string) []byte {
	data, err := B64Decode(b64value)
	if err != nil {
		return nil
	}

	id := DecodeUint32(data[:4])
	key := ckc.keysById[id]

	if key == nil {
		return nil
	}

	block, _ := aes.NewCipher(key.key)
	cbc := cipher.NewCBCDecrypter(block, key.iv)
	data = data[4:]
	cbc.CryptBlocks(data, data)

	padLen := uint8(data[0])
	return data[padLen+1:]
}

func (ckc *CookieKeyCache) newCookieKey() *cookieKey {
	var id uint32

	max_num_keys := 50 // is the max number of iterations

	found := false
	for i := 0; i < max_num_keys; i++ {
		id = rand.Uint32()
		if _, ok := ckc.keysById[id]; !ok {
			found = true
			break
		}
	}

	if !found {
		return nil // time to purge some
	}

	sk := &cookieKey{id: id}
	sk.key = RandBytes(aes.BlockSize)
	sk.iv = RandBytes(aes.BlockSize)

	return sk
}

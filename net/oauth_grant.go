// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sparrow/oauth"
	"sparrow/utils"
	"time"
)

const macLen int = 32 // length of HMAC

type CodeType uint8

const (
	OAuth2 CodeType = iota
	OIDC
	SAML2
)

// Represents OAuth authorization grant returned to clients
// this structure helps in identifying the corresponding
// user for whom this code was issued before generating
// the access token, hence keeps the server working in a
// stateless fashion.
// The use of maps for holding either issued or used codes
// is inefficient
type oAuthGrant struct {
	IvAsId     []byte // the random IV. It will be used as the unique ID for each oAuth grant
	UserId     string
	DomainCode string // first 8 chars of domain name's SHA256 hash
	CreatedAt  int64
	CType      CodeType
}

func newOauthCode(cl *oauth.Client, createdAt time.Time, userId string, domainCode string, ctype CodeType) string {
	iv := utils.RandBytes(aes.BlockSize)

	dataLen := macLen + aes.BlockSize + 36 + 8 + 8 + 1 + 11 // the last 11 are filler bytes to satisfy the block size requirement

	dst := make([]byte, dataLen)
	copy(dst[macLen:], iv)
	copy(dst[macLen+aes.BlockSize:], []byte(userId))
	copy(dst[macLen+aes.BlockSize+36:], []byte(domainCode))
	copy(dst[macLen+aes.BlockSize+36+8:], utils.Itob(createdAt.Unix()))
	dst[macLen+aes.BlockSize+36+8+8] = byte(ctype)
	// leave the rest of the data as 0s

	block, _ := aes.NewCipher(cl.Oauth.ServerSecret)
	cbc := cipher.NewCBCEncrypter(block, iv)

	cbc.CryptBlocks(dst[macLen+aes.BlockSize:], dst[macLen+aes.BlockSize:])

	// generate a new key using ServerSecret and Secret
	hmacKeySrc := make([]byte, 0)
	// secret is stored in hex form
	secretBytes, err := hex.DecodeString(cl.Oauth.Secret)
	if err != nil {
		msg := fmt.Sprintf("Decoding hex value of OAuth secret of client %s failed", cl.Id)
		log.Criticalf(msg)
		panic(msg)
	}

	hmacKeySrc = append(hmacKeySrc, secretBytes...)
	hmacKeySrc = append(hmacKeySrc, cl.Oauth.ServerSecret...)

	hmacKey := sha256.Sum256(hmacKeySrc)

	hmacCalc := hmac.New(sha256.New, hmacKey[:])
	hmacCalc.Write(dst[macLen:])
	mac := hmacCalc.Sum(nil)

	copy(dst, mac)
	return utils.B64UrlEncode(dst)
}

func decryptOauthCode(code string, cl *oauth.Client) *oAuthGrant {
	data, err := utils.B64UrlDecode(code)
	if err != nil {
		return nil
	}

	if len(data) != 112 {
		//AUDIT
		log.Debugf("Invalid authorization code received, insufficent bytes")
		return nil
	}

	expectedMac := data[:macLen]

	// verify HMAC first
	// generate a new key using ServerSecret and Secret
	hmacKeySrc := make([]byte, 0)
	secretBytes, _ := hex.DecodeString(cl.Oauth.Secret) // safe to ignore error if the secret is incorrect code wouldn't have been issued
	hmacKeySrc = append(hmacKeySrc, secretBytes...)
	hmacKeySrc = append(hmacKeySrc, cl.Oauth.ServerSecret...)

	hmacKey := sha256.Sum256(hmacKeySrc)

	hmacCalc := hmac.New(sha256.New, hmacKey[:])
	hmacCalc.Write(data[macLen:])
	mac := hmacCalc.Sum(nil)

	if !hmac.Equal(expectedMac, mac) {
		//AUDIT
		log.Debugf("Invalid authorization code received, possibly tampered")
		return nil
	}

	// end of HMAC verification

	block, _ := aes.NewCipher(cl.Oauth.ServerSecret)
	iv := data[macLen : macLen+aes.BlockSize]
	cbc := cipher.NewCBCDecrypter(block, iv)
	dst := make([]byte, len(data)-(macLen+aes.BlockSize))

	cbc.CryptBlocks(dst, data[macLen+aes.BlockSize:])

	ac := &oAuthGrant{}
	ac.IvAsId = iv
	ac.UserId = string(dst[:36])
	ac.DomainCode = string(dst[36:44])
	ac.CreatedAt = utils.Btoi(dst[44:52])
	ac.CType = CodeType(dst[52])
	// leave the remaining 15 bytes

	return ac
}

// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sparrow/oauth"
	"sparrow/utils"
	"testing"
	"time"
)

func TestCodeGeneration(t *testing.T) {
	ttl := time.Now()
	id := utils.GenUUID()

	domain := "example.com"
	sh2 := sha256.New()
	sh2.Write([]byte(domain))
	hash := sh2.Sum([]byte{})
	hexVal := fmt.Sprintf("%x", hash[:])
	domCode := hexVal[:8]

	cl := &oauth.Client{}
	cl.Id = id
	cl.Oauth = &oauth.ClientOauthConf{}
	cl.Oauth.Secret = utils.NewRandShaStr()
	cl.Oauth.ServerSecret, _ = hex.DecodeString(utils.NewRandShaStr())

	code := newOauthCode(cl, ttl, id, domCode, OAuth2)
	fmt.Println(code)

	ac := decryptOauthCode(code, cl)

	if ac.CreatedAt != ttl.Unix() {
		t.Errorf("Decrypted time does not match encrypted one %d != %d", ac.CreatedAt, ttl.Unix())
	}

	if ac.UserId != id {
		t.Errorf("Decrypted ID does not match encrypted one %s != %s", id, ac.UserId)
	}

	if ac.DomainCode != domCode {
		t.Errorf("Decrypted domain code does not match encrypted one %s != %s", domCode, ac.DomainCode)
	}

	codeSlice := []byte(code)
	fmt.Println(code[0] - 1)
	codeSlice[0] = code[0] - 1
	ac = decryptOauthCode(string(codeSlice), cl)
	if ac != nil {
		t.Errorf("Decoding should fail when code is tampered")
	}
}

func TestBitFlags(t *testing.T) {
	af := &authFlow{}
	yes := true
	af.SetFromOauth(yes)
	af.SetFromSaml(yes)
	af.SetPasswordVerified(yes)
	af.SetTfaRequired(yes)
	af.SetTfaVerified(yes)
	if af.BitFlag != 31 { // 2^5 - 1
		t.Error("Incorrect bit flags")
	}

	yes = false
	af.SetFromOauth(yes)
	af.SetFromSaml(yes)
	af.SetPasswordVerified(yes)
	af.SetTfaRequired(yes)
	af.SetTfaVerified(yes)
	if af.BitFlag != 0 {
		t.Error("Incorrect bit flags")
	}

	af = &authFlow{}
	af.SetPasswordVerified(true)
	af.SetFromOauth(true)
	af.SetTfaRequired(false)
	if !af.FromOauth() {
		t.Error("oauth flag was not set")
	}
}

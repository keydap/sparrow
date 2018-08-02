// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package utils

import (
	"testing"
)

func TestCookieKeyCache(t *testing.T) {
	ckc := NewCookieKeyCache()

	strArr := []string{"0123456789", "0", "", "01234567890123456789", "0123456789abcdef"}

	for _, s := range strArr {
		encStr := B64Encode(ckc.Encrypt([]byte(s)))
		decData, _ := ckc.Decrypt(encStr)
		if s != string(decData) {
			t.Errorf("failed to encrypt and decrypt the value %s", s)
		}
	}
}

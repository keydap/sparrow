// Copyright 2017 Keydap. All rights reserved.
// Use of this source code is governed by a Apache
// license that can be found in the LICENSE file.

package utils

import (
	"testing"
)

const plaintext = "secret"

func TestPasswordHashing(t *testing.T) {
	for k, v := range hashTypeMap {
		hash := HashPassword(plaintext, k)
		t.Log(hash)
		result := ComparePassword(plaintext, hash)
		if !result {
			t.Errorf("Failed to compare the password hashed with %s", v)
		}

		result = ComparePassword("", hash)
		if result {
			t.Errorf("Empty password comparison must fail")
		}
	}
}

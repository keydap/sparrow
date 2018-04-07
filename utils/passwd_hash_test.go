// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package utils

import (
	"testing"
)

const plaintext = "secret"

func TestPasswordHashing(t *testing.T) {
	for _, v := range nameHashMechMap {
		hash := HashPassword(plaintext, v.AlgoName)
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

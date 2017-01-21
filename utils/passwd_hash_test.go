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
	}
}

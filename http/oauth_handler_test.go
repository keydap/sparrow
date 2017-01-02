package http

import (
	"fmt"
	"sparrow/utils"
	"testing"
	"time"
)

func TestCodeGeneration(t *testing.T) {
	key := utils.RandBytes()
	ttl := time.Now()

	code := newOauthCode(key, ttl)
	fmt.Println(code)

	decryptedTtl := decryptOauthCode(code, key)

	if ttl.Unix() != decryptedTtl.Unix() {
		t.Errorf("Decrypted value does not match encrypted one %s != %s", ttl, decryptedTtl)
	}
}

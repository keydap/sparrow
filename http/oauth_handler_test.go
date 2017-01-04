package http

import (
	"fmt"
	"sparrow/utils"
	"testing"
	"time"
)

func TestCodeGeneration(t *testing.T) {
	key := utils.Rand32()
	ttl := time.Now()
	id := utils.GenUUID()

	domain := "example.com"
	var domCode uint32
	for _, r := range domain {
		domCode += uint32(r)
	}

	code := newOauthCode(key, ttl, id, domCode)
	fmt.Println(code)

	ac := decryptOauthCode(code, key)

	if ac.CreatedAt != ttl.Unix() {
		t.Errorf("Decrypted time does not match encrypted one %s != %s", ac.CreatedAt, ttl.Unix())
	}

	if ac.Id != id {
		t.Errorf("Decrypted ID does not match encrypted one %s != %s", id, ac.Id)
	}

	if ac.DomainCode != domCode {
		t.Errorf("Decrypted domain code does not match encrypted one %d != %d", domCode, ac.DomainCode)
	}

}

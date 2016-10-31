package silo

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"
)

func TestCreateJwt(t *testing.T) {
	initSilo()

	user := createTestUser()
	user, _ = sl.Insert(user)

	group := prepareGroup(user)
	sl.Insert(group)

	user, _ = sl.Get(user.GetId(), userType)

	session := sl.Engine.NewRbacSession(user)

	now := time.Now().Unix()
	random := rand.New(rand.NewSource(now))

	priv, err := rsa.GenerateKey(random, 2048)
	if err != nil {
		panic(err)
	}

	fmt.Println(session.ToJwt(priv))
	if false {
		block := &pem.Block{}
		block.Bytes, _ = x509.MarshalPKIXPublicKey(priv.Public())
		block.Type = "RSA PUBLIC KEY"
		keyFile, _ := os.Create("/tmp/xyz.pem")
		pem.Encode(keyFile, block)
		keyFile.Close()
	}
}

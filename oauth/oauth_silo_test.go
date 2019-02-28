// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package oauth

import (
	"fmt"
	logger "github.com/juju/loggo"
	"os"
	"sparrow/utils"
	"testing"
	"time"
)

var dbFilePath = "/tmp/oauth_silo_test.db"
var osl *OauthSilo
var grantcodeTTL = 1
var grantcodePurgeInterval = grantcodeTTL * 2

func TestMain(m *testing.M) {
	logger.ConfigureLoggers("<root>=warn;sparrow.oauth=debug")

	initSilo()

	// now run the tests
	m.Run()

	// cleanup
	os.Remove(dbFilePath)
}

func initSilo() {
	if osl != nil {
		osl.Close()
	}

	os.Remove(dbFilePath)

	var err error
	osl, err = Open(dbFilePath, 120, grantcodePurgeInterval, grantcodeTTL)

	if err != nil {
		fmt.Println("Failed to open oauth silo\n", err)
		os.Exit(1)
	}
}

// this must be an integration test
func TestAddClient(t *testing.T) {
	//	cl := &oauth.Client{}
	//	cl.Id = id
	//	cl.Secret = utils.NewRandShaStr()
	//	cl.ServerSecret = utils.NewRandShaStr()
	//
	//	osl.AddClient(cl)
	//
	//	loaded := osl.GetClient(cl.Id)
	//	if loaded == nil {
	//		t.Errorf("Failed to retrieve the client %s", cl.Id)
	//	}

	/*
		tx, _ := osl.db.Begin(false)
		bc := tx.Bucket(BUC_OAUTH_CLIENTS)
		cursor := bc.Cursor()

		for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
			fmt.Println(string(k))
		}
	*/
}

func TestGrantCodeAddAndPurge(t *testing.T) {
	type testCode struct {
		key   int64
		value []byte
	}

	total := 10
	arr := make([]testCode, total)
	for i := 0; i < total; i++ {
		now := time.Now().Unix()
		id := utils.RandBytes(16)
		arr[i] = testCode{key: now, value: id}
		osl.StoreGrantCodeId(now, id)
	}

	existCount := 0
	for _, v := range arr {
		if osl.HasGrantCodeId(v.key, v.value) {
			existCount++
		}
	}

	if existCount == 0 {
		t.Logf("at least one grant code is expected to be still present in the grant code db")
		t.Fail()
	}

	time.Sleep(time.Duration(grantcodePurgeInterval) * time.Second)
	log.Debugf("checked existence")

	for _, v := range arr {
		if osl.HasGrantCodeId(v.key, v.value) {
			t.Logf("code with ID %d is expected to be purged", v.key)
			t.Fail()
			break
		}
	}
}

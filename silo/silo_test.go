// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"bytes"
	"fmt"
	bolt "github.com/coreos/bbolt"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"os"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/schema"
	"testing"
)

var dbFilePath = "/tmp/silo_test.db"
var config = conf.DefaultDomainConfig()
var resDir, _ = os.Getwd()
var sl *Silo
var uCount int
var userResName string

var schemas map[string]*schema.Schema
var restypes map[string]*schema.ResourceType
var deviceType *schema.ResourceType
var userType *schema.ResourceType
var groupType *schema.ResourceType
var givenName = "Given-Name-fixed-intentionally-to-test-dup-keys"

func TestMain(m *testing.M) {
	logger.ConfigureLoggers("<root>=warn;scim.main=debug")

	resDir += "/../"
	resDir = resDir + "/resources/"
	schemaDir := resDir + "/schemas"
	rtDir := resDir + "/types"

	schemas, _ = base.LoadSchemas(schemaDir)
	restypes, _, _ = base.LoadResTypes(rtDir, schemas)

	deviceType = restypes["Device"]
	userType = restypes["User"]
	groupType = restypes["Group"]

	userResName = userType.Name

	os.Remove(dbFilePath)

	// now run the tests
	m.Run()

	// cleanup
	os.Remove(dbFilePath)
}

func createTestUser() *base.Resource {
	rt := restypes[userResName]

	rs := base.NewResource(rt)

	uCount++

	username := fmt.Sprintf("user-%d", uCount)
	err := rs.AddSA("username", username)

	if err != nil {
		panic(err)
	}

	nameMap := make(map[string]interface{})
	nameMap["formatted"] = "Formatted " + username
	nameMap["familyname"] = "Family " + username
	nameMap["givenName"] = givenName
	nameMap["middleName"] = "Middle " + username
	nameMap["honorificPrefix"] = "Mr."
	nameMap["honorificSuffix"] = "Jr"

	err = rs.AddCA("name", nameMap)
	if err != nil {
		panic(err)
	}

	// always add the same email address so that we can test the duplicate keys in index
	emailsMap := make(map[string]interface{})
	emailsMap["value"] = "bjensen@example.com"
	err = rs.AddCA("emails", emailsMap)
	if err != nil {
		panic(err)
	}

	rs.AddSA("schemas", []string{rt.Schema})
	return rs
}

func initSilo() {
	if sl != nil {
		sl.Close()
	}

	os.Remove(dbFilePath)

	var err error
	// add an index on name.givenName of User resource
	addIndexField("User", "name.givenName")
	addIndexField("User", "organization")
	addIndexField("User", "employeeNumber")

	sl, err = Open(dbFilePath, 0, config, restypes, schemas)

	if err != nil {
		fmt.Println("Failed to open silo\n", err)
		os.Exit(1)
	}
}

func loadTestUser() *base.Resource {
	data, err := ioutil.ReadFile(resDir + "/samples/full-user.json")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	reader := bytes.NewReader(data)
	rs, err := base.ParseResource(restypes, schemas, reader)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return rs
}

func TestInsert(t *testing.T) {
	initSilo()
	user := loadTestUser() //createTestUser()
	metaMap := make(map[string]interface{})
	metaMap["created"] = "abc"
	metaMap["lastmodified"] = "xyz"

	user.AddCA("meta", metaMap)
	uMeta := user.GetMeta()

	crCtx := &base.CreateContext{}
	crCtx.InRes = user
	err := sl.Insert(crCtx)
	if err != nil {
		t.Error("Failed to insert the resource")
		t.Fail()
		t.FailNow()
	}

	rs := crCtx.InRes
	if rs == nil {
		t.Error("Failed to insert the resource")
		t.FailNow()
		return
	}
	rid := rs.GetId()

	if len(rid) == 0 {
		t.Error("Invalid insert operation, no generated ID found for the inserted resource")
		t.FailNow()
	}

	// just testing the Equals() operation
	if !rs.Equals(rs) {
		t.Error("equality of resources failed")
		t.FailNow()
	}
	idx := sl.getIndex(userResName, "username")
	tx, _ := sl.db.Begin(true)
	cnt := idx.getCount(tx)
	//fmt.Printf("Total username count %d\n", cnt)
	if cnt != 1 {
		t.Errorf("Incorrect key count %d in the username index", cnt)
		t.FailNow()
	}

	unameVal := rs.GetAttr("username").GetSimpleAt().Values[0]
	idx.add(unameVal, rid, tx)
	cnt = idx.getCount(tx)
	//fmt.Printf("Total username count %d\n", cnt)
	if cnt != 1 {
		t.Errorf("Key count should not increment after inserting the same key in the index expected %d found %d", 1, cnt)
		t.FailNow()
	}

	cnt = 0
	cur := idx.cursor(tx)
	for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
		cnt++
	}

	if cnt != 1 {
		t.Errorf("Wrong number of entries %d fetched after navigating using a cursor", cnt)
		t.FailNow()
	}

	idx.remove(unameVal, rid, tx)
	tx.Commit() // committing is mandatory to get accurate count
	tx, _ = sl.db.Begin(true)
	cnt = idx.getCount(tx)
	if cnt != 0 {
		t.Errorf("Invalid key count after deleting the username from index, expected %d found %d", 0, cnt)
		t.FailNow()
	}

	idx.remove(unameVal, rid, tx)
	tx.Commit() // committing is mandatory to get accurate count
	tx, _ = sl.db.Begin(true)
	cnt = idx.getCount(tx)
	if cnt != 0 {
		t.Errorf("Invalid key count after attempting to delete the same username again from index, expected %d found %d", 0, cnt)
		t.FailNow()
	}

	// now, put back the username in index to let the rest of the test pass
	idx.add(unameVal, rid, tx)
	tx.Commit()

	// check that metadata is overwritten
	rsMeta := rs.GetMeta()
	if uMeta.GetValue("created") == rsMeta.GetValue("created") {
		t.Error("created time should not match")
		t.FailNow()
	}

	if uMeta.GetValue("lastmodified") == rsMeta.GetValue("lastmodified") {
		t.Error("lastmodified time should not match")
		t.FailNow()
	}

	loaded, err := sl.Get(rid, rs.GetType())

	if err != nil {
		t.Error("Failed to get the saved resource")
		t.FailNow()
	}

	if rid != loaded.GetId() {
		t.Errorf("Invalid resource was retrieved, inserted resource's ID %s is not matching with the retrieved resource's ID", rid)
		t.FailNow()
	}

	// add the same user, should return an error
	err = sl.Insert(crCtx)
	if err == nil {
		t.Error("Failed to detect uniqueness violation of username attribute in the resource")
		t.FailNow()
	}
}

func TestIndexOps(t *testing.T) {
	initSilo()
	email := "bjensen@example.com"
	emailBytes := []byte(email)
	//nameBytes := []byte(givenName)

	emailIdx := sl.indices[userResName]["emails.value"]
	givenNameIdx := sl.indices[userResName]["name.givenname"]

	readTx, err := sl.db.Begin(false)
	if err != nil {
		panic(err)
	}

	emailExists := emailIdx.HasVal(email, readTx)
	emailCount := emailIdx.keyCount(email, readTx)
	nameExists := givenNameIdx.HasVal(givenName, readTx)
	nameCount := givenNameIdx.keyCount(givenName, readTx)
	readTx.Rollback()

	if emailExists || (emailCount != 0) {
		t.Errorf("email %s should not exist", email)
		t.FailNow()
	}

	if nameExists || (nameCount != 0) {
		t.Errorf("givenname %s should not exist", givenName)
		t.FailNow()
	}

	// first user
	rs := createTestUser()
	crCtx := &base.CreateContext{InRes: rs}
	sl.Insert(crCtx)
	rid1 := rs.GetId()

	readTx, _ = sl.db.Begin(false)
	emailCount = emailIdx.keyCount(email, readTx)
	if emailCount != 1 {
		t.Errorf("Email %s count mismatch", email)
		t.FailNow()
	}

	nameCount = givenNameIdx.keyCount(givenName, readTx)
	if nameCount != 1 {
		t.Errorf("givenname %s count mismatch", givenName)
		t.FailNow()
	}

	assertPrCount(rs, readTx, 1, t)
	if !sl.getSysIndex(userResName, "presence").HasVal("emails.value", readTx) {
		t.Error("emails.value should exist in presence index")
		t.FailNow()
	}

	readTx.Rollback()

	// second user
	rs = createTestUser()
	crCtx = &base.CreateContext{}
	crCtx.InRes = rs
	sl.Insert(crCtx)
	rid2 := rs.GetId()

	readTx, _ = sl.db.Begin(false)
	rids := emailIdx.GetRids(emailBytes, readTx)
	assertPrCount(rs, readTx, 2, t)

	nameCount = givenNameIdx.keyCount(givenName, readTx)
	if nameCount != 2 {
		t.Errorf("givenname %s count mismatch expected 2 found %d", givenName, nameCount)
		t.FailNow()
	}

	readTx.Rollback()

	var r1, r2 bool
	for _, v := range rids {
		if v == rid1 {
			r1 = true
		}

		if v == rid2 {
			r2 = true
		}
	}

	if !r1 || !r2 {
		t.Errorf("Required two resource IDs are not present in emails.value index")
	}

	// now delete the resources
	sl.Delete(&base.DeleteContext{Rid: rid1, Rt: rs.GetType()})
	sl.Delete(&base.DeleteContext{Rid: rid2, Rt: rs.GetType()})

	readTx, _ = sl.db.Begin(false)
	rids = emailIdx.GetRids(emailBytes, readTx)
	readTx.Rollback()

	if len(rids) != 0 {
		t.Error("Expecting an empty resource ID slice")
		t.FailNow()
	}

	readTx, _ = sl.db.Begin(false)
	bucket := readTx.Bucket(emailIdx.BnameBytes)
	bucket = bucket.Bucket([]byte(email))
	if bucket != nil {
		t.Error("Bucket associated with indexed attribute emails.value still exists though no values are indexed")
		t.FailNow()
	}
	readTx.Rollback()

	//json := rs.ToJSON()
	//fmt.Println(json)

	// a non-silo related test
	rs.RemoveReadOnlyAt()
	//json = rs.ToJSON()
	//fmt.Println(json)

	if (len(rs.GetId()) != 0) || (rs.GetMeta() != nil) {
		t.Error("RemoveReadOnlyAt() didn't remove readonly attributes")
		t.FailNow()
	}
}

func TestReloadSilo(t *testing.T) {

}

func assertPrCount(rs *base.Resource, readTx *bolt.Tx, expected int64, t *testing.T) {
	prIdx := sl.getSysIndex(userResName, "presence")
	for _, atName := range config.Resources[0].IndexFields {
		// skip if there is no value for the attribute
		if rs.GetAttr(atName) == nil {
			continue
		}
		actual := prIdx.keyCount(atName, readTx)
		if actual != expected {
			t.Errorf("attribute %s count mismatch in presence index actual %d expected %d", atName, actual, expected)
			t.FailNow()
		}
	}
}

func TestSearch(t *testing.T) {
	initSilo()
	rs1 := createTestUser()
	crCtx1 := &base.CreateContext{InRes: rs1}
	sl.Insert(crCtx1)

	rs2 := createTestUser()
	crCtx2 := &base.CreateContext{InRes: rs2}
	sl.Insert(crCtx2)

	filter, _ := base.ParseFilter("userName eq \"" + rs1.GetAttr("username").GetSimpleAt().Values[0].(string) + "\"")
	sc := &base.SearchContext{}
	sc.Filter = filter
	sc.ResTypes = []*schema.ResourceType{restypes[userResName]}

	outPipe := make(chan *base.Resource)

	go sl.Search(sc, outPipe)

	results := readResults(outPipe)

	if len(results) != 1 {
		t.Errorf("Expected %d but received %d", 1, len(results))
		t.FailNow()
	}

	// search using presence filter
	filter, _ = base.ParseFilter("id pr")
	sc.Filter = filter
	outPipe = make(chan *base.Resource)
	go sl.Search(sc, outPipe)
	results = readResults(outPipe)

	if len(results) != 2 {
		t.Errorf("Expected %d but received %d", 2, len(results))
		t.FailNow()
	}

	// search using AND filter
	filter, _ = base.ParseFilter("id pr and userName eq \"" + rs1.GetAttr("username").GetSimpleAt().Values[0].(string) + "\"")
	sc.Filter = filter

	outPipe = make(chan *base.Resource)

	go sl.Search(sc, outPipe)

	results = readResults(outPipe)

	//fmt.Println(results[rs1.GetId()].ToJSON())

	if len(results) != 1 {
		t.Errorf("Expected %d but received %d", 1, len(results))
		t.FailNow()
	}
}

func TestWebauthnInsert(t *testing.T) {
	initSilo()
	user := loadTestUser() //createTestUser()
	crCtx := &base.CreateContext{}
	crCtx.InRes = user
	sl.Insert(crCtx)
	rs := crCtx.InRes
	rid := rs.GetId()

	// test generating webauthn id
	userWithWebauthnKey, _ := sl.GenWebauthnIdFor(rid)
	wid := userWithWebauthnKey.AuthData.WebauthnId
	if len(wid) == 0 {
		t.Error("Invalid webauthn id")
		t.FailNow()
	}

	tx, _ := sl.db.Begin(false)
	userIdByWebauthnId := tx.Bucket(BUC_WEBAUTHN).Get([]byte(wid))
	tx.Rollback()
	if len(userIdByWebauthnId) == 0 {
		t.Error("webauthn id was not stored in the index")
		t.FailNow()
	}

	// try generating again for the same user, it should return the old one
	_, err := sl.GenWebauthnIdFor(rid)
	if err == nil {
		t.Error("webauthn ID should not be re-generated")
		t.FailNow()
	}

	wres, _ := sl.GetUserByWebauthnId(wid)
	if wres.GetId() != rid {
		t.Error("failed to find the user by webauthn ID")
		t.FailNow()
	}

	delCtx := &base.DeleteContext{}
	delCtx.Rid = rid
	delCtx.Rt = restypes["User"]
	err = sl.Delete(delCtx)
	if err != nil {
		t.FailNow()
	}

	_, err = sl.GetUserByWebauthnId(wid)
	if err == nil {
		t.Errorf("the user should not be found by webauthn ID after deleting the user")
		t.FailNow()
	}
}

func BenchmarkResourceInsertion(t *testing.B) {
	initSilo()
	user := loadTestUser() //createTestUser()
	crCtx := &base.CreateContext{}
	crCtx.InRes = user
	usernameAt := user.GetAttr("username").GetSimpleAt()
	username := usernameAt.GetStringVal()
	for i := 0; i < t.N; i++ {
		usernameAt.Values[0] = fmt.Sprintf("%s-%d", username, i)
		sl.Insert(crCtx)
	}
}

func readResults(outPipe chan *base.Resource) map[string]*base.Resource {
	//fmt.Println("reading from pipe")
	results := make(map[string]*base.Resource)
	for rs := range outPipe {
		//fmt.Println("received RS ", rs.GetId())
		results[rs.GetId()] = rs
	}

	return results
}

func addIndexField(resName string, atName string) {
	for _, r := range config.Resources {
		if r.Name == resName {
			r.IndexFields = append(r.IndexFields, atName)
			break
		}
	}
}

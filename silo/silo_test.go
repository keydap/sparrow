// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"bytes"
	"fmt"
	"github.com/coreos/bbolt"
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

	rs, err := sl.Insert(user)

	//fmt.Println(rs.ToJSON())

	rid := rs.GetId()

	if err != nil {
		t.Error("Failed to insert the resource")
	}

	if rs == nil {
		t.Error("Failed to insert the resource")
		return
	}

	if len(rid) == 0 {
		t.Error("Invalid insert operation, no generated ID found for the inserted resource")
	}

	idx := sl.getIndex(userResName, "username")
	tx, _ := sl.db.Begin(true)
	cnt := idx.getCount(tx)
	//fmt.Printf("Total username count %d\n", cnt)
	if cnt != 1 {
		t.Errorf("Incorrect key count %d in the username index", cnt)
	}

	unameVal := rs.GetAttr("username").GetSimpleAt().Values[0]
	idx.add(unameVal, rid, tx)
	cnt = idx.getCount(tx)
	//fmt.Printf("Total username count %d\n", cnt)
	if cnt != 1 {
		t.Errorf("Key count should not increment after inserting the same key in the index expected %d found %d", 1, cnt)
	}

	cnt = 0
	cur := idx.cursor(tx)
	for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
		cnt++
	}

	if cnt != 1 {
		t.Errorf("Wrong number of entries %d fetched after navigating using a cursor", cnt)
	}

	idx.remove(unameVal, rid, tx)
	tx.Commit() // committing is mandatory to get accurate count
	tx, _ = sl.db.Begin(true)
	cnt = idx.getCount(tx)
	if cnt != 0 {
		t.Errorf("Invalid key count after deleting the username from index, expected %d found %d", 0, cnt)
	}

	idx.remove(unameVal, rid, tx)
	tx.Commit() // committing is mandatory to get accurate count
	tx, _ = sl.db.Begin(true)
	cnt = idx.getCount(tx)
	if cnt != 0 {
		t.Errorf("Invalid key count after attempting to delete the same username again from index, expected %d found %d", 0, cnt)
	}

	// now, put back the username in index to let the rest of the test pass
	idx.add(unameVal, rid, tx)
	tx.Commit()

	// check that metadata is overwritten
	rsMeta := rs.GetMeta()
	if uMeta.GetValue("created") == rsMeta.GetValue("created") {
		t.Error("created time should not match")
	}

	if uMeta.GetValue("lastmodified") == rsMeta.GetValue("lastmodified") {
		t.Error("lastmodified time should not match")
	}

	loaded, err := sl.Get(rid, rs.GetType())

	if err != nil {
		t.Error("Failed to get the saved resource")
	}

	if rid != loaded.GetId() {
		t.Errorf("Invalid resource was retrieved, inserted resource's ID %s is not matching with the retrieved resource's ID", rid)
	}

	// add the same user, should return an error
	rs, err = sl.Insert(user)
	if err == nil {
		t.Error("Failed to detect uniqueness violation of username attribute in the resource")
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
	}

	if nameExists || (nameCount != 0) {
		t.Errorf("givenname %s should not exist", givenName)
	}

	// first user
	rs := createTestUser()
	sl.Insert(rs)
	rid1 := rs.GetId()

	readTx, _ = sl.db.Begin(false)
	emailCount = emailIdx.keyCount(email, readTx)
	if emailCount != 1 {
		t.Errorf("Email %s count mismatch", email)
	}

	nameCount = givenNameIdx.keyCount(givenName, readTx)
	if nameCount != 1 {
		t.Errorf("givenname %s count mismatch", givenName)
	}

	assertPrCount(rs, readTx, 1, t)
	if !sl.getSysIndex(userResName, "presence").HasVal("emails.value", readTx) {
		t.Error("emails.value should exist in presence index")
	}

	readTx.Rollback()

	// second user
	rs = createTestUser()
	sl.Insert(rs)
	rid2 := rs.GetId()

	readTx, _ = sl.db.Begin(false)
	rids := emailIdx.GetRids(emailBytes, readTx)
	assertPrCount(rs, readTx, 2, t)

	nameCount = givenNameIdx.keyCount(givenName, readTx)
	if nameCount != 2 {
		t.Errorf("givenname %s count mismatch expected 2 found %d", givenName, nameCount)
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
	sl.Delete(rid1, rs.GetType())
	sl.Delete(rid2, rs.GetType())

	readTx, _ = sl.db.Begin(false)
	rids = emailIdx.GetRids(emailBytes, readTx)
	readTx.Rollback()

	if len(rids) != 0 {
		t.Error("Expecting an empty resource ID slice")
	}

	readTx, _ = sl.db.Begin(false)
	bucket := readTx.Bucket(emailIdx.BnameBytes)
	bucket = bucket.Bucket([]byte(email))
	if bucket != nil {
		t.Error("Bucket associated with indexed attribute emails.value still exists though no values are indexed")
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
		}
	}
}

func TestSearch(t *testing.T) {
	initSilo()
	rs1 := createTestUser()
	rs1, _ = sl.Insert(rs1)

	rs2 := createTestUser()
	rs2, _ = sl.Insert(rs2)

	filter, _ := base.ParseFilter("userName eq \"" + rs1.GetAttr("username").GetSimpleAt().Values[0].(string) + "\"")
	sc := &base.SearchContext{}
	sc.Filter = filter
	sc.ResTypes = []*schema.ResourceType{restypes[userResName]}

	outPipe := make(chan *base.Resource)

	go sl.Search(sc, outPipe)

	results := readResults(outPipe)

	if len(results) != 1 {
		t.Errorf("Expected %d but received %d", 1, len(results))
	}

	// search using presence filter
	filter, _ = base.ParseFilter("id pr")
	sc.Filter = filter
	outPipe = make(chan *base.Resource)
	go sl.Search(sc, outPipe)
	results = readResults(outPipe)

	if len(results) != 2 {
		t.Errorf("Expected %d but received %d", 2, len(results))
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

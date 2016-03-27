package silo

import (
	"fmt"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"os"
	"sparrow/scim/conf"
	"sparrow/scim/provider"
	"testing"
)

var dbFilePath = "/tmp/silo_test.db"
var config = conf.DefaultConfig()
var resDir, _ = os.Getwd()
var sl *Silo
var uCount int
var userResSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

func TestMain(m *testing.M) {
	logger.ConfigureLoggers("<root>=debug;scim.main=debug")

	resDir += "/../../"
	resDir = resDir + "/resources/"
	schemaDir := resDir + "/schemas"
	rtDir := resDir + "/types"

	schemas, _ = provider.LoadSchemas(schemaDir)
	restypes, _ = provider.LoadResTypes(rtDir)

	os.Remove(dbFilePath)

	// now run the tests
	m.Run()

	// cleanup
	os.Remove(dbFilePath)
}

func createTestUser() *provider.Resource {
	rt := restypes[userResSchema]

	rs := provider.NewResource(rt)

	uCount++

	username := fmt.Sprintf("user-%d", uCount)
	err := rs.AddSA("username", username)

	if err != nil {
		panic(err)
	}

	nameMap := make(map[string]interface{})
	nameMap["formatted"] = "Formatted " + username
	nameMap["familyname"] = "Family " + username
	nameMap["givenName"] = "Given " + username
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
	sl, err = Open(dbFilePath, config, restypes, schemas)

	if err != nil {
		fmt.Println("Failed to open silo\n", err)
		os.Exit(1)
	}
}

func loadTestUser() *provider.Resource {
	data, err := ioutil.ReadFile(resDir + "/samples/full-user.json")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rs, err := provider.ParseResource(restypes, schemas, string(data))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return rs
}

func TestInsert(t *testing.T) {
	initSilo()
	rs, err := sl.Insert(loadTestUser())

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

	loaded, err := sl.Get(rid, rs.GetType())

	if err != nil {
		t.Error("Failed to get the saved resource")
	}

	if rid != loaded.GetId() {
		t.Errorf("Invalid resource was retrieved, inserted resource's ID %s is not matching with the retrieved resource's ID", rid)
	}

	// add the same user, should return an error
	rs, err = sl.Insert(loadTestUser())
	if err == nil {
		t.Error("Failed to detect uniqueness violation of username attribute in the resource")
	}
}

func TestIndexOps(t *testing.T) {
	initSilo()
	email := "bjensen@example.com"

	idx := sl.indices["user"]["emails.value"]

	readTx, err := sl.db.Begin(false)
	if err != nil {
		panic(err)
	}

	exists := idx.HasVal(email, readTx)
	readTx.Rollback()

	if exists {
		t.Errorf("Email %s should not exist", email)
	}

	// first user
	rs := createTestUser()
	sl.Insert(rs)
	rid1 := rs.GetId()

	// second user
	rs = createTestUser()
	sl.Insert(rs)
	rid2 := rs.GetId()

	readTx, _ = sl.db.Begin(false)
	rids := idx.GetRids(email, readTx)
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
	sl.Remove(rid1, rs.GetType())
	sl.Remove(rid2, rs.GetType())

	readTx, _ = sl.db.Begin(false)
	rids = idx.GetRids(email, readTx)
	readTx.Rollback()

	if len(rids) != 0 {
		t.Error("Expecting an empty resource ID slice")
	}

	readTx, _ = sl.db.Begin(false)
	bucket := readTx.Bucket(idx.BnameBytes)
	bucket = bucket.Bucket([]byte(email))
	if bucket != nil {
		t.Error("Bucket associated with indexed attribute still exists though no values are indexed")
	}
	readTx.Rollback()
}

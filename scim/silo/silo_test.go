package silo

import (
	"fmt"
	"github.com/boltdb/bolt"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"os"
	"sparrow/scim/conf"
	"sparrow/scim/provider"
	"sparrow/scim/schema"
	"testing"
)

var dbFilePath = "/tmp/silo_test.db"
var config = conf.DefaultConfig()
var resDir, _ = os.Getwd()
var sl *Silo
var uCount int
var userResName = "User"

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
	rt := restypes[userResName]

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
	user := createTestUser()
	metaMap := make(map[string]interface{})
	metaMap["created"] = "abc"
	metaMap["lastmodified"] = "xyz"

	user.AddCA("meta", metaMap)
	uMeta := user.GetMeta()

	resCount := sl.resCounts[userResName]
	if resCount != 0 {
		t.Errorf("Invalid initial count %d of resource %s", resCount, userResName)
	}

	rs, err := sl.Insert(user)

	resCount = sl.resCounts[userResName]
	if resCount != 1 {
		t.Errorf("Invalid initial count %d of resource %s", resCount, userResName)
	}

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

	// check that metadata is overwritten
	rsMeta := rs.GetMeta()
	if uMeta.Get("created") == rsMeta.Get("created") {
		t.Error("created time should not match")
	}

	if uMeta.Get("lastmodified") == rsMeta.Get("lastmodified") {
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

	idx := sl.indices[userResName]["emails.value"]

	readTx, err := sl.db.Begin(false)
	if err != nil {
		panic(err)
	}

	exists := idx.HasVal(email, readTx)
	count := idx.keyCount(email, readTx)
	readTx.Rollback()

	if exists || (count != 0) {
		t.Errorf("Email %s should not exist", email)
	}

	// first user
	rs := createTestUser()
	sl.Insert(rs)
	rid1 := rs.GetId()

	readTx, _ = sl.db.Begin(false)
	count = idx.keyCount(email, readTx)
	if count != 1 {
		t.Errorf("Email %s count mismatch", email)
	}

	assertPrCount(rs, readTx, 1, t)

	readTx.Rollback()

	// second user
	rs = createTestUser()
	sl.Insert(rs)
	rid2 := rs.GetId()

	readTx, _ = sl.db.Begin(false)
	rids := idx.GetRids(email, readTx)
	assertPrCount(rs, readTx, 2, t)
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

	json, _ := rs.ToJSON()
	fmt.Println(json)

	// a non-silo related test
	rs.RemoveReadOnlyAt()
	json, _ = rs.ToJSON()
	fmt.Println(json)

	if (len(rs.GetId()) != 0) || (rs.GetMeta() != nil) {
		t.Error("RemoveReadOnlyAt() didn't remove readonly attributes")
	}
}

func TestReloadSilo(t *testing.T) {

}

func assertPrCount(rs *provider.Resource, readTx *bolt.Tx, expected int64, t *testing.T) {
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

	filter, _ := provider.ParseFilter("username eq \"" + rs1.GetAttr("username").GetSimpleAt().Values[0] + "\"")
	sc := &provider.SearchContext{}
	sc.Filter = filter
	sc.ResTypes = []*schema.ResourceType{restypes[userResName]}

	results, err := sl.Search(sc)
	if err != nil {
		t.Errorf("Failed to search using filter %s (%s)", sc.Filter, err.Error())
	}

	fmt.Println(results[rs1.GetId()].ToJSON())

	if len(results) != 1 {
		t.Errorf("Expected %d but received %d", 1, len(results))
	}

	// search using presence filter
	filter, _ = provider.ParseFilter("id pr")
	sc.Filter = filter
	results, err = sl.Search(sc)
	if err != nil {
		t.Errorf("Failed to search using PR filter %s (%s)", sc.Filter, err.Error())
	}

	if len(results) != 2 {
		t.Errorf("Expected %d but received %d", 2, len(results))
	}
}

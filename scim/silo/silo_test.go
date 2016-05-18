package silo

import (
	"bytes"
	"fmt"
	"github.com/boltdb/bolt"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"os"
	"sparrow/scim/base"
	"sparrow/scim/conf"
	"sparrow/scim/schema"
	"testing"
)

var dbFilePath = "/tmp/silo_test.db"
var config = conf.DefaultConfig()
var resDir, _ = os.Getwd()
var sl *Silo
var uCount int
var userResName = "User"

var schemas map[string]*schema.Schema
var restypes map[string]*schema.ResourceType

func TestMain(m *testing.M) {
	logger.ConfigureLoggers("<root>=warn;scim.main=debug")

	resDir += "/../../"
	resDir = resDir + "/resources/"
	schemaDir := resDir + "/schemas"
	rtDir := resDir + "/types"

	schemas, _ = base.LoadSchemas(schemaDir)
	restypes, _, _ = base.LoadResTypes(rtDir, schemas)

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
	if !sl.getSysIndex(userResName, "presence").HasVal("emails.value", readTx) {
		t.Error("emails.value should exist in presence index")
	}

	readTx.Rollback()

	// second user
	rs = createTestUser()
	sl.Insert(rs)
	rid2 := rs.GetId()

	readTx, _ = sl.db.Begin(false)
	rids := idx.GetRids(emailBytes, readTx)
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
	rids = idx.GetRids(emailBytes, readTx)
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

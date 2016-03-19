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

func TestMain(m *testing.M) {
	logger.ConfigureLoggers("<root>=debug;scim.main=debug")

	resDir += "/../../"
	resDir = resDir + "/resources/"
	schemaDir := resDir + "/schemas"
	rtDir := resDir + "/types"

	schemas, _ = provider.LoadSchemas(schemaDir)
	restypes, _ = provider.LoadResTypes(rtDir)

	// now run the tests
	m.Run()

	// cleanup
	os.Remove(dbFilePath)
}

func createTestUser() *provide.Resource {

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
	//var idx Index

	//idx.add
}

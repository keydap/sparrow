package provider

import (
	//"encoding/json"
	"fmt"
	logger "github.com/juju/loggo"
	"os"
	"sparrow/scim/schema"
	"strings"
)

var schemas = make(map[string]*schema.Schema)
var resources = make(map[string]*schema.ResourceType)

type AuthContext struct {
}

var log logger.Logger

func init() {
	log = logger.GetLogger("scim.provider")
}

func Start(layout *Layout) error {
	err := loadSchemas(layout)
	if err != nil {
		return err
	}

	err = loadResTypes(layout)
	if err != nil {
		return err
	}

	return nil
}

func AddSchema(sc *schema.Schema) {
	schemas[sc.Id] = sc
}

func loadSchemas(layout *Layout) error {
	dir, err := os.Open(layout.SchemaDir)
	if err != nil {
		log.Criticalf("Could not open schema directory %s [%s]", layout.SchemaDir, err)
		return err
	}

	files, err := dir.Readdir(-1)

	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			sc, err := schema.LoadSchema(name)
			if err != nil {
				log.Warningf("Failed to load schema from file %s [%s]", name, err)
				continue
			}

			log.Infof("Loaded schema %s", sc.Id)
			schemas[sc.Id] = sc
		}
	}

	log.Infof("Loaded %d schemas", len(schemas))
	return nil
}

func loadResTypes(layout *Layout) error {
	dir, err := os.Open(layout.ResTypesDir)
	if err != nil {
		log.Criticalf("Could not open resourcetypes directory %s [%s]", layout.ResTypesDir, err)
		return err
	}

	files, err := dir.Readdir(-1)

	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			rt, err := schema.LoadResourceType(name, schemas)
			if err != nil {
				log.Warningf("Failed to load resource type from file %s [%s]", name, err)
				continue
			}

			log.Infof("Loaded resource type %s", rt.Id)
			resources[rt.Id] = rt
		}
	}

	log.Infof("Loaded %d resource types", len(resources))
	return nil
}

func GetSchemaJsonArray() string {
	json := "["

	for _, v := range schemas {
		json += v.Text + ","
	}

	json = strings.TrimSuffix(json, ",")

	return json + "]"
}

func GetSchema(id string) (string, error) {
	sc := schemas[id]

	if sc == nil {
		return "", fmt.Errorf("No schema present with the ID %s", id)
	}

	return sc.Text, nil
}

func GetResTypeJsonArray() string {
	json := "["

	for _, v := range resources {
		json += v.Text + ","
	}

	json = strings.TrimSuffix(json, ",")

	return json + "]"
}

func GetResourceType(id string) (string, error) {
	rt := resources[id]

	if rt == nil {
		return "", fmt.Errorf("No resource type present with the ID %s", id)
	}

	return rt.Text, nil
}

/*
func CreateResource(jsonData string) error {
	obj, err := validateData(sc, jsonData)

	if obj != nil {

	}
	if err != nil {
		return err
	}

	return nil
}
*/

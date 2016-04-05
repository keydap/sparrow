package provider

import (
	//"encoding/json"
	"fmt"
	logger "github.com/juju/loggo"
	"os"
	"sparrow/scim/schema"
	"strings"
)

var schemas = make(map[string]*schema.Schema)         // a map of Schema ID to Schema
var resources = make(map[string]*schema.ResourceType) // a map of Name to ResourceTye
var rsPathMap = make(map[string]*schema.ResourceType) // a map of EndPoint to ResourceTye

type AuthContext struct {
}

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.scim.provider")
}

func Start(layout *Layout) error {
	_, err := LoadSchemas(layout.SchemaDir)
	if err != nil {
		return err
	}

	_, err = LoadResTypes(layout.ResTypesDir)
	if err != nil {
		return err
	}

	return nil
}

func AddSchema(sc *schema.Schema) {
	schemas[sc.Id] = sc
}

func LoadSchemas(sDirPath string) (map[string]*schema.Schema, error) {
	dir, err := os.Open(sDirPath)
	if err != nil {
		log.Criticalf("Could not open schema directory %s [%s]", sDirPath, err)
		return nil, err
	}

	files, err := dir.Readdir(-1)

	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			sc, err := schema.LoadSchema((sDirPath + "/" + name))
			if err != nil {
				log.Warningf("Failed to load schema from file %s [%s]", name, err)
				continue
			}

			log.Infof("Loaded schema %s", sc.Id)
			schemas[sc.Id] = sc
		}
	}

	log.Infof("Loaded %d schemas", len(schemas))
	return schemas, nil
}

func LoadResTypes(rtDirPath string) (map[string]*schema.ResourceType, error) {
	dir, err := os.Open(rtDirPath)
	if err != nil {
		log.Criticalf("Could not open resourcetypes directory %s [%s]", rtDirPath, err)
		return nil, err
	}

	files, err := dir.Readdir(-1)

	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			rt, err := schema.LoadResourceType((rtDirPath + "/" + name), schemas)
			if err != nil {
				log.Warningf("Failed to load resource type from file %s [%s]", name, err)
				continue
			}

			log.Infof("Loaded resource type %s", rt.Id)

			// check if any of the resources are defined with duplicate Name or
			if _, ok := resources[rt.Name]; ok {
				panic(fmt.Errorf("Duplicate resource type, a ResourceType with the Name '%s' already exists", rt.Name))
			}

			// are mapped to the same path
			if _, ok := rsPathMap[rt.Endpoint]; ok {
				panic(fmt.Errorf("Duplicate resource type, a ResourceType with the Endpoint '%s' already exists", rt.Endpoint))
			}

			resources[rt.Name] = rt
			rsPathMap[rt.Endpoint] = rt
		}
	}

	log.Infof("Loaded %d resource types", len(resources))
	return resources, nil
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

func GetResourceType(name string) (string, error) {
	rt := resources[name]

	if rt == nil {
		return "", fmt.Errorf("No resource type present with the ID %s", name)
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

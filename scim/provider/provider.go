package provider

import (
	//	"encoding/json"
	logger "github.com/juju/loggo"
	"net/http"
	"os"
	"sparrow/scim/schema"
	"strings"
)

var schemas = make(map[string]*schema.Schema)

type AuthContext struct {
}

var log logger.Logger

func init() {
	log = logger.GetLogger("scim.provider")
}

func Start(layout *Layout) {
	loadSchemas(layout)
	http.HandleFunc("/Schemas", serveSchemas)
}

func loadSchemas(layout *Layout) {
	dir, err := os.Open(layout.SchemaDir)
	if err != nil {
		log.Criticalf("Could not open schema directory %s [%s]", layout.SchemaDir, err)
		os.Exit(1)
	}

	files, err := dir.Readdir(-1)

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

			schemas[sc.Id] = sc
		}
	}
}

func serveSchemas(w http.ResponseWriter, req *http.Request) {

}

/*
func CreateResource(sc *schema.Schema, jsonData string) error {
	obj, err := validateData(sc, jsonData)

	if obj != nil {

	}
	if err != nil {
		return err
	}

	return nil
}
*/

package provider

import (
	//"encoding/json"
	"fmt"
	logger "github.com/juju/loggo"
	"path/filepath"
	"sparrow/scim/base"
	"sparrow/scim/conf"
	"sparrow/scim/schema"
	"sparrow/scim/silo"
	"strings"
)

type Provider struct {
	schemas   map[string]*schema.Schema       // a map of Schema ID to Schema
	rsTypes   map[string]*schema.ResourceType // a map of Name to ResourceTye
	rtPathMap map[string]*schema.ResourceType // a map of EndPoint to ResourceTye
	config    *conf.Config
	sl        *silo.Silo
	layout    *Layout
}

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.scim.provider")
}

func NewProvider(layout *Layout) (prv *Provider, err error) {
	schemas, err := base.LoadSchemas(layout.SchemaDir)
	if err != nil {
		return nil, err
	}

	prv = &Provider{}
	prv.schemas = schemas

	prv.rsTypes, prv.rtPathMap, err = base.LoadResTypes(layout.ResTypesDir, prv.schemas)
	if err != nil {
		return nil, err
	}

	dataFilePath := filepath.Join(layout.DataDir, layout.name)

	prv.sl, err = silo.Open(dataFilePath, prv.config, prv.rsTypes, prv.schemas)

	if err != nil {
		return nil, err
	}

	prv.layout = layout

	return prv, nil
}

func (prv *Provider) GetSchemaJsonArray() string {
	json := "["

	for _, v := range prv.schemas {
		json += v.Text + ","
	}

	json = strings.TrimSuffix(json, ",")

	return json + "]"
}

func (prv *Provider) GetSchema(id string) (string, error) {
	sc := prv.schemas[id]

	if sc == nil {
		return "", fmt.Errorf("No schema present with the ID %s", id)
	}

	return sc.Text, nil
}

func (prv *Provider) GetResTypeJsonArray() string {
	json := "["

	for _, v := range prv.rsTypes {
		json += v.Text + ","
	}

	json = strings.TrimSuffix(json, ",")

	return json + "]"
}

func (prv *Provider) GetResourceType(name string) (string, error) {
	rt := prv.rsTypes[name]

	if rt == nil {
		return "", fmt.Errorf("No resource type present with the ID %s", name)
	}

	return rt.Text, nil
}

/*
func (prv *Provider) CreateResource(jsonData string) error {
	obj, err := validateData(sc, jsonData)

	if obj != nil {

	}
	if err != nil {
		return err
	}

	return nil
}
*/

func (prv *Provider) Search(sc *base.SearchContext, outPipe chan *base.Resource) error {
	node, err := base.ParseFilter(sc.ParamFilter)
	if err != nil {
		return base.NewBadRequestError(err.Error())
	}

	sc.Filter = node

	var rt *schema.ResourceType

	for _, v := range prv.rsTypes {
		if strings.Contains(sc.Endpoint, v.Endpoint) {
			rt = v
			break
		}
	}

	if rt == nil { // must have been searched at server root
		sc.ResTypes = make([]*schema.ResourceType, len(prv.rsTypes))
		count := 0
		for _, v := range prv.rsTypes {
			sc.ResTypes[count] = v
			count++
		}
	} else {
		sc.ResTypes = make([]*schema.ResourceType, 1)
		sc.ResTypes[0] = rt
	}

	prv.sl.Search(sc, outPipe)

	return nil
}

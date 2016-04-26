package provider

import (
	//"encoding/json"
	"fmt"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"path/filepath"
	"sparrow/scim/base"
	"sparrow/scim/conf"
	"sparrow/scim/schema"
	"sparrow/scim/silo"
	"strings"
)

type Provider struct {
	Schemas   map[string]*schema.Schema       // a map of Schema ID to Schema
	RsTypes   map[string]*schema.ResourceType // a map of Name to ResourceTye
	RtPathMap map[string]*schema.ResourceType // a map of EndPoint to ResourceTye
	config    *conf.Config
	sl        *silo.Silo
	layout    *Layout
	Name      string // the domain name
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
	prv.Schemas = schemas

	prv.RsTypes, prv.RtPathMap, err = base.LoadResTypes(layout.ResTypesDir, prv.Schemas)
	if err != nil {
		return nil, err
	}

	prv.config, err = conf.ParseConfig(filepath.Join(layout.ConfDir, "config.json"))
	if err != nil {
		return nil, err
	}

	dataFilePath := filepath.Join(layout.DataDir, layout.name)

	prv.sl, err = silo.Open(dataFilePath, prv.config, prv.RsTypes, prv.Schemas)

	if err != nil {
		return nil, err
	}

	prv.layout = layout
	prv.Name = layout.name

	return prv, nil
}

func (prv *Provider) GetSchemaJsonArray() string {
	json := "["

	for _, v := range prv.Schemas {
		json += v.Text + ","
	}

	json = strings.TrimSuffix(json, ",")

	return json + "]"
}

func (prv *Provider) GetSchema(id string) (string, error) {
	sc := prv.Schemas[id]

	if sc == nil {
		return "", fmt.Errorf("No schema present with the ID %s", id)
	}

	return sc.Text, nil
}

func (prv *Provider) GetResTypeJsonArray() string {
	json := "["

	for _, v := range prv.RsTypes {
		json += v.Text + ","
	}

	json = strings.TrimSuffix(json, ",")

	return json + "]"
}

func (prv *Provider) GetResourceType(name string) (string, error) {
	rt := prv.RsTypes[name]

	if rt == nil {
		return "", fmt.Errorf("No resource type present with the ID %s", name)
	}

	return rt.Text, nil
}

func (prv *Provider) GetConfigJson() (data []byte, err error) {
	f := filepath.Join(prv.layout.ConfDir, "config.json")
	return ioutil.ReadFile(f)
}

func (prv *Provider) CreateResource(opCtx *base.OpContext) (res *base.Resource, err error) {
	return prv.sl.Insert(opCtx.Rs)
}

func (prv *Provider) DeleteResource(opCtx *base.OpContext, rid string, rt *schema.ResourceType) error {
	return prv.sl.Remove(rid, rt)
}

func (prv *Provider) GetResource(opCtx *base.OpContext, rid string, rt *schema.ResourceType) (res *base.Resource, err error) {
	return prv.sl.Get(rid, rt)
}

func (prv *Provider) Search(sc *base.SearchContext, outPipe chan *base.Resource) error {
	node, err := base.ParseFilter(sc.ParamFilter)
	if err != nil {
		return base.NewBadRequestError(err.Error())
	}

	sc.Filter = node

	var rt *schema.ResourceType

	for _, v := range prv.RsTypes {
		if strings.Contains(sc.Endpoint, v.Endpoint) {
			rt = v
			break
		}
	}

	if rt == nil { // must have been searched at server root
		sc.ResTypes = make([]*schema.ResourceType, len(prv.RsTypes))
		count := 0
		for _, v := range prv.RsTypes {
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

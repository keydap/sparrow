package schema

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"strings"
)

type SchemaExtension struct {
	Schema   string
	Required bool
}

type ResourceType struct {
	Id               string
	Name             string
	Endpoint         string
	Description      string
	Schema           string
	SchemaExtensions []*SchemaExtension
	Meta             struct {
		Location     string
		ResourceType string
	}

	schemas      map[string]*Schema // map containing the main and extension schemas
	Text         string             // the JSON representation of this resource type
	UniqueAts    []string           // a collection of all unique attributes
	AtsNeverRtn  map[string]int     // names of attributes that are never returned
	AtsAlwaysRtn map[string]int     // names of attributes that are always returned
}

func LoadResourceType(name string, sm map[string]*Schema) (*ResourceType, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	log.Debugf("Loading resourcetype from file " + name)
	return NewResourceType(data, sm)
}

func NewResourceType(data []byte, sm map[string]*Schema) (*ResourceType, error) {
	rt := &ResourceType{}
	err := json.Unmarshal(data, rt)

	if err != nil {
		return nil, err
	}

	ve := &ValidationErrors{}

	rt.Name = strings.TrimSpace(rt.Name)
	if len(rt.Name) == 0 {
		ve.add("Name attribute of the resourcetype cannot be empty")
	}

	rt.Endpoint = path.Clean(strings.TrimSpace(rt.Endpoint))
	if len(rt.Endpoint) == 0 {
		ve.add("Endpoint attribute of the resourcetype cannot be empty")
	}

	rt.schemas = make(map[string]*Schema)

	rt.Schema = strings.TrimSpace(rt.Schema)
	if len(rt.Schema) == 0 {
		ve.add("Schema attribute of the resourcetype cannot be empty")
	} else if sm[rt.Schema] == nil {
		ve.add("No Schema found associated with the URN " + rt.Schema)
	} else {
		rt.schemas[rt.Schema] = sm[rt.Schema]
		log.Debugf("setting main schema %s on resourcetype %s", rt.Schema, rt.Name)
	}

	rt.UniqueAts = make([]string, 0)
	rt.AtsNeverRtn = make(map[string]int)
	rt.AtsAlwaysRtn = make(map[string]int)

	if len(rt.SchemaExtensions) != 0 {
		for _, ext := range rt.SchemaExtensions {
			ext.Schema = strings.TrimSpace(ext.Schema)
			if len(ext.Schema) == 0 {
				ve.add("Schema attribute of the resourcetype's extension cannot be empty")
			} else if sm[ext.Schema] == nil {
				ve.add("No Schema found associated with the extension schema URN " + ext.Schema)
			} else {
				rt.schemas[ext.Schema] = sm[ext.Schema]
				rt.UniqueAts = append(rt.UniqueAts, sm[ext.Schema].UniqueAts...)
				copyReturnAttrs(rt, sm[ext.Schema])
			}
		}
	}

	if ve.Count > 0 {
		return nil, ve
	}

	mainSchema := rt.schemas[rt.Schema]
	// common attributes
	addCommonAttrs(mainSchema)

	rt.UniqueAts = append(rt.UniqueAts, mainSchema.UniqueAts...)
	copyReturnAttrs(rt, mainSchema)

	rt.Text = string(data)
	return rt, nil
}

func copyReturnAttrs(rt *ResourceType, sc *Schema) {
	sc.collectReturnAttrs()

	for _, v := range sc.AtsAlwaysRtn {
		rt.AtsAlwaysRtn[v] = 1
	}

	for _, v := range sc.AtsNeverRtn {
		rt.AtsNeverRtn[v] = 1
	}
}

func addCommonAttrs(mainSchema *Schema) {
	schemasAttr := newAttrType()
	schemasAttr.Name = "schemas"
	schemasAttr.Required = true
	schemasAttr.Returned = "always"
	schemasAttr.MultiValued = true
	schemasAttr.Mutability = "readonly"
	schemasAttr.SchemaId = mainSchema.Id
	mainSchema.Attributes = append(mainSchema.Attributes, schemasAttr)
	mainSchema.AttrMap[schemasAttr.Name] = schemasAttr

	// id
	idAttr := newAttrType()
	idAttr.Name = "id"
	idAttr.Returned = "always"
	idAttr.CaseExact = true
	idAttr.MultiValued = false
	idAttr.Mutability = "readonly"
	idAttr.SchemaId = mainSchema.Id
	mainSchema.Attributes = append(mainSchema.Attributes, idAttr)
	mainSchema.AttrMap[idAttr.Name] = idAttr

	// externalId
	externalIdAttr := newAttrType()
	externalIdAttr.Name = "externalId"
	externalIdAttr.CaseExact = true
	externalIdAttr.SchemaId = mainSchema.Id
	mainSchema.Attributes = append(mainSchema.Attributes, externalIdAttr)
	mainSchema.AttrMap[strings.ToLower(externalIdAttr.Name)] = externalIdAttr

	// meta
	metaAttr := newAttrType()
	metaAttr.Name = "meta"
	metaAttr.Type = "complex"
	metaAttr.Returned = "default"
	metaAttr.CaseExact = false
	metaAttr.MultiValued = false
	metaAttr.Mutability = "readonly"
	metaAttr.SchemaId = mainSchema.Id
	mainSchema.Attributes = append(mainSchema.Attributes, metaAttr)
	mainSchema.AttrMap[metaAttr.Name] = metaAttr

	metaAttr.SubAttrMap = make(map[string]*AttrType)

	// meta.resourceType
	metaResTypeAttr := newAttrType()
	metaResTypeAttr.Name = "resourceType"
	metaResTypeAttr.CaseExact = true
	metaResTypeAttr.Mutability = "readonly"
	metaResTypeAttr.SchemaId = mainSchema.Id
	metaResTypeAttr.parent = metaAttr
	metaAttr.SubAttrMap[strings.ToLower(metaResTypeAttr.Name)] = metaResTypeAttr

	// meta.created
	metaCreatedAttr := newAttrType()
	metaCreatedAttr.Name = "created"
	metaCreatedAttr.Type = "datetime"
	metaCreatedAttr.Mutability = "readonly"
	metaCreatedAttr.SchemaId = mainSchema.Id
	metaCreatedAttr.parent = metaAttr
	metaAttr.SubAttrMap[strings.ToLower(metaCreatedAttr.Name)] = metaCreatedAttr

	// meta.lastModified
	metaLastModAttr := newAttrType()
	metaLastModAttr.Name = "lastModified"
	metaLastModAttr.Type = "datetime"
	metaLastModAttr.Mutability = "readonly"
	metaLastModAttr.SchemaId = mainSchema.Id
	metaLastModAttr.parent = metaAttr
	metaAttr.SubAttrMap[strings.ToLower(metaLastModAttr.Name)] = metaLastModAttr

	// meta.location
	metaLocAttr := newAttrType()
	metaLocAttr.Name = "location"
	metaLocAttr.Mutability = "readonly"
	metaLocAttr.SchemaId = mainSchema.Id
	metaLocAttr.parent = metaAttr
	metaAttr.SubAttrMap[strings.ToLower(metaLocAttr.Name)] = metaLocAttr

	// meta.version
	metaVerAttr := newAttrType()
	metaVerAttr.Name = "version"
	metaVerAttr.CaseExact = true
	metaVerAttr.Mutability = "readonly"
	metaVerAttr.SchemaId = mainSchema.Id
	metaVerAttr.parent = metaAttr
	metaAttr.SubAttrMap[strings.ToLower(metaVerAttr.Name)] = metaVerAttr
}

// Returns the main schema of the given resourcetype
func (rt *ResourceType) GetMainSchema() *Schema {
	return rt.GetSchema(rt.Schema)
}

// Returns the schema identified by the URN associated with the given resourcetype
func (rt *ResourceType) GetSchema(urnId string) *Schema {
	return rt.schemas[urnId]
}

func (rt *ResourceType) GetAtType(atPath string) *AttrType {
	for _, sc := range rt.schemas {
		at := sc.GetAtType(atPath)
		if at != nil {
			return at
		}
	}

	return nil
}

// Copyright 2017 Keydap. All rights reserved.
// Use of this source code is governed by a Apache
// license that can be found in the LICENSE file.

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

	schemas       map[string]*Schema // map containing the main and extension schemas
	Text          string             // the JSON representation of this resource type
	UniqueAts     []string           // a collection of all unique attributes
	AtsNeverRtn   map[string]int     // names of attributes that are never returned
	AtsAlwaysRtn  map[string]int     // names of attributes that are always returned
	AtsRequestRtn map[string]int     // names of attributes that are returned if requested
	AtsDefaultRtn map[string]int     // names of attributes that are returned by default
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
	rt.AtsRequestRtn = make(map[string]int)
	rt.AtsDefaultRtn = make(map[string]int)

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

	for _, v := range sc.AtsRequestRtn {
		rt.AtsRequestRtn[v] = 1
	}

	for _, v := range sc.AtsDefaultRtn {
		rt.AtsDefaultRtn[v] = 1
	}
}

func addCommonAttrs(mainSchema *Schema) {
	schemasAttr := newAttrType()
	schemasAttr.Name = "schemas"
	schemasAttr.NormName = schemasAttr.Name
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
	idAttr.NormName = idAttr.Name
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
	externalIdAttr.NormName = strings.ToLower(externalIdAttr.Name)
	externalIdAttr.CaseExact = true
	externalIdAttr.SchemaId = mainSchema.Id
	mainSchema.Attributes = append(mainSchema.Attributes, externalIdAttr)
	mainSchema.AttrMap[strings.ToLower(externalIdAttr.Name)] = externalIdAttr

	// meta
	metaAttr := newAttrType()
	metaAttr.Name = "meta"
	metaAttr.NormName = metaAttr.Name
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
	metaResTypeAttr.NormName = strings.ToLower(metaResTypeAttr.Name)
	metaResTypeAttr.CaseExact = true
	metaResTypeAttr.Mutability = "readonly"
	metaResTypeAttr.SchemaId = mainSchema.Id
	metaResTypeAttr.parent = metaAttr
	metaAttr.SubAttrMap[strings.ToLower(metaResTypeAttr.Name)] = metaResTypeAttr

	// meta.created
	metaCreatedAttr := newAttrType()
	metaCreatedAttr.Name = "created"
	metaCreatedAttr.NormName = metaCreatedAttr.Name
	metaCreatedAttr.Type = "datetime"
	metaCreatedAttr.Mutability = "readonly"
	metaCreatedAttr.SchemaId = mainSchema.Id
	metaCreatedAttr.parent = metaAttr
	metaAttr.SubAttrMap[strings.ToLower(metaCreatedAttr.Name)] = metaCreatedAttr

	// meta.lastModified
	metaLastModAttr := newAttrType()
	metaLastModAttr.Name = "lastModified"
	metaLastModAttr.NormName = strings.ToLower(metaLastModAttr.Name)
	metaLastModAttr.Type = "datetime"
	metaLastModAttr.Mutability = "readonly"
	metaLastModAttr.SchemaId = mainSchema.Id
	metaLastModAttr.parent = metaAttr
	metaAttr.SubAttrMap[strings.ToLower(metaLastModAttr.Name)] = metaLastModAttr

	// meta.location
	metaLocAttr := newAttrType()
	metaLocAttr.Name = "location"
	metaLocAttr.NormName = metaLocAttr.Name
	metaLocAttr.Mutability = "readonly"
	metaLocAttr.SchemaId = mainSchema.Id
	metaLocAttr.parent = metaAttr
	metaAttr.SubAttrMap[strings.ToLower(metaLocAttr.Name)] = metaLocAttr

	// meta.version
	metaVerAttr := newAttrType()
	metaVerAttr.Name = "version"
	metaVerAttr.NormName = metaVerAttr.Name
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
	colonPos := strings.LastIndex(atPath, ":")

	var uri string
	uriLen := 0
	if colonPos > 0 {
		uri = atPath[0:colonPos]
		colonPos++
		uriLen = len(uri)
	}

	for id, sc := range rt.schemas {
		if uriLen != 0 {
			if id == uri {
				return sc.GetAtType(atPath[colonPos:])
			}
		} else { // when  no schema ID is prefixed search all schemas associated with the ResourceType
			// this is helpful in shorter attribute paths when the attribute names are unique
			at := sc.GetAtType(atPath)
			if at != nil {
				return at
			}
		}
	}

	return nil
}

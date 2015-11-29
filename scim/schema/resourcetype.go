package schema

import (
	"log"
	"encoding/json"
	"io/ioutil"
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

	MainSchema *Schema
	Extensions map[string]*Schema
}

func LoadResourceType(name string, sm map[string]*Schema) (*ResourceType, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	
	log.Println("Loading resourcetype from file " + name)
	return NewResourceType(data, sm)
}

func NewResourceType(data []byte, sm map[string]*Schema) (*ResourceType, error) {
	//rt := &ResourceType{}
var rt ResourceType
	err := json.Unmarshal(data, &rt)

	if err != nil {
		return nil, err
	}

	ve := &ValidationErrors{}

	rt.Name = strings.TrimSpace(rt.Name)
	if len(rt.Name) == 0 {
		ve.add("Name attribute of the resourcetype cannot be empty")
	}

	rt.Endpoint = strings.TrimSpace(rt.Endpoint)
	if len(rt.Endpoint) == 0 {
		ve.add("Endpoint attribute of the resourcetype cannot be empty")
	}

	rt.Schema = strings.TrimSpace(rt.Schema)
	if len(rt.Schema) == 0 {
		ve.add("Schema attribute of the resourcetype cannot be empty")
	} else	if sm[rt.Schema] == nil {
		ve.add("No Schema found associated with the URN " + rt.Schema)
	} else {
		rt.MainSchema = sm[rt.Schema]
		log.Println("setting main schema on resourcetype %s \n %#v", rt.Name, rt.MainSchema.AttrMap)
	}

	if len(rt.SchemaExtensions) != 0 {
		rt.Extensions = make(map[string]*Schema)
		
		for _, ext := range rt.SchemaExtensions {
			ext.Schema = strings.TrimSpace(ext.Schema)
			if len(ext.Schema) == 0 {
				ve.add("Schema attribute of the resourcetype's extension cannot be empty")
			} else if sm[ext.Schema] == nil {
				ve.add("No Schema found associated with the extension schema URN " + ext.Schema)
			} else {
				rt.Extensions[ext.Schema] = sm[ext.Schema]
			}
		}
	}

	if ve.Count > 0 {
		return nil, ve
	}

	return &rt, nil
}

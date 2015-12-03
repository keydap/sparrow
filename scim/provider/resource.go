package provider

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sparrow/scim/schema"
	"strings"
)

type Attribute struct {
}

type SimpleAttribute struct {
	AtType *schema.AttrType
	Name   string
	Values []string
}

type MultiSubAttribute struct {
	SimpleAts []*SimpleAttribute
}

type ComplexAttribute struct {
	AtType *schema.AttrType
	Name   string
	SubAts     [][]*SimpleAttribute // it can hold a list of simple sub attributes
	//	Ma     []*MultiSubAttribute  // or a list of multi-valued simple sub attributes
}

type AtGroup struct {
	SimpleAts  map[string]*SimpleAttribute
	ComplexAts map[string]*ComplexAttribute
}

type Resource struct {
	ResType *schema.ResourceType
	Core    *AtGroup
	Ext     map[string]*AtGroup
}

func newAtGroup() *AtGroup {
	return &AtGroup{SimpleAts: make(map[string]*SimpleAttribute), ComplexAts: make(map[string]*ComplexAttribute)}
}

func (rs *Resource) addSimpleAt(sa *SimpleAttribute) {
	scId := sa.AtType.SchemaId
	if scId == rs.ResType.Schema {
		rs.Core.SimpleAts[sa.Name] = sa
		return
	}

	atg := rs.Ext[scId]
	if atg == nil {
		atg = newAtGroup()
		rs.Ext[scId] = atg
	}

	atg.SimpleAts[sa.Name] = sa
}

func (rs *Resource) addComplexAt(ca *ComplexAttribute) {
	scId := ca.AtType.SchemaId
	if scId == rs.ResType.Schema {
		rs.Core.ComplexAts[ca.Name] = ca
		return
	}

	atg := rs.Ext[scId]
	if atg == nil {
		atg = newAtGroup()
		rs.Ext[scId] = atg
	}

	atg.ComplexAts[ca.Name] = ca
}

func ParseResource(rt *schema.ResourceType, sm map[string]*schema.Schema, jsonData string) (*Resource, error) {
	if sm == nil {
		err := NewError()
		err.Detail = "Schema cannot be null"
		return nil, err
	}

	if rt == nil {
		err := NewError()
		err.Detail = "ResourceType cannot be null"
		return nil, err
	}

	if len(jsonData) == 0 {
		return nil, NewBadRequestError("Invalid JSON data")
	}

	var i interface{}
	err := json.Unmarshal([]byte(jsonData), &i)

	if err != nil {
		fmt.Printf("%#v", err)
		return nil, NewBadRequestError(err.Error())
	}

	if reflect.TypeOf(i).Kind() != reflect.Map {
		return nil, NewBadRequestError("Invalid JSON data")
	}

	obj := i.(map[string]interface{})

	log.Println("converting to resource")
	return toResource(rt, sm, obj)
}

func toResource(rt *schema.ResourceType, sm map[string]*schema.Schema, obj map[string]interface{}) (*Resource, error) {

	rs := &Resource{}
	rs.ResType = rt
	rs.Core = newAtGroup()
	rs.Ext = make(map[string]*AtGroup)

	defer func() (*Resource, error) {
		err := recover()
		if err != nil {
			fmt.Printf("panicking %#v\n", err)
			return nil, err.(error)
		}

		return nil, nil
	}()

	/*
		rs.Id = extrString("id", obj, false)
		delete(obj, "id")

		rs.ExternalId = extrString("externalId", obj, false)
		delete(obj, "id")

		rs.Schemas = extrStringArr("schemas", obj, true)
		delete(obj, "schemas")

		iSchemas := obj["schemas"]
		rs.Schemas = parseSimpleAttr("schemas", schema.SchemasAttr, iSchemas).Values
		delete(obj, "schemas")

		for _, val := range rs.Schemas {

		}
	*/
	//mainSchema :=
	//resSc := obj["schemas"]

	//	if len(resSc) == 0 {
	//
	//	}

	parseJsonObject(obj, rt.MainSchema, rs, sm)
	return rs, nil
}

func parseJsonObject(obj map[string]interface{}, sc *schema.Schema, rs *Resource, sm map[string]*schema.Schema) {
	//log.Println("resource schema %#v", sc.AttrMap["username"])
	for k, v := range obj {

		// see if the key is the ID of an extended schema
		if strings.ContainsRune(k, ':') {
			log.Printf("Parsing data of extended schema %s\n", k)
			extSc := sm[k]
			if extSc == nil {
				msg := fmt.Sprintf("No schema found with the ID %s", k)
				panic(NewBadRequestError(msg))
			}

			if rs.ResType.Extensions[k] == nil {
				msg := fmt.Sprintf("Schema %s is not declared in the extension schemas of resourcetype %s", k, rs.ResType.Name)
				panic(NewBadRequestError(msg))
			}

			var vObj map[string]interface{}
			switch v.(type) {
			case map[string]interface{}:
				vObj = v.(map[string]interface{})
			default:
				msg := fmt.Sprintf("Invalid value of key %s", k)
				panic(NewBadRequestError(msg))
			}

			parseJsonObject(vObj, extSc, rs, sm)
			continue
		}

		atName := strings.ToLower(k)
		atType := sc.AttrMap[atName]

		if atType == nil {
			msg := fmt.Sprintf("Attribute %s doesn't exist in the schema %s", atName, sc.Id)
			panic(NewBadRequestError(msg))
		} else {
			log.Printf("found atType %s\n", atType.Name)
		}

		if atType.IsSimple() {
			sa := parseSimpleAttr(atType, v)
			rs.addSimpleAt(sa)
		} else if atType.IsComplex() {
			ca := parseComplexAttr(atType, v)
			rs.addComplexAt(ca)
		}
	}
}

func parseSimpleAttr(attrType *schema.AttrType, iVal interface{}) *SimpleAttribute {
	rv := reflect.ValueOf(iVal)

	sa := &SimpleAttribute{}
	sa.Name = attrType.Name
	sa.AtType = attrType

	if attrType.MultiValued {
		//fmt.Println("rv kind ", rv.Kind())
		if (rv.Kind() != reflect.Slice) && (rv.Kind() != reflect.Array) {
			msg := fmt.Sprintf("Value of the attribute %s must be an array", attrType.Name)
			panic(NewBadRequestError(msg))
		}

		arr := make([]string, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			// make sure the values are all primitives
			v := rv.Index(i)
			//fmt.Println("v kind ", v.Kind())
			if !isPrimitive(v.Kind()) {
				msg := fmt.Sprintf("Invalid value '%#v' in attribute %s", v, attrType.Name)
				panic(NewBadRequestError(msg))
			}

			strVal := fmt.Sprint(v)
			arr = append(arr, strVal)
		}

		sa.Values = arr

		return sa
	}
	
	arr := make([]string, 1)
	arr = append(arr, fmt.Sprint(rv))
	sa.Values = arr

	return sa
}

func parseComplexAttr(attrType *schema.AttrType, iVal interface{}) *ComplexAttribute {
	rv := reflect.ValueOf(iVal)

	ca := &ComplexAttribute{}
	ca.Name = attrType.Name
	ca.AtType = attrType

	if attrType.MultiValued {
		if (rv.Kind() != reflect.Slice) && (rv.Kind() != reflect.Array) {
			msg := fmt.Sprintf("Value of the attribute %s must be an array", attrType.Name)
			panic(NewBadRequestError(msg))
		}

		subAtArr := make([][]*SimpleAttribute, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			v := rv.Index(i)
			simpleAtArr := parseSubAtList(v.Interface(), attrType)
			subAtArr = append(subAtArr, simpleAtArr)
		}

		ca.SubAts = subAtArr

		return ca
	}

	subAtArr := make([][]*SimpleAttribute, 1)
	simpleAtArr := parseSubAtList(iVal, attrType)
	subAtArr = append(subAtArr, simpleAtArr)
	ca.SubAts = subAtArr

	return ca
}

func parseSubAtList(v interface{}, attrType *schema.AttrType) []*SimpleAttribute {
	var vObj map[string]interface{}

	switch v.(type) {
	case map[string]interface{}:
		vObj = v.(map[string]interface{})
	default:
		msg := fmt.Sprintf("Invalid value %#v , expected a JSON object", v)
		panic(NewBadRequestError(msg))
	}

	arr := make([]*SimpleAttribute, len(vObj))

	for k, v := range vObj {
		subAtName := strings.ToLower(k)
		subAtType := attrType.SubAttrMap[subAtName]

		if subAtType == nil {
			msg := fmt.Sprintf("sub-Attribute %s.%s doesn't exist in the schema %s", attrType.Name, subAtName, attrType.SchemaId)
			panic(NewBadRequestError(msg))
		} else {
			log.Printf("found sub-atType %s.%s\n", attrType.Name, subAtName)
		}

		subAt := parseSimpleAttr(subAtType, v)
		arr = append(arr, subAt)
	}

	return arr
}

func isPrimitive(knd reflect.Kind) bool {
	return (knd != reflect.Array && knd != reflect.Map && knd != reflect.Slice)
}

func extrString(name string, obj map[string]interface{}, mandatory bool) string {
	val := obj[name]

	if reflect.TypeOf(val).Kind() != reflect.String {
		panic(NewBadRequestError("Invalid value given for attribute '" + name + "'"))
	}

	str := val.(string)
	if (len(str) == 0) && mandatory {
		panic(NewBadRequestError("Missing value for mandatory attribute '" + name + "'"))
	}

	return str
}

func extrStringArr(name string, obj map[string]interface{}, mandatory bool) []string {
	iStrArr := obj[name]
	rv := reflect.ValueOf(iStrArr)

	if (rv.Kind() != reflect.Slice) || (rv.Kind() != reflect.Array) {
		panic(NewBadRequestError("Invalid value given for attribute 'schemas' it must be an array"))
	}

	arr := make([]string, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		v := rv.Index(i)
		if v.Kind() != reflect.String {
			panic(NewBadRequestError("Invalid schema URI given in attribute 'schemas'"))
		}

		arr = append(arr, v.String())
	}

	return arr
}

func normalizeKeys() {

}

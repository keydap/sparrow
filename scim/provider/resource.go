package provider

import (
	"log"
	"encoding/json"
	"fmt"
	"reflect"
	"sparrow/scim/schema"
	"strings"
)

type Attribute struct {
}

type SimpleAttribute struct {
	Name   string
	Value  string
	Values []string
}

type MultiAttribute struct {
	Sa []*SimpleAttribute
}

type ComplexAttribute struct {
	Name string
	Sa   []*SimpleAttribute // it can hold a list of single-valued attributes
	Ma   []*MultiAttribute  // or a list of multi-valued attributes
}

type Resource struct {
	Schemas     []string
	SimpleAtrs  map[string]*SimpleAttribute
	ComplexAtrs map[string]*ComplexAttribute
}

func (rs *Resource) addSimpleAt(sa *SimpleAttribute) {
	if rs.SimpleAtrs == nil {
		rs.SimpleAtrs = make(map[string]*SimpleAttribute)
	}

	rs.SimpleAtrs[sa.Name] = sa
}

func (rs *Resource) addComplexAt(ca *ComplexAttribute) {
	if rs.ComplexAtrs == nil {
		rs.ComplexAtrs = make(map[string]*ComplexAttribute)
	}

	rs.ComplexAtrs[ca.Name] = ca
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

	parseJsonObject(obj, rt.MainSchema, rs)
	return rs, nil
}

func parseJsonObject(obj map[string]interface{}, sc *schema.Schema, rs *Resource) {
	//log.Println("resource schema %#v", sc.AttrMap["username"])
	for k, v := range obj {
		atName := strings.ToLower(k)
		atType := sc.AttrMap[atName]
		log.Println("found atType %#v", atType)

		if atType == nil {
			msg := fmt.Sprintf("Attribute %s doesn't exist in the schema %s", atName, sc.Id)
			panic(NewBadRequestError(msg))
		}

		if atType.IsSimple() {
			sa := parseSimpleAttr(atType, v)
			rs.addSimpleAt(sa)
		}
	}
}

func parseSimpleAttr(attrType *schema.AttrType, iVal interface{}) *SimpleAttribute {
	rv := reflect.ValueOf(iVal)

	sa := &SimpleAttribute{}
	sa.Name = attrType.Name

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

	sa.Value = fmt.Sprint(rv)

	return sa
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

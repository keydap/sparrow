package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sparrow/scim/schema"
	"strconv"
	"strings"
)

type Attribute struct {
}

type SimpleAttribute struct {
	atType *schema.AttrType
	Name   string
	Values []string
}

type MultiSubAttribute struct {
	SimpleAts []*SimpleAttribute
}

type ComplexAttribute struct {
	atType *schema.AttrType
	Name   string
	SubAts [][]*SimpleAttribute // it can hold a list of simple sub attributes
}

type AtGroup struct {
	SimpleAts  map[string]*SimpleAttribute
	ComplexAts map[string]*ComplexAttribute
}

type Resource struct {
	resType  *schema.ResourceType
	TypeName string // resourcetype's name
	Core     *AtGroup
	Ext      map[string]*AtGroup
}

func newAtGroup() *AtGroup {
	return &AtGroup{SimpleAts: make(map[string]*SimpleAttribute), ComplexAts: make(map[string]*ComplexAttribute)}
}

func (rs *Resource) addSimpleAt(sa *SimpleAttribute) {
	scId := sa.atType.SchemaId
	if scId == rs.resType.Schema {
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
	scId := ca.atType.SchemaId
	if scId == rs.resType.Schema {
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

func (rs *Resource) SetSchema(rt *schema.ResourceType) {
	if rt == nil {
		panic("ResourceType cannot be null")
	}

	if rt.Name != rs.TypeName {
		panic("Name of ResourceType and Resource are not same")
	}

	rs.resType = rt
	if rs.Core != nil {
		rs.Core.setSchema(rt.GetMainSchema())
	}

	if len(rs.Ext) > 0 {
		for k, v := range rs.Ext {
			extSc := rt.GetSchema(k)
			v.setSchema(extSc)
		}
	}
}

func (atg *AtGroup) setSchema(sc *schema.Schema) {
	if len(atg.SimpleAts) > 0 {
		for k, v := range atg.SimpleAts {
			atType := sc.AttrMap[strings.ToLower(k)]
			v.atType = atType
		}
	}

	if len(atg.ComplexAts) > 0 {
		for k, v := range atg.ComplexAts {
			parentType := sc.AttrMap[strings.ToLower(k)]
			v.atType = parentType
			for _, saArr := range v.SubAts {
				for _, sa := range saArr {
					subType := parentType.SubAttrMap[strings.ToLower(sa.Name)]
					sa.atType = subType
				}
			}
		}
	}
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
		log.Debugf("%#v", err)
		return nil, NewBadRequestError(err.Error())
	}

	if reflect.TypeOf(i).Kind() != reflect.Map {
		return nil, NewBadRequestError("Invalid JSON data")
	}

	obj := i.(map[string]interface{})

	log.Debugf("converting to resource")
	return toResource(rt, sm, obj)
}

func toResource(rt *schema.ResourceType, sm map[string]*schema.Schema, obj map[string]interface{}) (rs *Resource, err error) {

	rs = &Resource{}
	rs.resType = rt
	rs.TypeName = rt.Name
	rs.Core = newAtGroup()
	rs.Ext = make(map[string]*AtGroup)

	defer func() {
		err := recover()
		if err != nil {
			log.Debugf("panicking %#v\n", err)
			rs = nil
		}
	}()

	sc := rt.GetMainSchema()
	parseJsonObject(obj, rt, sc, rs)
	return rs, nil
}

func parseJsonObject(obj map[string]interface{}, rt *schema.ResourceType, sc *schema.Schema, rs *Resource) {
	//log.Debugf("resource schema %#v", sc.AttrMap["username"])
	if sc == nil {
		msg := fmt.Sprintf("Schema of resourcetype %s cannot be null", rs.TypeName)
		panic(NewBadRequestError(msg))
	}

	for k, v := range obj {

		// see if the key is the ID of an extended schema
		if strings.ContainsRune(k, ':') {
			log.Debugf("Parsing data of extended schema %s\n", k)

			extSc := rs.resType.GetSchema(k)
			if extSc == nil {
				msg := fmt.Sprintf("Schema %s is not declared in the extension schemas of resourcetype %s", k, rs.TypeName)
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

			parseJsonObject(vObj, rt, extSc, rs)
			continue
		}

		atName := strings.ToLower(k)
		atType := sc.AttrMap[atName]

		if atType == nil {
			msg := fmt.Sprintf("Attribute %s doesn't exist in the schema %s", atName, sc.Id)
			panic(NewBadRequestError(msg))
		} else {
			log.Debugf("found atType %s\n", atType.Name)
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
	sa.atType = attrType

	log.Debugf("Parsing simple attribute %s\n", sa.Name)
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

			strVal := checkValueTypeAndConvert(v, attrType)
			arr[i] = strVal
		}

		sa.Values = arr

		return sa
	}

	strVal := checkValueTypeAndConvert(rv, attrType)
	sa.Values = []string{strVal}
	return sa
}

func checkValueTypeAndConvert(v reflect.Value, attrType *schema.AttrType) string {
	msg := fmt.Sprintf("Invalid value '%#v' in attribute %s", v, attrType.Name)
	err := NewBadRequestError(msg)

	kind := v.Kind()

	switch attrType.Type {
	case "boolean":
		if kind != reflect.Bool {
			panic(err)
		}
		return strconv.FormatBool(v.Bool())
	case "integer":
		if kind != reflect.Int {
			panic(err)
		}
		return string(v.Int())
	case "decimal":
		if kind != reflect.Float64 {
			panic(err)
		}
		return strconv.FormatFloat(v.Float(), 'E', -1, 64)
	case "string", "datetime", "binary", "reference":
		if kind != reflect.String && kind != reflect.Interface {
			panic(err)
		}

		if kind == reflect.Interface {
			return fmt.Sprint(v.Interface())
		}

		return v.String()
	default:
		panic(err)
	}

	panic(err)
}

func parseComplexAttr(attrType *schema.AttrType, iVal interface{}) *ComplexAttribute {
	rv := reflect.ValueOf(iVal)

	ca := &ComplexAttribute{}
	ca.Name = attrType.Name
	ca.atType = attrType

	if attrType.MultiValued {
		if (rv.Kind() != reflect.Slice) && (rv.Kind() != reflect.Array) {
			msg := fmt.Sprintf("Value of the attribute %s must be an array", attrType.Name)
			panic(NewBadRequestError(msg))
		}

		subAtArr := make([][]*SimpleAttribute, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			v := rv.Index(i)
			simpleAtArr := parseSubAtList(v.Interface(), attrType)
			subAtArr[i] = simpleAtArr
		}

		ca.SubAts = subAtArr

		return ca
	}

	simpleAtArr := parseSubAtList(iVal, attrType)
	ca.SubAts = [][]*SimpleAttribute{simpleAtArr}

	return ca
}

func parseSubAtList(v interface{}, attrType *schema.AttrType) []*SimpleAttribute {
	var vObj map[string]interface{}

	switch v.(type) {
	case map[string]interface{}:
		vObj = v.(map[string]interface{})
	default:
		msg := fmt.Sprintf("Invalid sub-attribute value %#v , expected a JSON object", v)
		panic(NewBadRequestError(msg))
	}

	arr := make([]*SimpleAttribute, len(vObj))
	count := 0
	for k, v := range vObj {
		subAtName := strings.ToLower(k)
		subAtType := attrType.SubAttrMap[subAtName]

		if subAtType == nil {
			msg := fmt.Sprintf("sub-Attribute %s.%s doesn't exist in the schema %s", attrType.Name, subAtName, attrType.SchemaId)
			panic(NewBadRequestError(msg))
		} else {
			log.Debugf("found sub-atType %s.%s\n", attrType.Name, subAtName)
		}

		subAt := parseSimpleAttr(subAtType, v)
		arr[count] = subAt
		count++
	}

	return arr
}

func isPrimitive(knd reflect.Kind) bool {
	return (knd != reflect.Array && knd != reflect.Map && knd != reflect.Slice)
}

func (sa *SimpleAttribute) valToInterface() interface{} {

	if sa.Values == nil {
		return nil
	}

	if sa.atType.MultiValued {
		count := len(sa.Values)
		var arr []interface{}
		arr = make([]interface{}, count)
		for i, v := range sa.Values {
			log.Debugf("reading value %#v of AT %s\n", v, sa.Name)
			arr[i] = getConvertedVal(v, sa)
		}

		return arr
	}

	return getConvertedVal(sa.Values[0], sa)
}

func (ca *ComplexAttribute) valToInterface() interface{} {
	if ca.SubAts == nil {
		return nil
	}

	if ca.atType.MultiValued {
		arr := make([]map[string]interface{}, len(ca.SubAts))
		for i, v := range ca.SubAts {
			log.Debugf("reading sub attributes of AT %s\n", ca.Name)
			arr[i] = simpleATArrayToMap(v)
		}

		return arr
	}

	return simpleATArrayToMap(ca.SubAts[0])
}

func simpleATArrayToMap(sas []*SimpleAttribute) map[string]interface{} {
	obj := make(map[string]interface{})
	for _, v := range sas {
		obj[v.Name] = v.valToInterface()
	}

	return obj
}

func (atg *AtGroup) ToMap() map[string]interface{} {
	obj := make(map[string]interface{})

	if len(atg.SimpleAts) > 0 {
		for _, v := range atg.SimpleAts {
			i := v.valToInterface()
			if i != nil {
				obj[v.Name] = i
			}
		}
	}

	if len(atg.ComplexAts) > 0 {
		for _, v := range atg.ComplexAts {
			i := v.valToInterface()
			if i != nil {
				obj[v.Name] = i
			}
		}
	}

	return obj
}

func getConvertedVal(v string, sa *SimpleAttribute) interface{} {
	switch sa.atType.Type {
	case "boolean":
		cv, _ := strconv.ParseBool(v)
		return cv
	case "decimal":
		cv, _ := strconv.ParseFloat(v, 64)
		return cv
	case "integer":
		cv, _ := strconv.ParseInt(v, 10, 64)
		return cv
	default:
		return v
	}
}

func (rs *Resource) ToJSON() (string, error) {
	if rs == nil {
		return "", errors.New("nil-resource")
	}

	if rs.Core == nil {
		return "", errors.New("invalid resource, no attributes")
	}

	obj := rs.Core.ToMap()

	if len(rs.Ext) > 0 {
		for k, v := range rs.Ext {
			extObj := v.ToMap()
			obj[k] = extObj
		}
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

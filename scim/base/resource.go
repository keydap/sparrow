package base

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sparrow/scim/schema"
	"sparrow/scim/utils"
	"strconv"
	"strings"
	"time"
)

const URI_DELIM = ":"

const ATTR_DELIM = "."

type Attribute interface {
	IsSimple() bool
	GetSimpleAt() *SimpleAttribute
	GetComplexAt() *ComplexAttribute
	GetType() *schema.AttrType
}

// Name will always be stored in lowercase in all Attributes, to get the
// original user provided name, refer to the Name field of AttrType
type SimpleAttribute struct {
	atType *schema.AttrType
	Name   string
	Values []interface{}
}

type MultiSubAttribute struct {
	SimpleAts []*SimpleAttribute
}

type ComplexAttribute struct {
	atType *schema.AttrType
	Name   string
	SubAts []map[string]*SimpleAttribute // it can hold a list of simple sub attributes
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

type postParsingHints struct {
	updateSchemas bool
}

// Attribute contract

func (sa *SimpleAttribute) IsSimple() bool {
	return true
}

func (sa *SimpleAttribute) GetType() *schema.AttrType {
	return sa.atType
}

func (sa *SimpleAttribute) GetSimpleAt() *SimpleAttribute {
	return sa
}

func (sa *SimpleAttribute) GetComplexAt() *ComplexAttribute {
	panic("Not a complex attribute")
}

func (ca *ComplexAttribute) IsSimple() bool {
	return false
}

func (ca *ComplexAttribute) GetType() *schema.AttrType {
	return ca.atType
}

func (ca *ComplexAttribute) GetSimpleAt() *SimpleAttribute {
	panic("Not a simple attribute")
}

func (ca *ComplexAttribute) GetComplexAt() *ComplexAttribute {
	return ca
}

func (ca *ComplexAttribute) AddSubAts(subAtMap map[string]interface{}) {
	subAt, _ := parseSubAtList(subAtMap, ca.atType)
	if ca.SubAts == nil {
		ca.SubAts = make([]map[string]*SimpleAttribute, 1)
	}

	if ca.atType.MultiValued {
		ca.SubAts[len(ca.SubAts)-1] = subAt
	} else {
		ca.SubAts[0] = subAt
	}
}

func (ca *ComplexAttribute) GetValue(subAtName string) interface{} {
	if len(ca.SubAts) == 0 {
		return nil
	}

	atMap := ca.SubAts[0]
	subAtName = strings.ToLower(subAtName)
	sa := atMap[subAtName]
	if sa != nil {
		return sa.Values[0]
	}

	return nil
}

func (atg *AtGroup) getAttribute(name string) Attribute {
	var at Attribute
	if atg.SimpleAts != nil {
		// the interface will always be non-nil even if the
		// key is not present
		// so do not call
		// at = atg.SimpleAts[name] -- this will result in a non-nil value even if the key doesn't exist
		if v, ok := atg.SimpleAts[name]; ok {
			at = v
		}
	}

	if (at == nil) && (atg.ComplexAts != nil) {
		log.Debugf("searching complex ats for %s", name)
		if v, ok := atg.ComplexAts[name]; ok {
			at = v
		}
	}

	return at
}

func (rs *Resource) DeleteAttr(attrPath string) bool {
	log.Debugf("deleting attribute %s", attrPath)
	pos := strings.LastIndex(attrPath, URI_DELIM)
	if pos > 0 {
		var atg *AtGroup
		uri := attrPath[:pos]                        // URI is case sensitive
		attrPath = strings.ToLower(attrPath[pos+1:]) // attribute is not

		if rs.Ext != nil {
			atg = rs.Ext[uri]
		}

		if atg == nil {
			// select Core only if the URI matches the main schema
			if uri == rs.resType.Schema {
				atg = rs.Core
			} else {
				log.Warningf("Unknown URI prefix given in the attribute %s", attrPath)
				return false
			}
		}

		return rs.deleteAttribute(attrPath, atg)
	}

	attrPath = strings.ToLower(attrPath) // here no URI exists, can be converted to lowercase
	return rs.deleteAttribute(attrPath, rs.Core)
}

func (rs *Resource) deleteAttribute(attrPath string, atg *AtGroup) bool {
	pos := strings.LastIndex(attrPath, ATTR_DELIM)
	//handle the attributes with . char
	if pos > 0 {
		parent := attrPath[:pos]
		at := atg.getAttribute(parent)
		if at != nil {
			ct := at.GetComplexAt()
			childName := attrPath[pos+1:]
			deleted := false

			nilAtMapCount := 0
			for i, atMap := range ct.SubAts {
				if _, ok := atMap[childName]; ok {
					deleted = true
				}

				delete(atMap, childName)

				// resize the SubAts slice if the sub-attribute object is empty
				if len(atMap) == 0 {
					ct.SubAts[i] = nil
					nilAtMapCount++
				}
			}

			if nilAtMapCount > 0 {
				remaining := len(ct.SubAts) - nilAtMapCount

				if remaining == 0 {
					ct.SubAts = nil
				} else {
					tmp := make([]map[string]*SimpleAttribute, remaining)
					count := 0
					for _, atMap := range ct.SubAts {
						if atMap != nil {
							tmp[count] = atMap
							count++
						}
					}

					ct.SubAts = tmp
				}
			}

			// delete the entire attribute if there are no sub-attributes present
			if len(ct.SubAts) == 0 {
				// check whether this is core or extended
				if ct.atType.SchemaId == rs.resType.Schema {
					delete(rs.Core.ComplexAts, ct.Name)
				} else {
					delete(rs.Ext[ct.atType.SchemaId].ComplexAts, ct.Name)
				}
			}

			return deleted
		}

		return false
	} else {
		if _, ok := atg.SimpleAts[attrPath]; ok {
			delete(atg.SimpleAts, attrPath)
			return true
		} else {
			if _, ok := atg.ComplexAts[attrPath]; ok {
				log.Debugf("deleting complex ats for %s", attrPath)
				delete(atg.ComplexAts, attrPath)
				return true
			}
		}
	}

	return false
}

// accessor methods for common attributes
/*
func (rs *Resource) GetSchemaIds() []string {
	sa := rs.Core.SimpleAts["schemas"]
	return sa.Values.([]string)
//	if rs.schemaIds == nil {
//		rs.schemaIds = make([]string, 1)
//		rs.schemaIds[0] = rs.resType.Schema
//		for _, v := range rs.resType.SchemaExtensions {
//			rs.schemaIds = append(rs.schemaIds, v.Schema)
//		}
//	}
//
//	return rs.schemaIds
}*/

func (rs *Resource) GetId() string {
	sa := rs.Core.SimpleAts["id"]
	if sa == nil {
		return ""
	}

	return sa.Values[0].(string)
}

func (rs *Resource) SetId(id string) {
	sa := rs.Core.SimpleAts["id"]
	if sa != nil {
		log.Warningf("Attribute ID is already set on resource")
	} else {
		sa = &SimpleAttribute{}
		sa.Name = "id"
		sa.atType = rs.GetType().GetAtType(sa.Name)
		rs.Core.SimpleAts[sa.Name] = sa
	}

	sa.Values = make([]interface{}, 1)
	sa.Values[0] = id
}

func (rs *Resource) GetExternalId() *string {
	sa := rs.Core.SimpleAts["externalid"]
	if sa == nil {
		return nil
	}

	str := sa.Values[0].(string)
	return &str
}

func (rs *Resource) GetMeta() *ComplexAttribute {
	return rs.Core.ComplexAts["meta"]
}

func (rs *Resource) AddMeta() *ComplexAttribute {
	// manually adding with the assumption that this performs better than parsing map[string]interface{} when AddCA() is used
	ca := &ComplexAttribute{}
	ca.Name = "meta"
	sc := rs.resType.GetMainSchema()
	ca.atType = sc.AttrMap[ca.Name]
	ca.SubAts = make([]map[string]*SimpleAttribute, 1)
	rs.Core.ComplexAts[ca.Name] = ca

	parentAt := sc.AttrMap[ca.Name]
	atMap := make(map[string]*SimpleAttribute)
	ca.SubAts[0] = atMap

	// FIXME the sub-attributes resourcetype, location and version can be injected on demand during querying
	// this will save some disk space
	resTypeAt := &SimpleAttribute{Name: "resourcetype"}
	resTypeAt.atType = parentAt.SubAttrMap[resTypeAt.Name]
	resTypeAt.Values = make([]interface{}, 1)
	resTypeAt.Values[0] = rs.resType.Name
	atMap[resTypeAt.Name] = resTypeAt

	createdAt := &SimpleAttribute{Name: "created"}
	createdAt.atType = parentAt.SubAttrMap[createdAt.Name]
	createdAt.Values = make([]interface{}, 1)
	createdAt.Values[0] = utils.DateTimeMillis()
	atMap[createdAt.Name] = createdAt

	lastModAt := &SimpleAttribute{Name: "lastmodified"}
	lastModAt.atType = parentAt.SubAttrMap[lastModAt.Name]
	lastModAt.Values = make([]interface{}, 1)
	lastModAt.Values[0] = utils.DateTimeMillis()
	atMap[lastModAt.Name] = lastModAt

	locationAt := &SimpleAttribute{Name: "location"}
	locationAt.atType = parentAt.SubAttrMap[locationAt.Name]
	locationAt.Values = make([]interface{}, 1)
	locationAt.Values[0] = rs.resType.Endpoint + "/" + rs.GetId()
	atMap[locationAt.Name] = locationAt

	versionAt := &SimpleAttribute{Name: "version"}
	versionAt.atType = parentAt.SubAttrMap[versionAt.Name]
	versionAt.Values = make([]interface{}, 1)
	versionAt.Values[0] = fmt.Sprint(lastModAt.Values[0])
	atMap[versionAt.Name] = versionAt

	return ca
}

func (rs *Resource) RemoveReadOnlyAt() {
	_removeReadOnly(rs.Core)
	if len(rs.Ext) > 0 {
		for _, v := range rs.Ext {
			_removeReadOnly(v)
		}
	}
}

func _removeReadOnly(atg *AtGroup) {
	if atg == nil {
		return
	}

	if len(atg.SimpleAts) > 0 {
		for k, v := range atg.SimpleAts {
			if v.GetType().IsReadOnly() {
				// do not delete schemas attribute
				// this MUST be stored
				if k == "schemas" {
					continue
				}
				delete(atg.SimpleAts, k)
			}
		}
	}

	if len(atg.ComplexAts) > 0 {
		for k, v := range atg.ComplexAts {
			if v.GetType().IsReadOnly() {
				delete(atg.ComplexAts, k)
			}
		}
	}
}

func (rs *Resource) CheckMissingRequiredAts() error {
	err := _checkMissingReqAts(rs.resType.GetMainSchema(), rs)
	if err != nil {
		return err
	}

	for scid, _ := range rs.Ext {
		err = _checkMissingReqAts(rs.resType.GetSchema(scid), rs)
		if err != nil {
			return err
		}
	}

	return nil
}

func _checkMissingReqAts(sc *schema.Schema, rs *Resource) error {
	for _, atName := range sc.RequiredAts {
		attr := rs.GetAttr(atName)
		if attr == nil {
			detail := fmt.Sprintf("Required attribute %s of schema %s is missing from the resource", atName, sc.Id)
			log.Debugf(detail)
			return NewBadRequestError(detail)
		}
	}

	return nil
}

func (sa *SimpleAttribute) Equals(other *SimpleAttribute) bool {
	if other == nil {
		return false
	}

	if sa.atType != other.atType {
		return false
	}

	if len(sa.Values) != len(other.Values) {
		return false
	}

	for _, saVal := range sa.Values {
		matches := false
		for _, otherVal := range other.Values {
			matches = Compare(sa.atType, saVal, otherVal)
			if matches {
				break
			}
		}

		if !matches {
			return false
		}
	}

	return true
}

func Compare(atType *schema.AttrType, saVal interface{}, otherVal interface{}) bool {
	switch atType.Type {
	case "boolean":
		return saVal.(bool) == otherVal.(bool)

	case "integer", "datetime":
		return saVal.(int64) == otherVal.(int64)

	case "decimal":
		return saVal.(float64) == otherVal.(float64)

	case "string", "binary", "reference":
		// does a case-sensitive comparison irrespective of the attribute type's
		// caseExact setting
		return saVal.(string) == otherVal.(string)
	}

	panic(fmt.Errorf("Unknown attribute type comparison"))
}

func (rs *Resource) UpdateLastModTime() {
	meta := rs.Core.ComplexAts["meta"].SubAts[0]
	millis := utils.DateTimeMillis()
	meta["lastmodified"].Values[0] = millis
	meta["version"].Values[0] = fmt.Sprint(millis)
}

func (rs *Resource) UpdateSchemas() {
	schemaIds := make([]interface{}, 1)
	schemaIds[0] = rs.resType.Schema
	for scId, _ := range rs.Ext {
		schemaIds = append(schemaIds, scId)
	}

	schemas := rs.Core.SimpleAts["schemas"]
	schemas.Values = schemaIds
}

// ---------------- attribute accessors -------------

func (rs *Resource) GetAttr(attrPath string) Attribute {
	log.Debugf("searching for attribute %s", attrPath)
	pos := strings.LastIndex(attrPath, URI_DELIM)
	if pos > 0 {
		var atg *AtGroup
		uri := attrPath[:pos]                        // URI is case sensitive
		attrPath = strings.ToLower(attrPath[pos+1:]) // attribute is not

		if rs.Ext != nil {
			atg = rs.Ext[uri]
		}

		if atg == nil {
			// select Core only if the URI matches the main schema
			if uri == rs.resType.Schema {
				atg = rs.Core
			} else {
				log.Debugf("No extended attribute %s found with URI prefix %s", attrPath, uri)
				return nil
			}
		}

		return rs.searchAttr(attrPath, atg)
	}

	attrPath = strings.ToLower(attrPath) // here no URI exists, can be converted to lowercase
	at := rs.searchAttr(attrPath, rs.Core)
	if at == nil && rs.Ext != nil {
		for _, exAtg := range rs.Ext {
			at = rs.searchAttr(attrPath, exAtg)
			if at != nil {
				break
			}
		}
	}

	return at
}

func (rs *Resource) searchAttr(attrPath string, atg *AtGroup) Attribute {
	if atg == nil {
		return nil
	}
	pos := strings.LastIndex(attrPath, ATTR_DELIM)
	//handle the attributes with . char
	if pos > 0 {
		parent := attrPath[:pos]
		at := atg.getAttribute(parent)
		if at != nil && !at.IsSimple() {
			ct := at.GetComplexAt()
			// always get the first attribute, even if it is multi-valued
			// for accessing all values of the attribute caller should search for the parent alone
			child := attrPath[pos+1:]
			atMap := ct.SubAts[0]
			sa := atMap[child]

			return sa
		}

		return nil
	} else {
		return atg.getAttribute(attrPath)
	}
}

// ------------------ end of attribute accessors ----

func (rs *Resource) GetType() *schema.ResourceType {
	return rs.resType
}

func NewAtGroup() *AtGroup {
	return &AtGroup{SimpleAts: make(map[string]*SimpleAttribute), ComplexAts: make(map[string]*ComplexAttribute)}
}

func NewResource(rt *schema.ResourceType) *Resource {
	rs := &Resource{}
	rs.resType = rt
	rs.TypeName = rt.Name
	rs.Core = NewAtGroup()
	rs.Ext = make(map[string]*AtGroup)

	return rs
}

func (rs *Resource) AddSA(name string, val ...interface{}) error {
	sa := &SimpleAttribute{}
	sa.atType = rs.resType.GetAtType(name)
	sa.Name = sa.atType.NormName
	if sa.atType == nil {
		return fmt.Errorf("No attribute type found with the name %s in the resource type %s", name, rs.resType.Schema)
	}

	if len(val) == 0 {
		return fmt.Errorf("Invalid values given for the attribute %s", name)
	}

	if !sa.atType.MultiValued {
		sa.Values = make([]interface{}, 1)
		sa.Values[0] = val[0] //checkValueTypeAndConvert(reflect.ValueOf(val[0]), sa.atType)
	} else {
		sa.Values = val
	}

	rs.addSimpleAt(sa)

	return nil
}

func (rs *Resource) AddCA(name string, val ...map[string]interface{}) (err error) {
	atType := rs.resType.GetAtType(name)
	if atType == nil {
		return fmt.Errorf("No attribute type found with the name %s in the resource type %s", name, rs.resType.Schema)
	}

	if len(val) == 0 {
		return fmt.Errorf("Invalid values given for the attribute %s", name)
	}

	defer func() {
		e := recover()
		if e != nil {
			log.Debugf("panicked while adding complex attribute %s, %#v\n", name, e)
			err = e.(error)
		}
	}()

	var ca *ComplexAttribute
	if atType.MultiValued {
		ca = parseComplexAttr(atType, val)
	} else {
		ca = parseComplexAttr(atType, val[0])
	}

	if ca == nil {
		return fmt.Errorf("Failed to add the complex attribute %s, check the JSON data", name)
	}

	rs.addComplexAt(ca)
	return nil
}

func (rs *Resource) addSimpleAt(sa *SimpleAttribute) {
	scId := sa.atType.SchemaId
	if scId == rs.resType.Schema {
		rs.Core.SimpleAts[sa.Name] = sa
		return
	}

	atg := rs.Ext[scId]
	if atg == nil {
		atg = NewAtGroup()
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
		atg = NewAtGroup()
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
			atType := sc.AttrMap[k]
			v.atType = atType
		}
	}

	if len(atg.ComplexAts) > 0 {
		for k, v := range atg.ComplexAts {
			parentType := sc.AttrMap[k]
			v.atType = parentType
			for _, saArr := range v.SubAts {
				for _, sa := range saArr {
					subType := parentType.SubAttrMap[sa.Name]
					sa.atType = subType
				}
			}
		}
	}
}

func ParseResource(resTypes map[string]*schema.ResourceType, sm map[string]*schema.Schema, body io.Reader) (*Resource, error) {
	if sm == nil {
		err := NewError()
		err.Detail = "Schemas cannot be null"
		return nil, err
	}

	if resTypes == nil {
		err := NewError()
		err.Detail = "ResourceTypes cannot be null"
		return nil, err
	}

	if body == nil {
		return nil, NewBadRequestError("Invalid JSON data")
	}

	var i interface{}
	dec := json.NewDecoder(body)
	err := dec.Decode(&i)

	if err != nil {
		log.Debugf("%#v", err)
		return nil, NewBadRequestError(err.Error())
	}

	if reflect.TypeOf(i).Kind() != reflect.Map {
		return nil, NewBadRequestError("Invalid JSON data")
	}

	obj := i.(map[string]interface{})

	schemaIds := obj["schemas"]

	if schemaIds == nil {
		return nil, NewBadRequestError("Invalid resource, 'schemas' attribute is missing")
	}

	rv := reflect.ValueOf(schemaIds)
	kind := rv.Kind()
	if (kind != reflect.Slice) && (kind != reflect.Array) {
		msg := "Value of the 'schemas' attribute must be an array"
		log.Debugf(msg)
		return nil, NewBadRequestError(msg)
	}

	schemaIdMap := make(map[string]int)
	for i := 0; i < rv.Len(); i++ {
		// make sure the values are all primitives
		v := rv.Index(i)
		kind = v.Kind()
		if kind != reflect.String && kind != reflect.Interface {
			msg := "Value given for the 'schemas' attribute is invalid"
			log.Debugf(msg)
			return nil, NewBadRequestError(msg)
		}

		var strVal string
		if kind == reflect.Interface {
			strVal = fmt.Sprint(v.Interface())
		} else {
			strVal = v.String()
		}

		schemaIdMap[strVal] = 0
	}

	var rt *schema.ResourceType

	for _, rtype := range resTypes {
		if _, present := schemaIdMap[rtype.Schema]; present {
			rt = rtype
			break
		}
	}

	if rt == nil {
		msg := fmt.Sprintf("No resource type found with the schemas %#v", schemaIdMap)
		log.Debugf(msg)
		return nil, NewBadRequestError(msg)
	}

	// delete the main schema, those that remained are extensions
	delete(schemaIdMap, rt.Schema)

	// validate extensions
	if len(rt.SchemaExtensions) != 0 {
		for _, v := range rt.SchemaExtensions {
			if v.Required { // this MUST be present in 'schemas'
				if _, present := schemaIdMap[v.Schema]; !present {
					msg := fmt.Sprintf("The extensions schema %s is missing in the resource data, it is mandatory for resource type %s", v.Schema, rt.Id)
					log.Debugf(msg)
					return nil, NewBadRequestError(msg)

				}
			}
			// start deleting the extension schemas
			delete(schemaIdMap, v.Schema)
		}

		// at the end schemaIdMap should be empty, otherwise it means it has some unknown extension schemas
		if len(schemaIdMap) != 0 {
			msg := fmt.Sprintf("Unknown schema extensions are present in the given resource data %#v", schemaIdMap)
			log.Debugf(msg)
			return nil, NewBadRequestError(msg)
		}
	} else if len(schemaIdMap) > 0 { // note that only extension schemas are present in schemaIdMap by the time we get here
		msg := fmt.Sprintf("Given resource data has specified schema extension(s) but the resource type %s has no schema extensions", rt.Id)
		log.Debugf(msg)
		return nil, NewBadRequestError(msg)
	}

	log.Debugf("converting to resource")
	return toResource(rt, sm, obj)
}

func toResource(rt *schema.ResourceType, sm map[string]*schema.Schema, obj map[string]interface{}) (rs *Resource, err error) {

	rs = &Resource{}
	rs.resType = rt
	rs.TypeName = rt.Name
	rs.Core = NewAtGroup()
	rs.Ext = make(map[string]*AtGroup)

	defer func() {
		e := recover()
		if e != nil {
			log.Debugf("panicked while parsing resource data %#v\n", e)
			rs = nil
			err = e.(error)
		}
	}()

	sc := rt.GetMainSchema()

	pph := &postParsingHints{}

	parseJsonObject(obj, rt, sc, rs, pph)

	if pph.updateSchemas {
		rs.UpdateSchemas()
	}

	return rs, nil
}

func parseJsonObject(obj map[string]interface{}, rt *schema.ResourceType, sc *schema.Schema, rs *Resource, pph *postParsingHints) {
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
				msg := fmt.Sprintf("Unknown schema, %s is not found in the extension schemas of resourcetype %s", k, rs.TypeName)
				panic(NewBadRequestError(msg))
			}

			var vObj map[string]interface{}

			switch v.(type) {
			case map[string]interface{}:
				vObj = v.(map[string]interface{})
				if len(vObj) == 0 {
					log.Debugf("Skipping empty extended object")
					pph.updateSchemas = true
					continue
				}

			case nil:
				log.Debugf("Skipping null extended object")
				pph.updateSchemas = true
				continue

			default:
				msg := fmt.Sprintf("Invalid value of key %s", k)
				panic(NewBadRequestError(msg))
			}

			parseJsonObject(vObj, rt, extSc, rs, pph)
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
			if sa != nil {
				rs.addSimpleAt(sa)
			}
		} else if atType.IsComplex() {
			ca := parseComplexAttr(atType, v)
			if ca != nil {
				rs.addComplexAt(ca)
			}
		}
	}
}

func parseSimpleAttr(attrType *schema.AttrType, iVal interface{}) *SimpleAttribute {
	rv := reflect.ValueOf(iVal)

	kind := rv.Kind()

	if kind == reflect.Invalid {
		log.Debugf("Null value is received for the simple attribute %s, skipping attribute", attrType.Name)
		return nil
	}

	sa := &SimpleAttribute{}
	sa.Name = attrType.NormName
	sa.atType = attrType

	log.Debugf("Parsing simple attribute %s\n", sa.Name)
	if attrType.MultiValued {
		//fmt.Println("rv kind ", rv.Kind())
		if (kind != reflect.Slice) && (kind != reflect.Array) {
			msg := fmt.Sprintf("Value of the attribute %s must be an array", attrType.Name)
			panic(NewBadRequestError(msg))
		}

		arrLen := rv.Len()
		if arrLen == 0 {
			log.Debugf("Empty array is received for the simple attribute %s, skipping attribute", attrType.Name)
			return nil
		}

		arr := make([]interface{}, arrLen)
		for i := 0; i < arrLen; i++ {
			// make sure the values are all primitives
			v := rv.Index(i)
			kind = v.Kind()
			if kind == reflect.Invalid {
				detail := fmt.Sprintf("Null value is present in the values of multivalued simple attribute %s, skipping value", attrType.Name)
				log.Debugf(detail)
				panic(NewBadRequestError(detail))
			}

			strVal := checkValueTypeAndConvert(v, attrType)
			arr[i] = strVal
		}

		sa.Values = arr

		return sa
	}

	strVal := checkValueTypeAndConvert(rv, attrType)
	sa.Values = []interface{}{strVal}
	return sa
}

func checkValueTypeAndConvert(v reflect.Value, attrType *schema.AttrType) interface{} {
	msg := fmt.Sprintf("Invalid value '%#v' in attribute %s", v, attrType.Name)
	err := NewBadRequestError(msg)

	kind := v.Kind()

	log.Debugf("%s = %#v is of type %s", attrType.Name, v, kind)

	switch attrType.Type {
	case "boolean":
		if kind != reflect.Bool {
			panic(err)
		}
		return v.Bool()
	case "integer":
		if kind != reflect.Float64 {
			panic(err)
		}

		str := fmt.Sprint(v.Float())
		if strings.ContainsRune(str, '.') {
			panic(err)
		}

		intVal, e := strconv.ParseInt(str, 10, 64)
		if e != nil {
			panic(err)
		}

		return intVal
	case "decimal":
		if kind != reflect.Float64 {
			panic(err)
		}
		return v.Float()

	case "datetime":
		if kind != reflect.String && kind != reflect.Interface {
			panic(err)
		}

		var date string
		if kind == reflect.Interface {
			date = fmt.Sprint(v.Interface())
		} else {
			date = v.String()
		}

		t, e := time.Parse(time.RFC3339, date)
		if e != nil {
			panic(err)
		}

		millis := t.UnixNano() / 1000000

		return millis

	case "string", "binary", "reference":
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

	kind := rv.Kind()

	if kind == reflect.Invalid {
		log.Debugf("Null value is received for the complex attribute %s, skipping attribute", attrType.Name)
		return nil
	}

	ca := &ComplexAttribute{}
	ca.Name = attrType.NormName
	ca.atType = attrType

	if attrType.MultiValued {
		if (kind != reflect.Slice) && (kind != reflect.Array) {
			msg := fmt.Sprintf("Value of the attribute %s must be an array", attrType.Name)
			panic(NewBadRequestError(msg))
		}

		arrLen := rv.Len()
		if arrLen == 0 {
			log.Debugf("Empty array is received for the complex attribute %s, skipping attribute", attrType.Name)
			return nil
		}

		subAtArrMap := make([]map[string]*SimpleAttribute, arrLen)
		primaryAlreadySet := false
		for i := 0; i < arrLen; i++ {
			v := rv.Index(i)
			kind = v.Kind()
			if kind == reflect.Invalid {
				detail := fmt.Sprintf("Null value is present in the values of multivalued complex attribute %s, skipping value", attrType.Name)
				log.Debugf(detail)
				panic(NewBadRequestError(detail))
			}

			simpleAtMap, prm := parseSubAtList(v.Interface(), attrType)
			if prm {
				if primaryAlreadySet {
					detail := fmt.Sprintf("More than one sub attribute is marked as primary in the complex attribute %s", attrType.Name)
					log.Debugf(detail)
					panic(NewBadRequestError(detail))
				} else {
					primaryAlreadySet = true
				}
			}
			subAtArrMap[i] = simpleAtMap
		}

		ca.SubAts = subAtArrMap

		return ca
	}

	simpleAtMap, _ := parseSubAtList(iVal, attrType)
	ca.SubAts = []map[string]*SimpleAttribute{simpleAtMap}

	return ca
}

func parseSubAtList(v interface{}, attrType *schema.AttrType) (subAtMap map[string]*SimpleAttribute, primary bool) {
	var vObj map[string]interface{}

	switch v.(type) {
	case map[string]interface{}:
		vObj = v.(map[string]interface{})
	default:
		msg := fmt.Sprintf("Invalid sub-attribute value %#v , expected a JSON object", v)
		panic(NewBadRequestError(msg))
	}

	arr := make(map[string]*SimpleAttribute)
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
		if subAt != nil {
			if subAt.Name == "primary" {
				if p, ok := subAt.Values[0].(bool); ok && p {
					primary = true
				}
			}
			arr[subAt.Name] = subAt
		}
	}

	return arr, primary
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
			arr[i] = simpleATMapToMap(v)
		}

		return arr
	}

	return simpleATMapToMap(ca.SubAts[0])
}

func simpleATMapToMap(sas map[string]*SimpleAttribute) map[string]interface{} {
	obj := make(map[string]interface{})
	for _, v := range sas {
		obj[v.atType.Name] = v.valToInterface()
	}

	return obj
}

func (atg *AtGroup) ToMap() map[string]interface{} {
	obj := make(map[string]interface{})

	if len(atg.SimpleAts) > 0 {
		for _, v := range atg.SimpleAts {
			i := v.valToInterface()
			if i != nil {
				// use the name from AttrType
				// this name will be in camelcase
				obj[v.atType.Name] = i
			}
		}
	}

	if len(atg.ComplexAts) > 0 {
		for _, v := range atg.ComplexAts {
			i := v.valToInterface()
			if i != nil {
				// use the name from AttrType
				// this name will be in camelcase
				obj[v.atType.Name] = i
			}
		}
	}

	return obj
}

func getConvertedVal(v interface{}, sa *SimpleAttribute) interface{} {
	switch sa.atType.Type {
	case "datetime":
		millis, _ := v.(int64)
		// by default the TZ will be set to Local, so calling UTC() is a must
		t := time.Unix(0, millis*int64(time.Millisecond)).UTC()
		str := t.Format(time.RFC3339)
		return str

	default:
		return v
	}
}

func (rs *Resource) ToJSON() string {
	if rs.Core == nil {
		return `{"ToJSON": "invalid resource, no attributes"}`
	}

	return string(rs.Serialize())
}

func (rs *Resource) Serialize() []byte {
	obj := rs.Core.ToMap()

	if len(rs.Ext) > 0 {
		for k, v := range rs.Ext {
			extObj := v.ToMap()
			obj[k] = extObj
		}
	}

	data, err := json.Marshal(obj)
	if err != nil {
		log.Criticalf("Failed to serialize the resource %s", err)
		return nil
	}

	return data
}

func (rs *Resource) FilterAndSerialize(attrs []*AttributeParam, include bool) []byte {
	if !include {
		for _, ap := range attrs {
			if ap.SubAts != nil {
				for _, name := range ap.SubAts {
					rs.DeleteAttr(ap.Name + "." + name)
				}
			} else {
				rs.DeleteAttr(ap.Name)
			}
		}

		return rs.Serialize()
	}

	coreObj := make(map[string]interface{})

	for _, ap := range attrs {
		at := rs.GetAttr(ap.Name)
		if at == nil {
			continue
		}

		obj := coreObj

		atType := at.GetType()
		if atType.SchemaId != rs.resType.Schema {
			if coreObj[atType.SchemaId] == nil {
				obj = make(map[string]interface{})
				coreObj[atType.SchemaId] = obj
			}
		}

		if at.IsSimple() {
			sa := at.GetSimpleAt()
			obj[atType.Name] = sa.valToInterface()
		} else {
			ca := at.GetComplexAt()
			if ap.SubAts != nil {
				if atType.MultiValued {
					arr := make([]map[string]interface{}, 0)
					for _, st := range ca.SubAts {
						subObj := make(map[string]interface{})
						for _, sn := range ap.SubAts {
							if v, ok := st[sn]; ok {
								subObj[v.atType.Name] = getConvertedVal(v.Values[0], v)
							}
						}
						arr = append(arr, subObj)
					}

					obj[atType.Name] = arr
				} else {
					subObj := make(map[string]interface{})
					for _, sn := range ap.SubAts {
						if v, ok := ca.SubAts[0][sn]; ok {
							subObj[v.atType.Name] = getConvertedVal(v.Values[0], v)
						}
					}
					obj[atType.Name] = subObj
				}
			} else {
				obj[atType.Name] = ca.valToInterface()
			}
		}
	}

	data, err := json.Marshal(coreObj)
	if err != nil {
		log.Criticalf("Failed to serialize the filtered resource %s", err)
		return nil
	}

	return data
}

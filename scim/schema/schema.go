package schema

import (
	"log"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
)

var (
	validTypes = []string{"string", "boolean", "decimal", "integer", "datetime", "binary", "reference", "complex"}

	validMutability = []string{"readonly", "readwrite", "immutable", "writeonly"}

	validReturned = []string{"always", "never", "default", "request"}

	validUniqueness = []string{"none", "server", "global"}

	validNameRegex = regexp.MustCompile(`^[0-9A-Za-z_$-]+$`)
	
	//SchemasAttr = &AttrType{Name: "schemas", Required: true, CaseExact: true, Mutability: "readWrite", Returned: "always", Uniqueness: "none", Type: "string", MultiValued: true}
	
	//CORE_SCHEMA_PREFIX = "urn:ietf:params:scim:schemas:core:2.0:"
	
	//EXT_SCHEMA_PREFIX = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:"
)

type AttrType struct {
	Name            string      // name
	Type            string      // type
	Description     string      // description
	CaseExact       bool        // caseExact
	MultiValued     bool        // multiValued
	Mutability      string      // mutability
	Required        bool        // required
	Returned        string      // returned
	Uniqueness      string      // uniqueness
	SubAttributes   []*AttrType // subAttributes
	ReferenceTypes  []string    // referenceTypes
	CanonicalValues []string    // canonicalValues
	SubAttrMap      map[string]*AttrType
	SchemaId		string // schema's ID
	Parent			*AttrType // parent Attribute
}

type Schema struct {
	Id          string // id
	Name        string // name
	Description string // description
	Attributes  []*AttrType
	AttrMap     map[string]*AttrType
	Meta        struct {
		Location     string // location
		ResourceType string // resourceType
	} // meta
}

// see section https://tools.ietf.org/html/rfc7643#section-2.2 for the defaults
func newAttrType() *AttrType {
	return &AttrType{Required: false, CaseExact: false, Mutability: "readWrite", Returned: "default", Uniqueness: "none", Type: "string"}
}

func LoadSchema(name string) (*Schema, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	
	log.Println("Loading schema from file " + name)
	
	return NewSchema(data)
}

func NewSchema(data []byte) (*Schema, error) {
	sc := &Schema{}

	err := json.Unmarshal(data, sc)

	if err != nil {
		return nil, err
	}

	attrLen := len(sc.Attributes)

	if attrLen != 0 {
		for i := 0; i < attrLen; i++ {
			setAttrDefaults(sc.Attributes[i])
		}
	}

	err = validate(sc)

	if err != nil {
		return nil, err
	}

	// common attributes
	schemasAttr := newAttrType()
	schemasAttr.Name = "schemas"
	schemasAttr.Required = true
	schemasAttr.Returned = "always"
	schemasAttr.MultiValued = true
	schemasAttr.SchemaId = sc.Id
	sc.Attributes = append(sc.Attributes, schemasAttr)
	sc.AttrMap[schemasAttr.Name] = schemasAttr
	
	// id
	idAttr := newAttrType()
	idAttr.Name = "id"
	idAttr.Returned = "always"
	idAttr.CaseExact = true
	idAttr.MultiValued = false
	idAttr.SchemaId = sc.Id
	sc.Attributes = append(sc.Attributes, idAttr)
	sc.AttrMap[idAttr.Name] = idAttr

	// externalId
	externalIdAttr := newAttrType()
	externalIdAttr.Name = "externalid"
	externalIdAttr.CaseExact = true
	externalIdAttr.SchemaId = sc.Id
	sc.Attributes = append(sc.Attributes, externalIdAttr)
	sc.AttrMap[externalIdAttr.Name] = externalIdAttr

	// id
	metaAttr := newAttrType()
	metaAttr.Name = "meta"
	metaAttr.Returned = "default"
	metaAttr.CaseExact = false
	metaAttr.MultiValued = false
	metaAttr.SchemaId = sc.Id
	sc.Attributes = append(sc.Attributes, metaAttr)
	sc.AttrMap[metaAttr.Name] = metaAttr

	return sc, nil
}

func setAttrDefaults(attr *AttrType) {
	if len(attr.Mutability) == 0 {
		attr.Mutability = "readWrite"
	}

	if len(attr.Returned) == 0 {
		attr.Returned = "default"
	}

	if len(attr.Uniqueness) == 0 {
		attr.Uniqueness = "none"
	}

	if len(attr.Type) == 0 {
		attr.Type = "string"
	}

	attrLen := len(attr.SubAttributes)

	if attrLen != 0 {
		for i := 0; i < attrLen; i++ {
			setAttrDefaults(attr.SubAttributes[i])
		}
	}
}

/*
func parse(data []byte) (*Schema, error){
	var i interface{}

	err := json.Unmarshal(data, &i)

	if(err != nil) {
		return nil, err
	}

	msg := i.(map[string]interface{})

	sc := &Schema{}

	sc.Id = msg["id"].(string)
	sc.Name = msg["name"].(string)
	sc.Description = msg["description"].(string)

	atArr := msg["attributes"].([]interface{})

	if(atArr == nil) {
		return sc, nil
	}

	dataAtArr, err := json.Marshal(atArr)

	attArrLen := len(atArr)
	attrs := make([]AttrType, attArrLen)

	for i := 0; i < attArrLen; i++ {
		attrs[i] = newAttrType()
	}

	err = json.Unmarshal(dataAtArr, &attrs)
	if(err != nil) {
		return nil, err
	}

	sc.Attributes = attrs

	return sc, nil
}
*/
type ValidationErrors struct {
	Count int
	Msgs  []string
}

func (ve *ValidationErrors) Error() string {
	return fmt.Sprintf("Total %d errors\n%v", ve.Count, ve.Msgs)
}

func (ve *ValidationErrors) add(e string) {
	ve.Count++
	ve.Msgs = append(ve.Msgs, e)
}

func (attr *AttrType) IsComplex() bool {
	return strings.ToLower(attr.Type) == "complex"
}

func (attr *AttrType) IsRef() bool {
	return strings.ToLower(attr.Type) == "reference"
}

func (attr *AttrType) IsSimple() bool {
	return !attr.IsComplex() && !attr.IsRef()
}

func (attr *AttrType) IsReadOnly() bool {
	return strings.ToLower(attr.Mutability) == "readonly"
}

func (attr *AttrType) IsReference() bool {
	return strings.ToLower(attr.Type) == "reference"
}

func validate(sc *Schema) error {
	ve := &ValidationErrors{0, make([]string, 2)}

	if len(sc.Id) == 0 {
		ve.add("Schema id is required")
	}
	
	if len(sc.Attributes) == 0 {
		ve.add("A schema should contain atleast one attribute")
		return ve
	}

	sc.AttrMap = make(map[string]*AttrType)

	for _, attr := range sc.Attributes {
		validateAttrType(attr, sc, ve)
		sc.AttrMap[strings.ToLower(attr.Name)] = attr
	}

	if ve.Count == 0 {
		return nil
	}

	return ve
}

func validateAttrType(attr *AttrType, sc *Schema, ve *ValidationErrors) {

	// ATTRNAME   = ALPHA *(nameChar)
	// nameChar   = "$" / "-" / "_" / DIGIT / ALPHA
	// ALPHA      =  %x41-5A / %x61-7A   ; A-Z / a-z
	// DIGIT      =  %x30-39            ; 0-9

	if !validNameRegex.MatchString(attr.Name) {
		ve.add("Invalid attribute name '" + attr.Name + "'")
	}

	atType := strings.ToLower(attr.Type)
	if !exists(atType, validTypes) {
		ve.add("Invalid type '" + attr.Type + "' for attribute " + attr.Name)
	}

	atMut := strings.ToLower(attr.Mutability)
	if !exists(atMut, validMutability) {
		ve.add("Invalid mutability '" + attr.Mutability + "' for attribute " + attr.Name)
	}

	atRet := strings.ToLower(attr.Returned)
	if !exists(atRet, validReturned) {
		ve.add("Invalid returned '" + attr.Returned + "' for attribute " + attr.Name)
	}

	atUniq := strings.ToLower(attr.Uniqueness)
	if !exists(atUniq, validUniqueness) {
		ve.add("Invalid uniqueness '" + attr.Uniqueness + "' for attribute " + attr.Name)
	}

	refTypeLen := len(attr.ReferenceTypes)

	if attr.IsReference() && (refTypeLen == 0) {
		ve.add("No referenceTypes set for attribute " + attr.Name)
	}

	subAttrLen := len(attr.SubAttributes)

	if attr.IsComplex() && (subAttrLen == 0) {
		ve.add("No subattributes set for attribute " + attr.Name)
	}

    attr.Name = strings.ToLower(attr.Name)
    attr.SchemaId = sc.Id
    
	if subAttrLen != 0 {
		if attr.SubAttrMap == nil {
			attr.SubAttrMap = make(map[string]*AttrType)
		}
		for _, sa := range attr.SubAttributes {
			validateAttrType(sa, sc, ve)
			sa.Parent = attr
			attr.SubAttrMap[strings.ToLower(sa.Name)] = sa
		}
	}
}

func exists(val string, list []string) bool {
	for _, token := range list {
		if token == val {
			return true
		}
	}

	return false
}

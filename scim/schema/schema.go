package schema

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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

// The definition of an attribute's type
// All the fields are named identical to those defined in the schema definition
// in rfc7643 so that schema JSON files can be parsed using Go's default unmarshaller
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
	SchemaId        string    // schema's ID
	Parent          *AttrType // parent Attribute
}

// Definition of the schema
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

// Parses the given schema file and returns a schema instance after successfuly parsing
func LoadSchema(name string) (*Schema, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	log.Println("Loading schema from file " + name)

	return NewSchema(data)
}

// Parses the given schema data and returns a schema instance after successfuly parsing
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

	return sc, nil
}

// sets the default values on the missing common fields of schema's attribute type definitions
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

	attr.SchemaId = sc.Id

	if attr.IsComplex() {
		log.Printf("validating sub-attributes of attributetype %s\n", attr.Name)
		if attr.SubAttrMap == nil {
			attr.SubAttrMap = make(map[string]*AttrType)
		}

		if subAttrLen != 0 {
			for _, sa := range attr.SubAttributes {
				validateAttrType(sa, sc, ve)
				sa.Parent = attr
				attr.SubAttrMap[strings.ToLower(sa.Name)] = sa
			}
		}

		// add missing default sub-attributes https://tools.ietf.org/html/rfc7643#section-2.4
		if attr.MultiValued {
			addDefSubAttrs(attr)
		}
	}
}

func addDefSubAttrs(attr *AttrType) {
	defArr := [5]*AttrType{}

	typeAttr := newAttrType()
	typeAttr.Name = "type"
	defArr[0] = typeAttr

	primaryAttr := newAttrType()
	primaryAttr.Name = "primary"
	primaryAttr.Type = "boolean"
	defArr[1] = primaryAttr

	displayAttr := newAttrType()
	displayAttr.Name = "display"
	displayAttr.Mutability = "immutable"
	defArr[2] = displayAttr

	valueAttr := newAttrType()
	valueAttr.Name = "value"
	defArr[3] = valueAttr

	refAttr := newAttrType()
	refAttr.Name = "$ref"
	defArr[4] = refAttr

	for _, a := range defArr {
		key := strings.ToLower(a.Name)
		if attr.SubAttrMap[key] == nil {
			a.SchemaId = attr.SchemaId
			a.Parent = attr
			attr.SubAttrMap[key] = a
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

func (sc *Schema) GetAtType(name string) *AttrType {
	normName := strings.ToLower(name)

	var atType *AttrType

	if strings.ContainsRune(normName, '.') {
		arr := strings.SplitN(normName, ".", 2)
		parent := sc.AttrMap[arr[0]]

		if parent == nil {
			panic("Parent attribute type " + arr[0] + " not found")
		}

		if !parent.IsComplex() {
			panic("Parent attribute type " + arr[0] + " is not a complex attribute")
		}

		atType = parent.SubAttrMap[arr[1]]

		if atType == nil {
			panic("Sub-attribute type " + arr[1] + " not found")
		}
	} else {
		atType = sc.AttrMap[normName]
	}

	if atType == nil {
		panic("Attribute type " + normName + " not found")
	}

	return atType
}

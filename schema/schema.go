// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package schema

import (
	"encoding/json"
	"fmt"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"regexp"
	"sort"
	"strings"
)

const ATTR_DELIM = "."

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
	NormName        string    // the lowercase name of the attribute
	parent          *AttrType // parent Attribute, should be non-exportable, otherwise stackoverflow occurs during marshalling
	isUnique        bool      // for performance reasons
	isComplex       bool      // for performance reasons
	isRef           bool      // for performance reasons
	isSimple        bool      // for performance reasons
	isReadOnly      bool      // for performance reasons
	isImmutable     bool      // for performance reasons
	isStringType    bool      // for performance reasons
}

// Definition of the schema
type Schema struct {
	Id          string // id
	Name        string // name
	Description string // description
	Attributes  []*AttrType
	AttrMap     map[string]*AttrType
	Text        string
	Meta        struct {
		Location     string // location
		ResourceType string // resourceType
	} // meta

	UniqueAts     []string
	RequiredAts   []string
	AtsNeverRtn   []string // names of attributes that are never returned
	AtsAlwaysRtn  []string // names of attributes that are always returned
	AtsRequestRtn []string // names of attributes that are returned if requested
	AtsDefaultRtn []string // names of attributes that are returned by default
	AtsReadOnly   []string // names of attributes that are readonly
}

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.schema")
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

	log.Infof("Loading schema from file %s", name)

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

	sc.Text = string(data)
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

	attr.isUnique = (attr.Uniqueness == "server") || (attr.Uniqueness == "global")
	attr.isComplex = attr.Type == "complex"
	attr.isRef = attr.Type == "reference"
	attr.isSimple = !attr.isComplex && !attr.isRef
	attr.isReadOnly = attr.Mutability == "readonly"
	attr.isImmutable = attr.Mutability == "immutable"
	attr.isStringType = (attr.Type == "string" || attr.isRef)

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

// TODO avoid the need for strings.ToLower() in all IsXXX methods by replacing with lowercase values or by storing
// the result in boolean fields
func (attr *AttrType) IsComplex() bool {
	return attr.isComplex
}

func (attr *AttrType) IsRef() bool {
	return attr.isRef
}

func (attr *AttrType) IsSimple() bool {
	return attr.isSimple
}

func (attr *AttrType) IsReadOnly() bool {
	return attr.isReadOnly
}

func (attr *AttrType) IsUnique() bool {
	return attr.isUnique
}

func (attr *AttrType) IsImmutable() bool {
	return attr.isImmutable
}

func (attr *AttrType) IsStringType() bool {
	return attr.isStringType
}

func (attr *AttrType) Parent() *AttrType {
	return attr.parent
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
	sc.UniqueAts = make([]string, 0)
	sc.RequiredAts = make([]string, 0)

	for _, attr := range sc.Attributes {
		validateAttrType(attr, sc, ve)
		name := strings.ToLower(attr.Name)
		sc.AttrMap[name] = attr
		if attr.IsUnique() {
			sc.UniqueAts = append(sc.UniqueAts, name)
		}

		if attr.Required {
			sc.RequiredAts = append(sc.RequiredAts, name)
		}
	}

	if ve.Count == 0 {
		return nil
	}

	return ve
}

func (sc *Schema) collectReturnAttrs() {
	sc.AtsNeverRtn = make([]string, 0)
	sc.AtsAlwaysRtn = make([]string, 0)
	sc.AtsRequestRtn = make([]string, 0)
	sc.AtsDefaultRtn = make([]string, 0)
	sc.AtsReadOnly = make([]string, 0)

	for _, attr := range sc.Attributes {
		name := attr.NormName
		never := false
		readonly := false
		if attr.Returned == "never" {
			sc.AtsNeverRtn = append(sc.AtsNeverRtn, name)
			never = true
		}

		if attr.Returned == "always" {
			sc.AtsAlwaysRtn = append(sc.AtsAlwaysRtn, name)
		}

		if attr.Returned == "request" {
			sc.AtsRequestRtn = append(sc.AtsRequestRtn, name)
		}

		if attr.Returned == "default" {
			sc.AtsDefaultRtn = append(sc.AtsDefaultRtn, name)
		}

		// readonly is not a return characteristic but this method
		// is anyway iterating over all ATs so just placed this block here
		if attr.IsReadOnly() {
			sc.AtsReadOnly = append(sc.AtsReadOnly, name)
			readonly = true
		}

		// when the parent is not read-only or never returned check
		// for these qualities on sub-attributes
		if !never || !readonly {
			if attr.IsComplex() {
				for _, at := range attr.SubAttributes {
					subAtName := name + "." + at.NormName
					if at.Returned == "never" {
						sc.AtsNeverRtn = append(sc.AtsNeverRtn, subAtName)
					} else if at.IsReadOnly() {
						sc.AtsReadOnly = append(sc.AtsReadOnly, subAtName)
					}
				}
			}
		}
	}

	// sorting them just to keep them in order, helps while debugging
	sort.Strings(sc.AtsAlwaysRtn)
	sort.Strings(sc.AtsDefaultRtn)
	sort.Strings(sc.AtsNeverRtn)
	sort.Strings(sc.AtsReadOnly)
	sort.Strings(sc.AtsRequestRtn)
}

func validateAttrType(attr *AttrType, sc *Schema, ve *ValidationErrors) {

	// ATTRNAME   = ALPHA *(nameChar)
	// nameChar   = "$" / "-" / "_" / DIGIT / ALPHA
	// ALPHA      =  %x41-5A / %x61-7A   ; A-Z / a-z
	// DIGIT      =  %x30-39            ; 0-9

	if !validNameRegex.MatchString(attr.Name) {
		ve.add("Invalid attribute name '" + attr.Name + "'")
	}

	attr.Type = strings.ToLower(attr.Type)
	if !exists(attr.Type, validTypes) {
		ve.add("Invalid type '" + attr.Type + "' for attribute " + attr.Name)
	}

	attr.Mutability = strings.ToLower(attr.Mutability)
	if !exists(attr.Mutability, validMutability) {
		ve.add("Invalid mutability '" + attr.Mutability + "' for attribute " + attr.Name)
	}

	attr.Returned = strings.ToLower(attr.Returned)
	if !exists(attr.Returned, validReturned) {
		ve.add("Invalid returned '" + attr.Returned + "' for attribute " + attr.Name)
	}

	attr.Uniqueness = strings.ToLower(attr.Uniqueness)
	if !exists(attr.Uniqueness, validUniqueness) {
		ve.add("Invalid uniqueness '" + attr.Uniqueness + "' for attribute " + attr.Name)
	}

	refTypeLen := len(attr.ReferenceTypes)

	if attr.IsRef() && (refTypeLen == 0) {
		ve.add("No referenceTypes set for attribute " + attr.Name)
	}

	subAttrLen := len(attr.SubAttributes)

	if attr.IsComplex() && (subAttrLen == 0) {
		ve.add("No subattributes set for attribute " + attr.Name)
	}

	attr.SchemaId = sc.Id
	attr.NormName = strings.ToLower(attr.Name)

	if attr.IsComplex() {
		if attr.SubAttrMap == nil {
			attr.SubAttrMap = make(map[string]*AttrType)
		}

		if subAttrLen != 0 {
			log.Debugf("validating sub-attributes of attributetype %s\n", attr.Name)
			for _, sa := range attr.SubAttributes {
				log.Tracef("validating sub-type %s of %s", sa.Name, attr.Name)
				validateAttrType(sa, sc, ve)
				sa.parent = attr
				attr.SubAttrMap[sa.NormName] = sa
				name := attr.NormName + ATTR_DELIM + sa.NormName
				if sa.IsUnique() {
					sc.UniqueAts = append(sc.UniqueAts, name)
				}
				if sa.Required {
					sc.RequiredAts = append(sc.RequiredAts, name)
				}
			}
		}

		// add missing default sub-attributes https://tools.ietf.org/html/rfc7643#section-2.4
		if attr.MultiValued {
			addDefSubAttrs(attr)
			setAttrDefaults(attr)
		}
	}
}

func addDefSubAttrs(attr *AttrType) {
	defArr := [5]*AttrType{}

	typeAttr := newAttrType()
	typeAttr.Name = "type"
	typeAttr.NormName = typeAttr.Name
	defArr[0] = typeAttr

	primaryAttr := newAttrType()
	primaryAttr.Name = "primary"
	primaryAttr.NormName = primaryAttr.Name
	primaryAttr.Type = "boolean"
	defArr[1] = primaryAttr

	displayAttr := newAttrType()
	displayAttr.Name = "display"
	displayAttr.NormName = displayAttr.Name
	displayAttr.Mutability = "immutable"
	defArr[2] = displayAttr

	valueAttr := newAttrType()
	valueAttr.Name = "value"
	valueAttr.NormName = valueAttr.Name
	defArr[3] = valueAttr

	refAttr := newAttrType()
	refAttr.Name = "$ref"
	refAttr.NormName = refAttr.Name
	defArr[4] = refAttr

	for _, a := range defArr {
		key := strings.ToLower(a.Name)
		if attr.SubAttrMap[key] == nil {
			a.SchemaId = attr.SchemaId
			a.parent = attr
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

	log.Debugf("Looking up attribute type %s", name)

	if strings.ContainsRune(normName, '.') {
		arr := strings.SplitN(normName, ".", 2)
		parent := sc.AttrMap[arr[0]]

		if parent == nil {
			log.Debugf("Parent attribute type %s not found in schema %s", arr[0], sc.Name)
			return nil
		}

		if !parent.IsComplex() {
			panic("Parent attribute type " + arr[0] + " is not a complex attribute")
		}

		atType = parent.SubAttrMap[arr[1]]

		if atType == nil {
			//panic("Sub-attribute type " + arr[1] + " not found")
		}
	} else {
		atType = sc.AttrMap[normName]
	}

	if atType == nil {
		//panic("Attribute type " + normName + " not found")
	}

	return atType
}

package schema

import (
	"fmt"
	"strings"
	"regexp"
	"encoding/json"
	"io/ioutil"
)

var (
	validTypes = []string{"string", "boolean", "decimal", "integer", "datetime", "binary", "reference", "complex"}

	validMutability = []string{"readonly", "readwrite", "immutable", "writeonly"}

	validReturned = []string{"always", "never", "default", "request"}

	validUniqueness = []string{"none", "server", "global"}
	
	validNameRegex = regexp.MustCompile(`^[0-9A-Za-z_$-]+$`)
)

type Attribute struct {
	Name            string      // name
	Type            string      // type
	Description     string      // description
	CaseExact       bool        // caseExact
	MultiValued     bool        // multiValued
	Mutability      string      // mutability
	Required        bool        // required
	Returned        string      // returned
	Uniqueness      string      // uniqueness
	SubAttributes   []Attribute // subAttributes
	ReferenceTypes  []string    // referenceTypes
	CanonicalValues []string    // canonicalValues
}

type Schema struct {
	Id          string // id
	Name        string // name
	Description string // description
	Attributes  []Attribute
	Meta        struct {
		Location     string // location
		ResourceType string // resourceType
	} // meta
}

// see section https://tools.ietf.org/html/rfc7643#section-2.2 for the defaults
func newAttribute() Attribute {
	return Attribute{Required: false, CaseExact: false, Mutability: "readWrite", Returned: "default", Uniqueness: "none", Type: "string"}
}

func Load(name string) (*Schema, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	return New(data)
}

func New(data []byte) (*Schema, error) {
	sc := &Schema{}

	err := json.Unmarshal(data, sc)

	if err != nil {
		return nil, err
	}

	attrLen := len(sc.Attributes)

	if attrLen != 0 {
		for i := 0; i < attrLen; i++ {
			setAttrDefaults(&sc.Attributes[i])
		}
	}

    err = validate(sc)
    
    if err != nil {
    	return nil, err
    }
    
	return sc, nil
}

func setAttrDefaults(attr *Attribute) {
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
			setAttrDefaults(&attr.SubAttributes[i])
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
	attrs := make([]Attribute, attArrLen)

	for i := 0; i < attArrLen; i++ {
		attrs[i] = newAttribute()
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

func (attr *Attribute) IsComplex() bool {
	return strings.ToLower(attr.Type) == "complex"
}

func (attr *Attribute) IsReadOnly() bool {
	return strings.ToLower(attr.Mutability) == "readonly"
}

func (attr *Attribute) IsReference() bool {
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
	
	for _, attr := range sc.Attributes {
		validateAttribute(&attr, ve)
	}
	
	if ve.Count == 0 {
		return nil
	}
	
	return ve
}

func validateAttribute(attr *Attribute, ve *ValidationErrors) {

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

	subAttrLen := len(attr.SubAttributes)

	if attr.IsComplex() && (subAttrLen == 0) {
		ve.add("No subattributes set for attribute " + attr.Name)
	}

	if subAttrLen != 0 {
		for _, sa := range attr.SubAttributes {
			validateAttribute(&sa, ve)
		}
	}

	refTypeLen := len(attr.ReferenceTypes)

	if attr.IsReference() && (refTypeLen == 0) {
		ve.add("No referenceTypes set for attribute " + attr.Name)
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

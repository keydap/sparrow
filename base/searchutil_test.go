// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"os"
	"sparrow/schema"
	"testing"
)

var restypes []*schema.ResourceType
var schemas map[string]*schema.Schema
var rTypesMap map[string]*schema.ResourceType

func TestMain(m *testing.M) {
	resDir, _ := os.Getwd()
	resDir += "/../"
	resDir = resDir + "/resources/"
	schemaDir := resDir + "/schemas"
	rtDir := resDir + "/types"

	schemas, _ = LoadSchemas(schemaDir)
	rTypesMap, _, _ = LoadResTypes(rtDir, schemas)

	restypes = make([]*schema.ResourceType, 0)
	for _, v := range rTypesMap {
		restypes = append(restypes, v)
	}

	// now run the tests
	m.Run()
}

func TestParseAttributes(t *testing.T) {
	attrMap, subAtPresent := SplitAttrCsv("userName, pAsswoRD", restypes...)
	if !(attrMap["username"] == 1 && attrMap["password"] == 1) {
		t.Errorf("Incorrect attribute parsing")
	}

	if subAtPresent {
		t.Errorf("The subAtPresent flag must be false")
	}

	atParams := ConvertToParamAttributes(attrMap, subAtPresent)
	if len(atParams) != 2 {
		t.Errorf("Incorrect AttributeParam list")
	}

	// the '.' in URN shouldn't be considered for presence of a sub-attribute
	_, subAtPresent = SplitAttrCsv("urn:ietf:params:SCIM:schemas:corE:2.0:UseR:userName", restypes...)
	if subAtPresent {
		t.Errorf("The '.' in URN is considered for detecting presence of sub-attribute")
	}

	// check sub-attribute when the parent attribute is present
	attrMap, subAtPresent = SplitAttrCsv("userName, name.formatted, Name.GIVEnname, namename.name", restypes...)
	if !(attrMap["username"] == 1 && attrMap["name.givenname"] == 1 && attrMap["name.formatted"] == 1 && attrMap["namename.name"] == 1) {
		t.Errorf("Incorrect sub-attribute parsing")
	}

	if !subAtPresent {
		t.Errorf("The subAtPresent flag must be true")
	}

	atParams = ConvertToParamAttributes(attrMap, subAtPresent)
	if len(atParams) != 3 {
		t.Errorf("Incorrect AttributeParam list")
	}

	nameParam := findAtParam("name", atParams)

	count := 0
	for _, k := range nameParam.SubAts {
		if k == "formatted" || k == "givenname" {
			count++
		}
	}

	if count != 2 {
		t.Errorf("Incorrect children of the complex attribute %s", nameParam.Name)
	}

	// check sub-attribute grouping WITHOUT the parent attribute
	attrMap, subAtPresent = SplitAttrCsv("id, userName, name.formatted, Name.GIVEnname, namename.name", restypes...)
	if !(attrMap["username"] == 1 && attrMap["name.givenname"] == 1 && attrMap["name.formatted"] == 1 && attrMap["namename.name"] == 1) {
		t.Errorf("Incorrect sub-attribute parsing")
	}

	if !subAtPresent {
		t.Errorf("The subAtPresent flag must be true")
	}

	atParams = ConvertToParamAttributes(attrMap, subAtPresent)
	if len(atParams) != 4 {
		t.Errorf("Incorrect AttributeParam list")
	}

	nameParam = findAtParam("name", atParams)

	count = 0
	for _, k := range nameParam.SubAts {
		if k == "formatted" || k == "givenname" {
			count++
		}
	}

	if count != 2 {
		t.Errorf("Incorrect children of the complex attribute %s", nameParam.Name)
	}
}

func TestParseAttrsWithUrn(t *testing.T) {
	attrMap, subAtPresent := SplitAttrCsv("urn:ietf:params:SCIM:schemas:corE:2.0:UseR:userName, urn:ietf:params:SCIM:schemas:corE:2.0:UseR:name.formatted, urn:ietf:params:SCIM:schemas:corE:2.0:UseR:Name, urn:ietf:params:SCIM:schemas:corE:2.0:UseR:Name.GIVEnname, urn:ietf:params:scim:schemas:extension:ENTERPRISE:2.0:User:employeeNumber", restypes...)
	if !(attrMap["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeenumber"] == 1 && attrMap["username"] == 1 && attrMap["name"] == 1 && attrMap["name.formatted"] == 1 && attrMap["name.givenname"] == 1) {
		t.Errorf("Incorrect extensions attribute parsing")
	}

	if !subAtPresent {
		t.Errorf("The subAtPresent flag must be true")
	}

	atParams := ConvertToParamAttributes(attrMap, subAtPresent)
	if len(atParams) != 3 {
		t.Errorf("Incorrect AttributeParam list")
	}

	nameParam := findAtParam("name", atParams)
	count := 0
	for _, k := range nameParam.SubAts {
		if k == "formatted" || k == "givenname" {
			count++
		}
	}

	if count != 0 {
		t.Errorf("Incorrect children of the complex attribute %s", nameParam.Name)
	}

	nameParam = findAtParam("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeenumber", atParams)
	if nameParam == nil {
		t.Errorf("Could not find employeenumber attrubute")
	}
}

func TestParseAttrsWithWildcard(t *testing.T) {
	attrMap, subAtPresent := SplitAttrCsv("name.*", restypes...)
	if !(attrMap["name"] == 1) {
		t.Errorf("Incorrect wildcard attribute parsing")
	}

	atParams := ConvertToParamAttributes(attrMap, subAtPresent)
	if len(atParams) != 1 {
		t.Errorf("Incorrect AttributeParam list")
	}

	nameParam := findAtParam("name", atParams)
	if len(nameParam.SubAts) != 0 { //the complete name attribute is requested so no children are explicitly mentioned
		t.Errorf("Incorrect children of the complex attribute %s", nameParam.Name)
	}

	attrMap, subAtPresent = SplitAttrCsv("urn:ietf:params:scim:schemas:core:2.0:User:*, emails.type", restypes...)
	atTypeCount := len(rTypesMap["User"].GetMainSchema().Attributes)

	atParams = ConvertToParamAttributes(attrMap, subAtPresent)
	if len(atParams) != atTypeCount {
		t.Errorf("Incorrect AttributeParam list, must include all attributes of core User schema")
	}

	attrMap, subAtPresent = SplitAttrCsv("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:*, emails.type", restypes...)
	atTypeCount = len(rTypesMap["User"].GetSchema("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User").Attributes) + 1 // include core User schema's 'emails'

	atParams = ConvertToParamAttributes(attrMap, subAtPresent)
	if len(atParams) != (atTypeCount) {
		t.Errorf("Incorrect AttributeParam list, must include all attributes of enterprise User extension schema + emails")
	}

	attrMap, subAtPresent = SplitAttrCsv("*, emails.type", restypes...)
	allAtTypeCount := 0
	for _, v := range rTypesMap {
		c := getAtTypeCount(v)
		log.Debugf("resource %s has %d attributes", v.Endpoint, c)
		allAtTypeCount += c
	}

	atParams = ConvertToParamAttributes(attrMap, subAtPresent)
	if len(atParams) != allAtTypeCount {
		t.Errorf("Incorrect AttributeParam list, must include all attributes of all resource types")
	}

	attrMap, subAtPresent = SplitAttrCsv("emails.type, *", restypes...) //reverse the position of wildcard
	atParams = ConvertToParamAttributes(attrMap, subAtPresent)
	if len(atParams) != allAtTypeCount {
		t.Errorf("Incorrect AttributeParam list, must include all attributes of all resource types")
	}
}

func findAtParam(name string, atParams map[string]*AttributeParam) *AttributeParam {
	return atParams[name]
}

func getAtTypeCount(rt *schema.ResourceType) int {
	count := len(rt.GetMainSchema().Attributes)
	for _, se := range rt.SchemaExtensions {
		count += len(rt.GetSchema(se.Schema).Attributes)
	}

	return count
}

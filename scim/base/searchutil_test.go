package base

import (
	"fmt"
	"os"
	"sparrow/scim/schema"
	"testing"
)

var restypes []*schema.ResourceType

func TestMain(m *testing.M) {
	resDir, _ := os.Getwd()
	resDir += "/../../"
	resDir = resDir + "/resources/"
	schemaDir := resDir + "/schemas"
	rtDir := resDir + "/types"

	schemas, _ := LoadSchemas(schemaDir)
	rTypesMap, _, _ := LoadResTypes(rtDir, schemas)

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

	// check with sub attribute
	attrMap, subAtPresent = SplitAttrCsv("userName, name.formatted, Name, Name.GIVEnname, namename.name", restypes...)
	if !(attrMap["username"] == 1 && attrMap["name"] == 1 && attrMap["name.givenname"] == 1 && attrMap["name.formatted"] == 1 && attrMap["namename.name"] == 1) {
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
}

func TestParseAttrsWithUrn(t *testing.T) {
	attrMap, subAtPresent := SplitAttrCsv("urn:ietf:params:SCIM:schemas:corE:2.0:UseR:userName, urn:ietf:params:SCIM:schemas:corE:2.0:UseR:name.formatted, urn:ietf:params:SCIM:schemas:corE:2.0:UseR:Name, urn:ietf:params:SCIM:schemas:corE:2.0:UseR:Name.GIVEnname, urn:ietf:params:scim:schemas:extension:ENTERPRISE:2.0:User:employeeNumber", restypes...)
	if !(attrMap["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeenumber"] == 1 && attrMap["username"] == 1 && attrMap["name"] == 1 && attrMap["name.formatted"] == 1 && attrMap["name.givenname"] == 1 && attrMap["name"] == 1) {
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

	if count != 2 {
		t.Errorf("Incorrect children of the complex attribute %s", nameParam.Name)
	}

	nameParam = findAtParam("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeenumber", atParams)
	if nameParam == nil {
		t.Errorf("Could not find employeenumber attrubute")
	}
}

func findAtParam(name string, atParams []*AttributeParam) *AttributeParam {
	for _, k := range atParams {
		if k.Name == name {
			return k
		}
	}

	return nil
}

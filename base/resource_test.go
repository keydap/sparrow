package base

import (
	"bytes"
	"fmt"
	"sparrow/schema"
	"testing"
)

var userResName = "User"
var uCount int64

func createTestUser() *Resource {
	var rt *schema.ResourceType
	for _, r := range restypes {
		if r.Name == userResName {
			rt = r
			break
		}
	}

	rs := NewResource(rt)

	uCount++

	username := fmt.Sprintf("user-%d", uCount)
	err := rs.AddSA("username", username)

	if err != nil {
		panic(err)
	}

	err = rs.AddSA("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", "1")

	if err != nil {
		panic(err)
	}

	nameMap := make(map[string]interface{})
	nameMap["formatted"] = "Formatted " + username
	nameMap["familyname"] = "Family " + username
	nameMap["givenName"] = "Given " + username
	nameMap["middleName"] = "Middle " + username

	err = rs.AddCA("name", nameMap)
	if err != nil {
		panic(err)
	}

	emails := make([]map[string]interface{}, 4)
	for emailCount := 1; emailCount <= 4; emailCount++ {
		emailMap := make(map[string]interface{})
		emailMap["value"] = fmt.Sprintf("b%d@example.com", emailCount)
		if emailCount > 1 && (emailCount&(emailCount-1) == 0) { // set "type" on even numbered emails
			emailMap["type"] = "home"
		}
		emails[emailCount-1] = emailMap
	}

	err = rs.AddCA("emails", emails...)
	if err != nil {
		panic(err)
	}

	return rs
}

func TestDeleteAttribute(t *testing.T) {
	rs := createTestUser()
	emails := rs.GetAttr("emails").GetComplexAt()

	if len(emails.SubAts) != 4 {
		t.Errorf("Incorrect initial set of emails")
	}

	del := rs.DeleteAttr("emails.value")

	if del == nil {
		t.Errorf("The return value of delete operation is nil")
	}

	if len(emails.SubAts) != 2 {
		t.Errorf("Incorrect set of emails after first delete")
	}

	// type is set at even positions so 1st and 3rd emails will be completely deleted
	// leading to resizing the slice of sub-attributes in emails
	for _, subAtMap := range emails.SubAts {
		if subAtMap["value"] != nil {
			t.Errorf("emails.type was not deleted from 2nd and 4th emails")
		}
	}

	del = rs.DeleteAttr("emails.type")

	if rs.GetAttr("emails") != nil {
		t.Errorf("emails attribute shouldn't exist after second delete")
	}

	del = rs.DeleteAttr("name.formatted")
	name := rs.GetAttr("name").GetComplexAt()
	if len(name.GetFirstSubAt()) != 3 {
		t.Error("Failed to delete the attribute name.formatted")
	}

	del = rs.DeleteAttr("name.xyz")

	if del != nil {
		t.Error("Unknown attriute cannot be deleted")
	}

	//fmt.Println(rs.ToJSON())

	del = rs.DeleteAttr("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber")
	if del == nil {
		t.Error("Could not delete extended attribute employeenumber")
	}
}

func TestNullValue(t *testing.T) {
	device := `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],
			  "manufacturer":"keydap",
			  "serialNumber":"11",
			  "price":null,
			  "repairDates": null,
			  "photos": null}`

	reader := bytes.NewReader([]byte(device))
	rs, err := ParseResource(rTypesMap, schemas, reader)
	if err != nil {
		t.Errorf("Parsing resource with null values should not fail %s", err)
	}

	at := rs.GetAttr("price")
	if at != nil {
		t.Errorf("price should be null")
	}

	at = rs.GetAttr("repairdates")
	if at != nil {
		t.Errorf("repairDates should be null")
	}

	at = rs.GetAttr("photos")
	if at != nil {
		t.Errorf("photos should be null")
	}

	// check with empty array values, those attributes should be ignored
	device = `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],
			  "manufacturer":"keydap",
			  "serialNumber":"11",
			  "repairDates": [],
			  "photos": []}`

	reader = bytes.NewReader([]byte(device))
	rs, _ = ParseResource(rTypesMap, schemas, reader)

	at = rs.GetAttr("repairdates")
	if at != nil {
		t.Errorf("repairDates should be null when empty array value was present")
	}

	at = rs.GetAttr("photos")
	if at != nil {
		t.Errorf("photos should be null when empty array value was present")
	}
}

func TestExtendedObjParsing(t *testing.T) {
	user := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
			  "userName":"bjensen@example.com",
			  "displayName":"Babs Jensen",
			"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": null}`

	reader := bytes.NewReader([]byte(user))
	rs, err := ParseResource(rTypesMap, schemas, reader)
	if err != nil {
		t.Errorf("Parsing resource with null values should not fail %s", err)
	}

	schemasAt := rs.GetAttr("schemas").GetSimpleAt()
	if len(schemasAt.Values) != 1 {
		t.Errorf("invalid number of schemas present in the resource")
	}

	user = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
			  "userName":"bjensen@example.com",
			  "displayName":"Babs Jensen",
    		  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {}}`

	reader = bytes.NewReader([]byte(user))
	rs, err = ParseResource(rTypesMap, schemas, reader)
	if err != nil {
		t.Errorf("Parsing resource with empty object value should not fail %s", err)
	}

	schemasAt = rs.GetAttr("schemas").GetSimpleAt()
	if len(schemasAt.Values) != 1 {
		t.Errorf("invalid number of schemas present in the resource")
	}

	user = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],     
			  "userName":"bjensen@example.com",
			  "displayName":"Babs Jensen",
    		  "urn:ietf:params:scim:schemas:bad-extension:uri:2.0:User": {}}`

	reader = bytes.NewReader([]byte(user))
	rs, err = ParseResource(rTypesMap, schemas, reader)
	if err == nil {
		t.Errorf("Parsing resource with unknown extended schema URI must fail")
	}
}

func TestMultiplePrimaryValues(t *testing.T) {
	device := `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],     
			  "manufacturer":"keydap",
			  "serialNumber":"11",
			  "photos": [{"value": "abc.jpg", "primary": true}, {"value": "xyz.jpg", "primary": true}]}`

	reader := bytes.NewReader([]byte(device))
	_, err := ParseResource(rTypesMap, schemas, reader)
	if err == nil {
		t.Errorf("Parsing resource with two primary sub-attribute values should fail")
	}
}

func TestEquals(t *testing.T) {
	device1 := `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],     
			  "manufacturer":"keydap",
			  "serialNumber":"11",
			  "rating": 1,
			  "price": 7.2,
			  "installedDate": "2016-05-17T14:19:14Z",
			  "repairDates": ["2016-05-15T14:19:14Z", "2016-05-16T14:19:14Z"],
			  "location": {"latitude": "17°10'45.4\"N", "longitude": "78°13'02.8\"E"}}`

	device2 := `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],     
			  "manufacturer":"keydap",
			  "serialNumber":"16",
			  "rating": 2,
			  "price": 9.2,
			  "installedDate": "2016-05-17T14:19:14Z",
			  "repairDates": ["2016-05-15T14:19:14Z", "2016-05-16T14:19:14Z"],
			  "location": {"latitude": "17°10'45.4\"N", "longitude": "78°13'02.8\"E"}}`

	reader := bytes.NewReader([]byte(device1))
	rs1, _ := ParseResource(rTypesMap, schemas, reader)

	reader = bytes.NewReader([]byte(device2))
	rs2, _ := ParseResource(rTypesMap, schemas, reader)

	checkEquals("manufacturer", rs1, rs2, true, t)
	checkEquals("serialNumber", rs1, rs2, false, t)
	checkEquals("rating", rs1, rs2, false, t)
	checkEquals("price", rs1, rs2, false, t)
	checkEquals("installedDate", rs1, rs2, true, t)
	checkEquals("repairDates", rs1, rs2, true, t)
}

func checkEquals(attrName string, rs1 *Resource, rs2 *Resource, expected bool, t *testing.T) {
	sa1 := rs1.GetAttr(attrName).GetSimpleAt()
	sa2 := rs2.GetAttr(attrName).GetSimpleAt()

	if sa1.Equals(sa2) != expected {
		t.Errorf("%s attributes' equality is not matching with the expected value", sa1.Name)
	}
}

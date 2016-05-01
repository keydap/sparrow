package base

import (
	"fmt"
	"sparrow/scim/schema"
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

	if !del {
		t.Errorf("The return value of delete operation is false")
	}

	if len(emails.SubAts) != 2 {
		t.Errorf("Incorrect set of emails after first delete")
	}

	// type is set at even positions so 1st and 3rd emails will be completely deleted
	// leading to resizing the slice of sub-attributes in emails
	if emails.SubAts[0]["value"] != nil && emails.SubAts[3]["type"] != nil {
		t.Errorf("emails.type was not deleted from 2nd and 4th emails")
	}

	del = rs.DeleteAttr("emails.type")

	if rs.GetAttr("emails") != nil {
		t.Errorf("emails attribute shouldn't exist after second delete")
	}

	del = rs.DeleteAttr("name.formatted")
	name := rs.GetAttr("name").GetComplexAt()
	if len(name.SubAts[0]) != 3 {
		t.Error("Failed to delete the attribute name.formatted")
	}

	del = rs.DeleteAttr("name.xyz")

	if del {
		t.Error("Unknown attriute cannot be deleted")
	}

	fmt.Println(rs.ToJSON())

	del = rs.DeleteAttr("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber")
	if !del {
		t.Error("Could not deleted extended attribute employeenumber")
	}
}

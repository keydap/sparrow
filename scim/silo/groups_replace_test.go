package silo

import (
	"bytes"
	"fmt"
	"sparrow/scim/base"
	"strings"
	"testing"
)

var groupTmpl = `{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				   "displayName": "Administrators"
				 }`

func parseGroupTmpl() *base.Resource {
	body := bytes.NewReader([]byte(groupTmpl))
	group, err := base.ParseResource(restypes, schemas, body)

	if err != nil {
		panic(err)
	}

	return group
}

func prepareGroup(resources ...*base.Resource) *base.Resource {

	group := parseGroupTmpl()

	for i, r := range resources {
		subAtMap := make(map[string]interface{})

		userId := r.GetId()
		if len(strings.TrimSpace(userId)) == 0 {
			panic(fmt.Errorf("User ID cannot be null while creating a group member"))
		}

		subAtMap["value"] = userId
		if i == 0 {
			group.AddCA("members", subAtMap)
		} else {
			ca := group.GetAttr("members").GetComplexAt()
			ca.AddSubAts(subAtMap)
		}
	}

	return group
}

func TestGroupAdd(t *testing.T) {
	initSilo()

	user := createTestUser()
	sl.Insert(user)

	group := prepareGroup(user)

	group, err := sl.Insert(group)
	if err != nil {
		t.Errorf("Failed to insert a group with user resource ID %s (%#v)", user.GetId(), err)
	}

	gid := group.GetId()

	user, _ = sl.Get(user.GetId(), userType)
	if !user.IsMemberOf(gid) {
		t.Errorf("User is not part of the expected group %s", gid)
	}
}

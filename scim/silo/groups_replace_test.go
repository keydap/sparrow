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

	user1 := createTestUser()
	sl.Insert(user1)

	user2 := createTestUser()
	sl.Insert(user2)

	u1Id := user1.GetId()
	u2Id := user2.GetId()

	group := prepareGroup(user1, user2)

	group, err := sl.Insert(group)
	if err != nil {
		t.Errorf("Failed to insert a group with users %s , %s (%#v)", u1Id, u2Id, err)
	}

	gid := group.GetId()

	assertIndexVal(groupType.Name, "members.value", u1Id, true, t)
	assertIndexVal(groupType.Name, "members.value", u2Id, true, t)

	user1, _ = sl.Get(u1Id, userType)
	if !user1.IsMemberOf(gid) {
		t.Errorf("User1 is not part of the expected group %s", gid)
	}

	user2, _ = sl.Get(u2Id, userType)
	if !user2.IsMemberOf(gid) {
		t.Errorf("User2 is not part of the expected group %s", gid)
	}

	assertIndexVal(userType.Name, "groups.value", gid, true, t)

	// remove the second user, after which he shouldn't be part of the group
	sl.Remove(u2Id, userType)

	// check index after removing User2
	assertIndexVal(groupType.Name, "members.value", u1Id, true, t)  // U1 should be present
	assertIndexVal(groupType.Name, "members.value", u2Id, false, t) // and U2 shouldn't in the Group's members

	group, _ = sl.Get(gid, groupType)
	if group.HasMember(u2Id) {
		t.Errorf("Deleted user %s is still a member of the group %s", u2Id, gid)
	}

	err = sl.Remove(gid, groupType)
	if err != nil {
		t.Errorf("Failed to delete the group %s", gid)
	}

	// no user should have the group association
	assertIndexVal(userType.Name, "groups.value", gid, false, t)

	// now the user shouldn't contain the group
	user1, _ = sl.Get(u1Id, userType)
	if user1.IsMemberOf(gid) {
		t.Errorf("User should not be part of the delete group %s", gid)
	}
}

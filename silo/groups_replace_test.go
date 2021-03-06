// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"bytes"
	"fmt"
	"sort"
	"sparrow/base"
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

func TestGroupAddAndDelete(t *testing.T) {
	initSilo()

	user1 := createTestUser()
	crUserCtx := &base.CreateContext{InRes: user1}
	sl.Insert(crUserCtx)

	user2 := createTestUser()
	crUserCtx2 := &base.CreateContext{InRes: user2}
	sl.Insert(crUserCtx2)

	u1Id := user1.GetId()
	u2Id := user2.GetId()

	_, err := sl.Get(u1Id, restypes[userResName])
	if err != nil {
		t.Errorf("failed to find the first user")
	}

	_, err = sl.Get(u2Id, restypes[userResName])
	if err != nil {
		t.Errorf("failed to find the first user")
	}

	group := prepareGroup(user1, user2)
	crGroupCtx := &base.CreateContext{InRes: group}
	err = sl.Insert(crGroupCtx)
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
	sl.Delete(&base.DeleteContext{Rid: u2Id, Rt: userType})

	// check index after removing User2
	assertIndexVal(groupType.Name, "members.value", u1Id, true, t)  // U1 should be present
	assertIndexVal(groupType.Name, "members.value", u2Id, false, t) // and U2 shouldn't in the Group's members

	group, _ = sl.Get(gid, groupType)
	if group.HasMember(u2Id) {
		t.Errorf("Deleted user %s is still a member of the group %s", u2Id, gid)
	}

	err = sl.Delete(&base.DeleteContext{Rid: gid, Rt: groupType})
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

func TestGroupInsertWithInvalidMember(t *testing.T) {
	initSilo()

	user1 := createTestUser()
	user1.SetId("non-inserted-user")

	group := prepareGroup(user1)
	crCtx := &base.CreateContext{InRes: group}
	err := sl.Insert(crCtx)
	if err == nil {
		t.Error("Group creation must fail when the member is not present")
	}
}

func TestGroupReplace(t *testing.T) {
	initSilo()

	user1 := createTestUser()
	crUserCtx1 := &base.CreateContext{InRes: user1}
	sl.Insert(crUserCtx1)

	user2 := createTestUser()
	crUserCtx2 := &base.CreateContext{InRes: user2}
	sl.Insert(crUserCtx2)

	u1Id := user1.GetId()
	u2Id := user2.GetId()

	group := prepareGroup(user1, user2)
	crGroupCtx := &base.CreateContext{InRes: group}
	err := sl.Insert(crGroupCtx)

	user3 := createTestUser()
	crUserCtx3 := &base.CreateContext{InRes: user3}
	sl.Insert(crUserCtx3)
	u3Id := user3.GetId()

	gid := group.GetId()

	group, _ = sl.Get(gid, groupType)

	group.RemoveMember(u2Id)

	ca := group.GetAttr("members").GetComplexAt()
	subAtMap := make(map[string]interface{})
	subAtMap["value"] = u3Id
	ca.AddSubAts(subAtMap)

	replaceCtx := &base.ReplaceContext{InRes: group, IfMatch: group.GetVersion()}
	err = sl.Replace(replaceCtx)
	if err != nil {
		t.Error("Failed to replace the group")
	}

	// now the group should have u1Id and u3Id
	group = replaceCtx.Res
	if !group.HasMember(u1Id) || !group.HasMember(u3Id) {
		t.Error("Expected users are not present in the group after replace operation")
	}

	if group.HasMember(u2Id) {
		t.Error("User2 shouldn't be a member of the group")
	}

	assertIndexVal(groupType.Name, "members.value", u1Id, true, t)  // U1 should be present
	assertIndexVal(groupType.Name, "members.value", u3Id, true, t)  // U3 should be present
	assertIndexVal(groupType.Name, "members.value", u2Id, false, t) // and U2 shouldn't in the Group's members
}

func TestPatchAdd(t *testing.T) {
	initSilo()

	user1 := createTestUser()
	crUserCtx1 := &base.CreateContext{InRes: user1}
	sl.Insert(crUserCtx1)

	user2 := createTestUser()
	crUserCtx2 := &base.CreateContext{InRes: user2}
	sl.Insert(crUserCtx2)

	u1Id := user1.GetId()
	u2Id := user2.GetId()

	group := prepareGroup(user1)
	crGroupCtx1 := &base.CreateContext{InRes: group}
	sl.Insert(crGroupCtx1)

	gid := group.GetId()

	// now patch the group
	pr := getPr(`{"Operations":[{"op":"add", "value":{"members":[{"value": "`+u2Id+`"}]}}]}`, groupType, group.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: gid, Rt: groupType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	group = patchCtx.Res
	if !group.HasMember(u2Id) {
		t.Error("User2 is not a member of the group")
	}

	assertIndexVal(groupType.Name, "members.value", u1Id, true, t)
	assertIndexVal(groupType.Name, "members.value", u2Id, true, t)

	user3 := createTestUser()
	crUserCtx3 := &base.CreateContext{InRes: user3}
	sl.Insert(crUserCtx3)

	u3Id := user3.GetId()

	// now patch the group with path set to members
	pr = getPr(`{"Operations":[{"op":"add", "path": "members", "value":{"value": "`+u3Id+`"}}]}`, groupType, group.GetVersion())
	patchCtx = &base.PatchContext{Pr: pr, Rid: gid, Rt: groupType}
	err = sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch add req with path")
	}

	if !patchCtx.Res.HasMember(u3Id) {
		t.Error("User3 is not a member of the group")
	}

	assertIndexVal(groupType.Name, "members.value", u1Id, true, t)
	assertIndexVal(groupType.Name, "members.value", u2Id, true, t)
	assertIndexVal(groupType.Name, "members.value", u3Id, true, t)

	checkGroupIndex(gid, t, u1Id, u2Id, u3Id)
}

func TestPatchReplace(t *testing.T) {
	initSilo()

	user1 := createTestUser()
	crUserCtx1 := &base.CreateContext{InRes: user1}
	sl.Insert(crUserCtx1)

	user2 := createTestUser()
	crUserCtx2 := &base.CreateContext{InRes: user2}
	sl.Insert(crUserCtx2)

	u1Id := user1.GetId()
	u2Id := user2.GetId()

	group := prepareGroup(user1)
	crGroupCtx := &base.CreateContext{InRes: group}
	sl.Insert(crGroupCtx)

	gid := group.GetId()

	checkGroupIndex(gid, t, u1Id)

	// now patch the group
	pr := getPr(`{"Operations":[{"op":"replace", "value":{"members":[{"value": "`+u2Id+`"}]}}]}`, groupType, group.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: gid, Rt: groupType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	group = patchCtx.Res
	if !group.HasMember(u2Id) {
		t.Error("User2 is not a member of the group")
	}

	// User1 should not be present anymore as a member
	if group.HasMember(u1Id) {
		t.Error("User1 is still a member of the group after replace operation")
	}

	checkGroupIndex(gid, t, u2Id)

	assertIndexVal(groupType.Name, "members.value", u1Id, false, t)
	assertIndexVal(groupType.Name, "members.value", u2Id, true, t)

	user3 := createTestUser()
	crUserCtx3 := &base.CreateContext{InRes: user3}
	sl.Insert(crUserCtx3)

	u3Id := user3.GetId()

	// now patch the group with path set to members
	pr = getPr(`{"Operations":[{"op":"replace", "path": "members", "value":[{"value": "`+u3Id+`"}, {"value": "`+u1Id+`"}]}]}`, groupType, group.GetVersion())
	patchCtx = &base.PatchContext{Pr: pr, Rid: gid, Rt: groupType}
	err = sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch add req with path")
	}

	group = patchCtx.Res
	if !group.HasMember(u3Id) || !group.HasMember(u1Id) {
		t.Error("User3 is not a member of the group")
	}

	// User2 should not be present anymore as a member
	if group.HasMember(u2Id) {
		t.Error("User2 is still a member of the group after replace operation")
	}

	assertIndexVal(groupType.Name, "members.value", u1Id, true, t)
	assertIndexVal(groupType.Name, "members.value", u2Id, false, t)
	assertIndexVal(groupType.Name, "members.value", u3Id, true, t)

	checkGroupIndex(gid, t, u1Id, u3Id)
}

func TestPatchRemove(t *testing.T) {
	initSilo()

	user1 := createTestUser()
	crUserCtx1 := &base.CreateContext{InRes: user1}
	sl.Insert(crUserCtx1)

	user2 := createTestUser()
	crUserCtx2 := &base.CreateContext{InRes: user2}
	sl.Insert(crUserCtx2)

	user3 := createTestUser()
	crUserCtx3 := &base.CreateContext{InRes: user3}
	sl.Insert(crUserCtx3)

	u1Id := user1.GetId()
	u2Id := user2.GetId()
	u3Id := user3.GetId()

	group := prepareGroup(user1, user2, user3)
	crGroupCtx := &base.CreateContext{InRes: group}
	sl.Insert(crGroupCtx)

	gid := group.GetId()

	checkGroupIndex(gid, t, u1Id, u2Id, u3Id)

	// now patch the group with path set to members
	pr := getPr(`{"Operations":[{"op":"remove", "path": "members[value eq `+u3Id+`]"}]}`, groupType, group.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: gid, Rt: groupType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch add req with path")
	}

	group = patchCtx.Res
	if !group.HasMember(u1Id) || !group.HasMember(u2Id) {
		t.Error("User3 is not a member of the group")
	}

	// User3 should not be present anymore as a member
	if group.HasMember(u3Id) {
		t.Error("User3 is still a member of the group after remove operation")
	}

	assertIndexVal(groupType.Name, "members.value", u1Id, true, t)
	assertIndexVal(groupType.Name, "members.value", u2Id, true, t)
	assertIndexVal(groupType.Name, "members.value", u3Id, false, t)

	checkGroupIndex(gid, t, u1Id, u2Id)
}

// Checks if the expected User resource IDs are present in the groups.value index
// This function checks for the exact number of expected UIDs in the index.
// If the index has more than one element and a single UID needs to be checked then
// use assertIndexVal()
func checkGroupIndex(gid string, t *testing.T, expectedUids ...string) {
	idx := sl.getIndex(userType.Name, "groups.value")
	tx, _ := sl.db.Begin(false)
	actualUids := idx.GetRids([]byte(gid), tx)
	tx.Rollback()

	eLen := len(expectedUids)
	aLen := len(actualUids)
	if aLen != eLen {
		panic(fmt.Errorf("Expected number of users(%d) is different from the actual number of users (%d)", eLen, aLen))
	}

	sort.Strings(actualUids)

	for _, v := range expectedUids {
		pos := sort.SearchStrings(actualUids, v)
		//fmt.Println(pos, v)
		if pos == aLen {
			panic(fmt.Errorf("Expected user %s is not present in the groups.value index", v))
		}
	}
}

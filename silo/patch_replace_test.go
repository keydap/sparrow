// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"fmt"
	"sparrow/base"
	"sparrow/utils"
	"testing"
)

func TestPatchReplaceSimpleAts(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"replace", "value":{"installedDate": "2016-06-18T14:19:14Z"}}]}`, deviceType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs := patchCtx.Res
	assertIndexVal(deviceType.Name, "installedDate", utils.GetTimeMillis("2016-05-17T14:19:14Z"), false, t)
	assertIndexVal(deviceType.Name, "installedDate", utils.GetTimeMillis("2016-06-18T14:19:14Z"), true, t)

	// apply the same patch on the already updated resource, resource should not get modified
	err = sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	notUpdatedRs := patchCtx.Res
	originalMeta := updatedRs.GetMeta().GetFirstSubAt()
	newMeta := notUpdatedRs.GetMeta().GetFirstSubAt()

	assertEquals(t, "meta.created", notUpdatedRs, originalMeta["created"].Values[0])
	assertEquals(t, "meta.version", notUpdatedRs, fmt.Sprint(originalMeta["lastmodified"].Values[0]))
	if originalMeta["lastmodified"].Values[0] != newMeta["lastmodified"].Values[0] {
		t.Errorf("Patch operation modified though the attribute data is unchanged")
	}

	pr = getPr(`{"Operations":[{"op":"replace", "path": "location.latitude", "value": "20°10'45.4\"N"}]}`, deviceType, updatedRs.GetVersion())
	patchCtx2 := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err = sl.Patch(patchCtx2)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs = patchCtx2.Res
	assertIndexVal(deviceType.Name, "location.latitude", "19°10'45.4\"N", false, t)
	assertIndexVal(deviceType.Name, "location.latitude", "20°10'45.4\"N", true, t)

	pr = getPr(`{"Operations":[{"op":"replace", "path": "macId", "value": "6A"}]}`, deviceType, updatedRs.GetVersion())
	patchCtx3 := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err = sl.Patch(patchCtx3)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs = patchCtx3.Res
	macId := updatedRs.GetAttr("macId").GetSimpleAt().Values[0].(string)
	if macId != "6A" {
		t.Error("macId attribute was not added")
	}
}

func TestAddMultiValuedSubAt(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"replace", "path": "photos.display", "value": "photo display"}]}`, deviceType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs := patchCtx.Res
	photos := updatedRs.GetAttr("photos").GetComplexAt()
	for _, subAtMap := range photos.SubAts {
		val := subAtMap["display"].Values[0].(string)
		if val != "photo display" {
			t.Errorf("Failed to add display value of photos attribute")
		}
	}
}

func TestReplaceSingleCA(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"replace", "path": "location", "value": {"latitude": "20°10'45.4\"N", "desc": "kodihalli"}}]}`, deviceType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs := patchCtx.Res
	assertIndexVal(deviceType.Name, "location.latitude", "19°10'45.4\"N", false, t)
	assertIndexVal(deviceType.Name, "location.latitude", "20°10'45.4\"N", true, t)

	desc := updatedRs.GetAttr("location.desc").GetSimpleAt().Values[0].(string)
	if desc != "kodihalli" {
		t.Error("desc attribute was not added")
	}

}

/*
   o  If the target location is a multi-valued attribute and a value
      selection ("valuePath") filter is specified that matches one or
      more values of the multi-valued attribute, then all matching
      record values SHALL be replaced.
*/
func TestReplaceMultiCA(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"replace", "path": "photos[value pr]", "value": {"value": "1.jpg", "display": "added display"}}]}`, deviceType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs := patchCtx.Res
	assertIndexVal(deviceType.Name, "photos.value", "abc.jpg", false, t)
	assertIndexVal(deviceType.Name, "photos.value", "xyz.jpg", false, t)
	assertIndexVal(deviceType.Name, "photos.value", "1.jpg", true, t)

	displayAt := updatedRs.GetAttr("photos").GetComplexAt()
	for _, subAtMap := range displayAt.SubAts {
		display := subAtMap["display"].Values[0].(string)
		if display != "added display" {
			t.Error("display attribute was not added")
		}
	}
}

/*
   o  If the target location is a complex multi-valued attribute with a
      value selection filter ("valuePath") and a specific sub-attribute
      (e.g., "addresses[type eq "work"].streetAddress"), the matching
      sub-attribute of all matching records is replaced.
*/
func TestMultival(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"replace", "path": "photos[value pr].display", "value": "this is a photo"}]}`, deviceType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs := patchCtx.Res
	photos := updatedRs.GetAttr("photos").GetComplexAt()
	for _, saMap := range photos.SubAts {
		display := saMap["display"].Values[0].(string)
		if display != "this is a photo" {
			t.Error("display attribute was not added")
		}
	}
}

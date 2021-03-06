// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"fmt"
	"sparrow/base"
	"sparrow/utils"
	"testing"
)

func TestPatchRemoveSimpleAts(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"remove", "path": "installedDate"}]}`, deviceType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs := patchCtx.Res
	if updatedRs.GetAttr("installedDate") != nil {
		t.Errorf("installedDate attribute should be removed, but it is still present")
	}

	assertIndexVal(deviceType.Name, "installedDate", utils.GetTimeMillis("2016-05-17T14:19:14Z"), false, t)

	// apply the same patch on the already updated resource, resource should not get modified
	pr.IfMatch = updatedRs.GetVersion()
	patchCtx2 := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err = sl.Patch(patchCtx2)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	notUpdatedRs := patchCtx2.Res
	originalMeta := updatedRs.GetMeta().GetFirstSubAt()
	newMeta := notUpdatedRs.GetMeta().GetFirstSubAt()

	assertEquals(t, "meta.created", notUpdatedRs, originalMeta["created"].Values[0])
	assertEquals(t, "meta.version", notUpdatedRs, fmt.Sprint(originalMeta["version"].Values[0]))
	if originalMeta["lastmodified"].Values[0] != newMeta["lastmodified"].Values[0] {
		t.Errorf("Patch operation modified though the attribute data is unchanged")
	}

	pr = getPr(`{"Operations":[{"op":"remove", "path": "location.LatiTude"}]}`, deviceType, updatedRs.GetVersion())
	patchCtx3 := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err = sl.Patch(patchCtx3)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs = patchCtx3.Res
	assertIndexVal(deviceType.Name, "location.latitude", "19°10'45.4\"N", false, t)

	pr = getPr(`{"Operations":[{"op":"remove", "path": "photos[value eq \"abc.jpg\"].value"}]}`, deviceType, updatedRs.GetVersion())
	patchCtx4 := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err = sl.Patch(patchCtx4)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs = patchCtx4.Res
	assertIndexVal(deviceType.Name, "photos.value", "abc.jpg", false, t)
	assertIndexVal(deviceType.Name, "photos.value", "xyz.jpg", true, t)

	photos := updatedRs.GetAttr("photos").GetComplexAt()
	if len(photos.SubAts) != 2 {
		t.Errorf("Failed to delete the photo using value based selector")
	}
}

func TestPatchRemoveComplexAt(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"remove", "path": "repairDates"}]}`, deviceType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs := patchCtx.Res
	if updatedRs.GetAttr("repairDates") != nil {
		t.Errorf("repairDates attribute should be removed, but it is still present")
	}

	assertIndexVal(deviceType.Name, "repairDates", utils.GetTimeMillis("2016-05-10T14:19:14Z"), false, t)
	assertIndexVal(deviceType.Name, "repairDates", utils.GetTimeMillis("2016-05-11T14:19:14Z"), false, t)

	// multi-valued CA
	pr = getPr(`{"Operations":[{"op":"remove", "path": "photos[primary eq true]"}]}`, deviceType, updatedRs.GetVersion())
	patchCtx2 := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err = sl.Patch(patchCtx2)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs = patchCtx2.Res
	assertIndexVal(deviceType.Name, "photos.value", "abc.jpg", false, t)
	assertIndexVal(deviceType.Name, "photos.value", "xyz.jpg", true, t)

	photos := updatedRs.GetAttr("photos").GetComplexAt()
	if len(photos.SubAts) != 1 {
		t.Errorf("Failed to delete the primary photo")
	}
}

func TestPatchRemoveMultipleVals(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"remove", "path": "photos.value"}]}`, deviceType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: rs.GetType()}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	updatedRs := patchCtx.Res
	assertIndexVal(deviceType.Name, "photos.value", "abc.jpg", false, t)
	assertIndexVal(deviceType.Name, "photos.value", "xyz.jpg", false, t)

	photos := updatedRs.GetAttr("photos").GetComplexAt()
	for _, subAtMap := range photos.SubAts {
		if _, ok := subAtMap["value"]; ok {
			t.Error("value sub-attribute should not be present")
		}
	}
}

func TestPatchRemoveReadOnly(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	rid := rs.GetId()
	checkRemoveFailure(t, rid, `{"Operations":[{"op":"remove", "path": "id"}]}`, rs)           // mandatory field
	checkRemoveFailure(t, rid, `{"Operations":[{"op":"remove", "path": "schemas"}]}`, rs)      // mandatory field
	checkRemoveFailure(t, rid, `{"Operations":[{"op":"remove", "path": "serialNumber"}]}`, rs) // required field
	checkRemoveFailure(t, rid, `{"Operations":[{"op":"remove", "path": "macId"}]}`, rs)        // immutable field
}

func TestPatchRemoveExtensionAts(t *testing.T) {
	initSilo()

	rs := insertRs(patchUser)
	pr := getPr(`{"Operations":[{"op":"add", "value":
	               {"urn:keydap:params:scim:schemas:extension:authentication:2.0:User": {"twofactortype": "totp"}}}]}`, userType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: rs.GetType()}
	err := sl.Patch(patchCtx)
	if err != nil {
		t.Errorf("Failed to apply patch req with extended object")
	}
	updatedRs := patchCtx.Res
	assertEquals(t, "twofactortype", updatedRs, "totp")

	// patch user with a new extension's data while using the URN as path
	pr = getPr(`{"Operations":[{"op":"remove","path":"urn:keydap:params:scim:schemas:extension:authentication:2.0:User:twofactortype"}]}`, userType, updatedRs.GetVersion())
	patchCtx2 := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: rs.GetType()}
	err = sl.Patch(patchCtx2)
	if err != nil {
		t.Errorf("Failed to apply patch req with extended object")
	}

	updatedRs = patchCtx2.Res
	twofactortypeAt := updatedRs.GetAttr("twofactortype")
	if twofactortypeAt != nil {
		t.Errorf("Failed to delete the twofactortype attribute from an extension schema")
	}

	scIds := updatedRs.GetAttr("schemas").GetSimpleAt()
	t.Log(scIds.Values)
	if len(scIds.Values) != 1 {
		t.Errorf("Failed to exclude the extension schema's URN in the schemas array of updated resource")
	}

}

func checkRemoveFailure(t *testing.T, rid string, patchJson string, rs *base.Resource) {
	pr := getPr(patchJson, deviceType, rs.GetVersion())
	patchCtx := &base.PatchContext{Pr: pr, Rid: rs.GetId(), Rt: deviceType}
	err := sl.Patch(patchCtx)
	se := err.(*base.ScimError)
	if se == nil {
		msg := fmt.Sprintf("Failed to return error when attempted to delete path %s", pr.Operations[0].Path)
		panic(msg)
	}
}

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

	updatedRs, err := sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	if updatedRs.GetAttr("installedDate") != nil {
		t.Errorf("installedDate attribute should be removed, but it is still present")
	}

	assertIndexVal(deviceType.Name, "installedDate", utils.GetTimeMillis("2016-05-17T14:19:14Z"), false, t)

	// apply the same patch on the already updated resource, resource should not get modified
	pr.IfNoneMatch = updatedRs.GetVersion()
	notUpdatedRs, err := sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	originalMeta := updatedRs.GetMeta().GetFirstSubAt()
	newMeta := notUpdatedRs.GetMeta().GetFirstSubAt()

	assertEquals(t, "meta.created", notUpdatedRs, originalMeta["created"].Values[0])
	assertEquals(t, "meta.version", notUpdatedRs, fmt.Sprint(originalMeta["version"].Values[0]))
	if originalMeta["lastmodified"].Values[0] != newMeta["lastmodified"].Values[0] {
		t.Errorf("Patch operation modified though the attribute data is unchanged")
	}

	pr = getPr(`{"Operations":[{"op":"remove", "path": "location.LatiTude"}]}`, deviceType, updatedRs.GetVersion())

	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	assertIndexVal(deviceType.Name, "location.latitude", "19°10'45.4\"N", false, t)

	pr = getPr(`{"Operations":[{"op":"remove", "path": "photos[value eq \"abc.jpg\"].value"}]}`, deviceType, updatedRs.GetVersion())

	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

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

	updatedRs, err := sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	if updatedRs.GetAttr("repairDates") != nil {
		t.Errorf("repairDates attribute should be removed, but it is still present")
	}

	assertIndexVal(deviceType.Name, "repairDates", utils.GetTimeMillis("2016-05-10T14:19:14Z"), false, t)
	assertIndexVal(deviceType.Name, "repairDates", utils.GetTimeMillis("2016-05-11T14:19:14Z"), false, t)

	// multi-valued CA
	pr = getPr(`{"Operations":[{"op":"remove", "path": "photos[primary eq true]"}]}`, deviceType, updatedRs.GetVersion())

	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

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

	updatedRs, err := sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

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

func checkRemoveFailure(t *testing.T, rid string, patchJson string, rs *base.Resource) {
	pr := getPr(patchJson, deviceType, rs.GetVersion())
	_, err := sl.Patch(rid, pr, deviceType)
	se := err.(*base.ScimError)
	if se == nil {
		msg := fmt.Sprintf("Failed to return error when attempted to delete path %s", pr.Operations[0].Path)
		panic(msg)
	}
}

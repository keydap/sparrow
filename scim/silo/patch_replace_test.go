package silo

import (
	"fmt"
	"sparrow/scim/utils"
	"testing"
)

func estPatchReplaceSimpleAts(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"remove", "path": "installedDate"}]}`)

	updatedRs, err := sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	if updatedRs.GetAttr("installedDate") != nil {
		t.Errorf("installedDate attribute should be removed, but it is still present")
	}

	assertIndexVal(deviceType.Name, "installedDate", utils.GetTimeMillis("2016-05-17T14:19:14Z"), false, t)

	// apply the same patch on the already updated resource, resource should not get modified
	notUpdatedRs, err := sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	originalMeta := updatedRs.GetMeta().SubAts[0]
	newMeta := notUpdatedRs.GetMeta().SubAts[0]

	assertEquals(t, "meta.created", notUpdatedRs, originalMeta["created"].Values[0])
	assertEquals(t, "meta.version", notUpdatedRs, fmt.Sprint(originalMeta["lastmodified"].Values[0]))
	if originalMeta["lastmodified"].Values[0] != newMeta["lastmodified"].Values[0] {
		t.Errorf("Patch operation modified though the attribute data is unchanged")
	}

	pr = getPr(`{"Operations":[{"op":"remove", "path": "location.latitude"}]}`)

	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}

	assertIndexVal(deviceType.Name, "location.latitude", "19°10'45.4\"N", false, t)

	pr = getPr(`{"Operations":[{"op":"remove", "path": "photos[value eq \"abc.jpg\"].value"}]}`)

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

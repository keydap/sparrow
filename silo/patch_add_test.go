// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"bytes"
	"fmt"
	"sparrow/base"
	"sparrow/schema"
	"sparrow/utils"
	"testing"
)

var patchDevice = `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],     
			  "manufacturer":"keydap",
			  "serialNumber":"11",
			  "rating": 1,
			  "price": 7.2,
			  "installedDate": "2016-05-17T14:19:14Z",
			  "repairDates": ["2016-05-10T14:19:14Z", "2016-05-11T14:19:14Z"],
			  "location": {"latitude": "1.1", "longitude": "2.2"},
			  "photos": [{"value": "abc.jpg", "primary": true}, {"value": "xyz.jpg", "primary": false}]}`

var patchUser = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],     
			  "userName":"bjensen@example.com",
			  "displayName":"Babs Jensen"}`

func TestPatchAddSimpleAts(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	pr := getPr(`{"Operations":[{"op":"add", "value":{"price": 9.2, "rating": 1}}]}`, deviceType, rs.GetVersion())

	updatedRs, err := sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req")
	}
	assertEquals(t, "price", updatedRs, float64(9.2))
	assertIndexVal(deviceType.Name, "price", float64(7.2), false, t)
	assertIndexVal(deviceType.Name, "price", float64(9.2), true, t)

	assertEquals(t, "rating", updatedRs, int64(1))
	assertIndexVal(deviceType.Name, "rating", int64(1), true, t)

	// apply the same patch on the already updated resource, resource should not get modified
	pr.IfMatch = updatedRs.GetVersion()
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

	assertEquals(t, "price", updatedRs, float64(9.2))
	assertEquals(t, "rating", updatedRs, int64(1))

	// without path, give Value an array instead of a map
	pr = getPr(`{"Operations":[{"op":"add", "value":[{"price": 9.2, "rating": 1}]}]}`, deviceType, updatedRs.GetVersion())
	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err == nil {
		t.Errorf("Patch operation must fail when path is not given and Value is an array instead of an object")
	}

	// with path now
	sl.Delete(rs.GetId(), deviceType)

	rs = insertRs(patchDevice)
	pr = getPr(`{"Operations":[{"op":"add", "path":"price", "value":10.6}]}`, deviceType, rs.GetVersion())

	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req with path")
	}

	assertEquals(t, "price", updatedRs, float64(10.6))
	assertIndexVal(deviceType.Name, "price", float64(7.2), false, t)
	assertIndexVal(deviceType.Name, "price", float64(9.2), false, t) // just to ensure the old value is not lingering even after deleting the resource
	assertIndexVal(deviceType.Name, "price", float64(10.6), true, t)

	// test multi-valued simple attribute with path
	pr = getPr(`{"Operations":[{"op":"add", "path":"repairDates", "value":"2016-05-28T14:19:14Z"}]}`, deviceType, updatedRs.GetVersion())
	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req with path on a multivalued simple attribute %s", err)
	}

	millis := utils.GetTimeMillis("2016-05-28T14:19:14Z")
	assertEquals(t, "repairDates", updatedRs, millis)
	assertIndexVal(deviceType.Name, "repairDates", millis, true, t)

	pr = getPr(`{"Operations":[{"op":"add", "path":"repairDates", "value":["2016-05-29T14:19:14Z"]}]}`, deviceType, updatedRs.GetVersion())
	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req with path on a multivalued simple attribute %s", err)
	}

	millis = utils.GetTimeMillis("2016-05-29T14:19:14Z")
	assertEquals(t, "repairDates", updatedRs, millis)
	assertIndexVal(deviceType.Name, "repairDates", millis, true, t)

	// try to add more photos using patch
	prevVersion := updatedRs.GetVersion()

	pr = getPr(`{"Operations":[{"op":"add", "path":"photos", "value":[{"value": "yet-another-pic.jpg", "primary": false}]}]}`, deviceType, updatedRs.GetVersion())
	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req with path on a multivalued photos attribute %s", err)
	}

	assertIndexVal(deviceType.Name, "photos.value", "yet-another-pic.jpg", true, t)
	assertIndexVal(deviceType.Name, "photos.value", "abc.jpg", true, t)
	assertIndexVal(deviceType.Name, "photos.value", "xyz.jpg", true, t)

	curVersion := updatedRs.GetVersion()
	if prevVersion == curVersion {
		//FIXME for some reason go test ./... is not reporting
		// when t.Error() is called, using panic for now
		panic("Version should have been modified if the patch operation was successful")
	}

	prevVersion = curVersion

	pr = getPr(`{"Operations":[{"op":"add", "path":"photos", "value":[{}]}]}`, deviceType, updatedRs.GetVersion())
	updatedRs, err = sl.Patch(rs.GetId(), pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req with path on a multivalued photos attribute and empty value %s", err)
	}

	curVersion = updatedRs.GetVersion()
	if prevVersion != curVersion {
		panic("Version should NOT have been modified cause the patch operation didn't have any meaningful values")
	}
}

func TestModifyUniqueSimpleAt(t *testing.T) {
	initSilo()

	var device1 = `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],     
			  "manufacturer":"keydap",
			  "serialNumber":"20",
			  "rating": 1,
			  "price": 7.2,
			  "installedDate": "2016-05-17T14:19:14Z",
			  "repairDates": ["2016-05-10T14:19:14Z", "2016-05-11T14:19:14Z"],
			  "location": {"latitude": "1.1", "longitude": "2.2"},
			  "photos": [{"value": "abc.jpg", "primary": true}, {"value": "xyz.jpg", "primary": false}]}`

	// insert device1 first
	insertRs(device1)

	// next device to be patched
	rs := insertRs(patchDevice)
	rid := rs.GetId()

	// now define a patch operation which tries to change value of serialNumber to be that of device1
	pr := getPr(`{"Operations":[{"op":"add", "value":{"serialNumber": "20"}}]}`, deviceType, rs.GetVersion())

	// it must fail
	_, err := sl.Patch(rid, pr, deviceType)
	if err == nil {
		t.Errorf("Patch operation must fail due to uniqueness violation")
	}

	se := err.(*base.ScimError)
	if se.ScimType != base.ST_UNIQUENESS {
		t.Error("ScimType must be set to uniqueness")
	}
}

func TestPatchReadOnlyAT(t *testing.T) {

}

func TestPatchAddComplexAT(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	rid := rs.GetId()
	pr := getPr(`{"Operations":[{"op":"add", "value":{"location": {"latitude": "1.0", "longitude": "2.0"}}}]}`, deviceType, rs.GetVersion())

	updatedRs, err := sl.Patch(rid, pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req with complex attribute")
	}

	assertEquals(t, "location.latitude", updatedRs, "1.0")
	assertIndexVal(deviceType.Name, "location.latitude", "1.1", false, t)
	assertIndexVal(deviceType.Name, "location.latitude", "1.0", true, t)

	assertEquals(t, "location.longitude", updatedRs, "2.0")

	// apply the same patch on the already updated resource, resource should not get modified
	pr.IfMatch = updatedRs.GetVersion()
	notUpdatedRs, err := sl.Patch(rid, pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req on the already updated resource")
	}

	originalMeta := updatedRs.GetMeta().GetFirstSubAt()
	newMeta := notUpdatedRs.GetMeta().GetFirstSubAt()

	assertEquals(t, "meta.created", notUpdatedRs, originalMeta["created"].Values[0])
	assertEquals(t, "meta.version", notUpdatedRs, fmt.Sprint(originalMeta["version"].Values[0]))
	if originalMeta["lastmodified"].Values[0] != newMeta["lastmodified"].Values[0] {
		t.Errorf("Patch operation modified though the attribute data is unchanged")
	}

	//with path now
	pr = getPr(`{"Operations":[{"op":"add", "path":"location.latitude", "value":"5.0"}]}`, deviceType, updatedRs.GetVersion())

	updatedRs, err = sl.Patch(rid, pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req with path of complex attribute")
	}

	assertEquals(t, "location.latitude", updatedRs, "5.0")
	assertIndexVal(deviceType.Name, "location.latitude", "1.1", false, t)
	assertIndexVal(deviceType.Name, "location.latitude", "5.0", true, t)

	//path with a selector
	pr = getPr(`{"Operations":[{"op":"add", "path":"location[longitude eq \"2.0\"].latitude", "value":"7.0"}]}`, deviceType, updatedRs.GetVersion())

	updatedRs, err = sl.Patch(rid, pr, deviceType)
	if err != nil {
		t.Errorf("Failed to apply patch req with path of complex attribute")
	}

	assertEquals(t, "location.latitude", updatedRs, "7.0")
	assertIndexVal(deviceType.Name, "location.latitude", "5.0", false, t)
	assertIndexVal(deviceType.Name, "location.latitude", "7.0", true, t)

	//path with a selector
	pr = getPr(`{"Operations":[{"op":"add", "path":"location[longitude eq \"non-existing-val\"].latitude", "value":"9.0"}]}`, deviceType, updatedRs.GetVersion())

	updatedRs, err = sl.Patch(rid, pr, deviceType)
	if err == nil {
		t.Errorf("Modify operation must fail due to non-matching selector")
	}
	// old value should remain
	assertIndexVal(deviceType.Name, "location.latitude", "7.0", true, t)
}

// multivalued complex ATs
func TestPatchAddMultiValComplexAT(t *testing.T) {
	initSilo()

	rs := insertRs(patchDevice)
	rid := rs.GetId()
	pr := getPr(`{"Operations":[{"op":"add", "value":{"photos": [{"value": "123.jpg", "primary": true}, {"value": "456.jpg", "primary": true}]}}]}`, deviceType, rs.GetVersion())

	updatedRs, err := sl.Patch(rid, pr, deviceType)
	if err == nil {
		t.Errorf("Patch request should fail cause multiple primary flags were set")
	}

	pr = getPr(`{"Operations":[{"op":"add", "value":{"photos": [{"value": "123.jpg", "primary": true}, {"value": "456.jpg", "primary": false}]}}]}`, deviceType, rs.GetVersion())

	updatedRs, err = sl.Patch(rid, pr, deviceType)
	if err != nil {
		t.Errorf("Failed to add multivalued complex attribute to the resource")
	}

	photos := updatedRs.GetAttr("photos").GetComplexAt()
	for _, subAtMap := range photos.SubAts {
		if subAtMap["value"].Values[0].(string) == "123.jpg" {
			if !subAtMap["primary"].Values[0].(bool) {
				t.Errorf("the sub-attribute with value 123.jpg should be marked as primary")
			}
		}

		if subAtMap["value"].Values[0].(string) == "456.jpg" {
			if subAtMap["primary"].Values[0].(bool) {
				t.Errorf("the sub-attribute with value 456.jpg should NOT be marked as primary")
			}
		}
	}

	assertIndexVal(deviceType.Name, "photos.value", "123.jpg", true, t)
	assertIndexVal(deviceType.Name, "photos.value", "456.jpg", true, t)

	// with path now
	sl.Delete(rid, deviceType)
	rs = insertRs(patchDevice)
	rid = rs.GetId()
	pr = getPr(`{"Operations":[{"op":"add", "path": "photos[value eq \"xyz.jpg\"].primary", "value":true}]}`, deviceType, rs.GetVersion())

	updatedRs, err = sl.Patch(rid, pr, deviceType)
	if err != nil {
		t.Errorf("Patch request failed on a complex multi-valued attribute %#v", err)
	}

	photos = updatedRs.GetAttr("photos").GetComplexAt()
	for _, subAtMap := range photos.SubAts {
		if subAtMap["value"].Values[0].(string) == "abc.jpg" {
			if subAtMap["primary"].Values[0].(bool) {
				t.Errorf("the sub-attribute with value abc.jpg's primary flag should be set to false")
			}
		}

		if subAtMap["value"].Values[0].(string) == "xyz.jpg" {
			if !subAtMap["primary"].Values[0].(bool) {
				t.Errorf("the sub-attribute with value xyz.jpg' should be marked as primary")
			}
		}
	}
}

func TestPatchAddExtensionAts(t *testing.T) {
	initSilo()

	rs := insertRs(patchUser)
	pr := getPr(`{"Operations":[{"op":"add", "value":
	               {"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"employeeNumber": "1", "organization": "keydap" }}
    		     }]}`, userType, rs.GetVersion())

	updatedRs, err := sl.Patch(rs.GetId(), pr, userType)
	if err != nil {
		t.Errorf("Failed to apply patch req with extended object")
	}

	// patch user with a new extension's data while using the URN as path
	pr = getPr(`{"Operations":[{"op":"add", "path": "urn:keydap:params:scim:schemas:extension:authentication:2.0:User", "value":
	               {"twofactorType": "Totp"}
    		     }]}`, userType, updatedRs.GetVersion())

	updatedRs, err = sl.Patch(rs.GetId(), pr, userType)
	if err != nil {
		t.Errorf("Failed to apply patch req with extended object")
	}

	// add one more attribute to the container, this time individually instead of as an object
	pr = getPr(`{"Operations":[{"op":"add", "path": "urn:keydap:params:scim:schemas:extension:authentication:2.0:User:changepassword", "value":true}]}`, userType, updatedRs.GetVersion())

	updatedRs, err = sl.Patch(rs.GetId(), pr, userType)
	if err != nil {
		t.Errorf("Failed to apply patch req with new attribute in container")
	}
	assertEquals(t, "changepassword", updatedRs, true)

	scIds := updatedRs.GetAttr("schemas").GetSimpleAt()
	t.Log(scIds.Values)
	if len(scIds.Values) != 3 {
		t.Errorf("Failed to include the extension schema's URN in the schemas array of updated resource")
	}

	assertEquals(t, "employeeNumber", updatedRs, "1")
	assertEquals(t, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", updatedRs, "1")
	assertIndexVal(userType.Name, "employeeNumber", "1", true, t)

	// add a sub-attribute when parent is not present
	pr = getPr(`{"Operations":[{"op":"add", "path": "name.familyNamE", "value": "Mantha"}]}`, userType, updatedRs.GetVersion())
	updatedRs, err = sl.Patch(rs.GetId(), pr, userType)
	if err != nil {
		t.Errorf("Failed to apply patch req with sub-attribute")
	}

	assertEquals(t, "name.FamilyNamE", updatedRs, "Mantha")
}

func insertRs(json string) *base.Resource {
	reader := bytes.NewReader([]byte(json))
	rs, err := base.ParseResource(restypes, schemas, reader)
	if err != nil {
		panic(err)
	}

	rs, err = sl.Insert(rs)
	if err != nil {
		panic(err)
	}

	return rs
}

func getPr(pr string, rt *schema.ResourceType, version string) *base.PatchReq {
	reader := bytes.NewReader([]byte(pr))
	req, err := base.ParsePatchReq(reader, rt)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	req.IfMatch = version
	return req
}

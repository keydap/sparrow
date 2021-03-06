// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"bytes"
	"fmt"
	"sparrow/base"
	"sparrow/utils"
	"strings"
	"testing"
)

func TestReplace(t *testing.T) {
	initSilo()
	origDevice := `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],     
			  "manufacturer":"keydap",
			  "serialNumber":"11",
			  "rating": 1,
			  "price": 7.2,
			  "installedDate": "2016-05-17T14:19:14Z",
			  "repairDates": ["2016-05-10T14:19:14Z", "2016-05-11T14:19:14Z"],
			  "location": {"latitude": "19°10'45.4\"N", "longitude": "78°13'02.8\"E"},
			  "photos": [{"value": "abc.jpg", "primary": true}, {"value": "xyz.jpg", "primary": false}]}`

	upDevice := `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],     
			  "manufacturer":"keydap",
			  "serialNumber":"11",
			  "rating": 2,
			  "price": 9.2,
			  "macId": "abcd1",
			  "repairDates": ["2016-05-15T14:19:14Z", "2016-05-16T14:19:14Z"],
			  "location": {"latitude": "17°10'45.4\"N", "longitude": "78°13'02.8\"E"},
			  "photos": [{"value": "device1.jpg", "primary": false}, {"value": "device2.jpg", "primary": true}]}`

	reader := bytes.NewReader([]byte(origDevice))
	originalRs, _ := base.ParseResource(restypes, schemas, reader)
	crOriginalUserCtx := &base.CreateContext{InRes: originalRs}
	sl.Insert(crOriginalUserCtx)

	reader = bytes.NewReader([]byte(upDevice))
	upRs, _ := base.ParseResource(restypes, schemas, reader)
	upRs.SetId(originalRs.GetId())

	replaceCtx := &base.ReplaceContext{InRes: upRs, IfMatch: originalRs.GetVersion()}
	err := sl.Replace(replaceCtx)
	if err != nil {
		t.Errorf("Failed to replace resource %s", err)
	}

	newRs := replaceCtx.Res

	resName := newRs.GetType().Name

	originalMeta := originalRs.GetMeta().GetFirstSubAt()
	newMeta := newRs.GetMeta().GetFirstSubAt()

	assertEquals(t, "meta.created", newRs, originalMeta["created"].Values[0])
	assertEquals(t, "meta.version", newRs, fmt.Sprint(newMeta["version"].Values[0]))
	if originalMeta["lastmodified"].Values[0] == newMeta["lastmodified"].Values[0] {
		t.Errorf("Replace operation didn't modify value of meta.lastModified attribute")
	}

	assertEquals(t, "manufacturer", newRs, "keydap")
	assertEquals(t, "serialNumber", newRs, "11")
	assertIndexVal(resName, "serialNumber", "11", true, t)

	assertEquals(t, "rating", newRs, int64(2))
	assertIndexVal(resName, "rating", int64(1), false, t) // value before replacing
	assertIndexVal(resName, "rating", int64(2), true, t)  // value after replacing

	assertEquals(t, "price", newRs, float64(9.2))
	assertIndexVal(resName, "price", float64(7.2), false, t) // value before replacing
	assertIndexVal(resName, "price", float64(9.2), true, t)  // value after replacing

	if newRs.GetAttr("installeddate") != nil {
		t.Errorf("installedDate should be removed %#v", newRs.GetAttr("installeddate"))
	}
	assertIndexVal(resName, "installedDate", utils.GetTimeMillis("2016-05-17T14:19:14Z"), false, t) // value should be removed
	tx, _ := sl.db.Begin(false)
	if sl.getSysIndex(resName, "presence").HasVal("installedDate", tx) {
		t.Error("installedDate should be removed from presence index")
	}
	tx.Rollback()

	assertEquals(t, "repairDates", newRs, utils.GetTimeMillis("2016-05-15T14:19:14Z"), utils.GetTimeMillis("2016-05-16T14:19:14Z"))
	assertIndexVal(resName, "repairDates", utils.GetTimeMillis("2016-05-10T14:19:14Z"), false, t) // 1st value before replacing
	assertIndexVal(resName, "repairDates", utils.GetTimeMillis("2016-05-11T14:19:14Z"), false, t) // 2nd value before replacing

	assertIndexVal(resName, "repairDates", utils.GetTimeMillis("2016-05-15T14:19:14Z"), true, t) // 1st value after replacing
	assertIndexVal(resName, "repairDates", utils.GetTimeMillis("2016-05-16T14:19:14Z"), true, t) // 2nd value after replacing

	assertEquals(t, "location.latitude", newRs, "17°10'45.4\"N")
	assertIndexVal(resName, "location.latitude", "19°10'45.4\"N", false, t) // value before replacing
	assertIndexVal(resName, "location.latitude", "17°10'45.4\"N", true, t)  // value after replacing

	assertEquals(t, "location.longitude", newRs, "78°13'02.8\"E")
	assertEquals(t, "macid", newRs, "abcd1")

	assertIndexVal(resName, "photos.value", "abc.jpg", false, t)    // 1st value before replacing
	assertIndexVal(resName, "photos.value", "xyz.jpg", false, t)    // 2nd value before replacing
	assertIndexVal(resName, "photos.value", "device1.jpg", true, t) // 1st value after replacing
	assertIndexVal(resName, "photos.value", "device2.jpg", true, t) // 2nd value after replacing

	// try to update the immutable value
	upDevice2 := `{"schemas":["urn:keydap:params:scim:schemas:core:2.0:Device"],     
			  "manufacturer":"keydap",
			  "serialNumber":"11",
			  "rating": 2,
			  "price": 9.2,
			  "macId": "xyz2"}`
	reader = bytes.NewReader([]byte(upDevice2))
	upRs, _ = base.ParseResource(restypes, schemas, reader)
	upRs.SetId(originalRs.GetId())

	replaceCtx = &base.ReplaceContext{InRes: upRs, IfMatch: newRs.GetVersion()}
	err = sl.Replace(replaceCtx)
	if err == nil {
		t.Error("Replace operation must fail when an immutable attribute value already exists")
	}

	se := err.(*base.ScimError)

	if se.ScimType != base.ST_MUTABILITY || se.Status != base.BadRequest {
		t.Error("Invalid error returned for failed replace operation involving immutable attributes")
	}
}

func TestReplaceExtendedObj(t *testing.T) {
	initSilo()
	origUser := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],     
			  "userName":"bjensen@example.com",
			  "displayName":"Babs Jensen",
    		  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
    		   "employeeNumber": "1",
    		   "organization": "keydap"
    		  }}`

	upUser1 := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],     
			  "userName":"bjensen@example.com",
			  "displayName":"Babs Jensen"}`

	reader := bytes.NewReader([]byte(origUser))
	originalRs, _ := base.ParseResource(restypes, schemas, reader)
	crOriginalUserCtx := &base.CreateContext{InRes: originalRs}
	sl.Insert(crOriginalUserCtx)

	reader = bytes.NewReader([]byte(upUser1))
	upRs, _ := base.ParseResource(restypes, schemas, reader)
	upRs.SetId(originalRs.GetId())

	replaceCtx := &base.ReplaceContext{InRes: upRs, IfMatch: originalRs.GetVersion()}
	err := sl.Replace(replaceCtx)

	if err != nil {
		t.Errorf("Failed to replace user resource")
	}

	newRs := replaceCtx.Res
	rt := newRs.GetType()
	resName := rt.Name

	schemasAt := newRs.GetAttr("schemas").GetSimpleAt()
	if len(schemasAt.Values) != 1 && schemasAt.Values[0].(string) != rt.Schema {
		t.Error("Invalid schemas attribute after replacing")
	}

	assertIndexVal(resName, "employeeNumber", "1", false, t)
	assertIndexVal(resName, "organization", "keydap", false, t)

	upUser2 := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],     
			  "userName":"bjensen@example.com",
			  "displayName":"Babs Jensen",
    		  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
    		   "employeeNumber": "2",
    		   "organization": "keydap"
    		  }}`

	// replace again
	reader = bytes.NewReader([]byte(upUser2))
	upRs, _ = base.ParseResource(restypes, schemas, reader)
	upRs.SetId(originalRs.GetId())
	replaceCtx = &base.ReplaceContext{InRes: upRs, IfMatch: newRs.GetVersion()}
	err = sl.Replace(replaceCtx)
	if err != nil {
		t.Errorf("Failed to update second time %s", err)
	}

	assertIndexVal(resName, "employeeNumber", "2", true, t)
	assertIndexVal(resName, "organization", "keydap", true, t)

	assertEquals(t, "schemas", newRs, rt.Schema, rt.SchemaExtensions[0].Schema)
}

func assertIndexVal(resName string, attrPath string, val interface{}, expected bool, t *testing.T) {
	tx, err := sl.db.Begin(false)
	if err != nil {
		panic(err)
	}
	idx := sl.getIndex(resName, strings.ToLower(attrPath))
	actual := idx.HasVal(val, tx)
	tx.Rollback()
	if actual != expected {
		if expected {
			t.Errorf("Did not find the expected value %s in the index of attribute %s", val, attrPath)
		} else {
			t.Errorf("The unexpected value %s is still present in the index of attribute %s", val, attrPath)
		}
		panic("")
	}
}

func assertEquals(t *testing.T, attrPath string, rs *base.Resource, expected ...interface{}) {
	at := rs.GetAttr(attrPath)
	atType := at.GetType()

	matched := false

	if at.IsSimple() {
		sa := at.GetSimpleAt()
		if atType.MultiValued {
			count := len(sa.Values)
			for _, val := range sa.Values {
				for _, e := range expected {
					found := base.Compare(atType, val, e)
					if found {
						count--
						break
					}
				}
			}

			matched = (count == 0)

		} else {
			matched = base.Compare(atType, sa.Values[0], expected[0])
		}
	} else {
		panic(fmt.Errorf("Complex attributes cannot be asserted"))
	}

	if !matched {
		panic(fmt.Errorf("Failed to match %s with the expected value(s) %#v", attrPath, expected))
	}
}

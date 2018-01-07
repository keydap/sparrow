// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"encoding/json"
	"sparrow/schema"
	"strings"
)

type resOps struct {
	Ops []opsObj
}

type opsObj struct {
	Op         string
	AllowAttrs string
	DenyAttrs  string
	Filter     string
}

func ParseResPerms(group *Resource, resTypes map[string]*schema.ResourceType) map[string]*ResourcePermission {
	resPerms := make(map[string]*ResourcePermission)
	perms := group.GetAttr("permissions")
	if perms != nil {
		permSubAts := perms.GetComplexAt().SubAts
		for _, subAtMap := range permSubAts {
			resNameAt := subAtMap["resname"]
			opsObjAt := subAtMap["opsobj"]

			resName := resNameAt.Values[0].(string)
			opsObj := opsObjAt.Values[0].(string)

			rt := resTypes[resName]
			if rt == nil {
				log.Warningf("No resource type found with the name %s, ignoring permissions", resName)
				continue
			}

			rp := &ResourcePermission{RType: rt}
			rp.Perms, _ = parseOpsObj(opsObj, rt)
			resPerms[resName] = rp
		}
	}

	return resPerms
}

func parseOpsObj(opsObj string, rt *schema.ResourceType) (map[string]*Permission, error) {
	ro := &resOps{}

	err := json.Unmarshal([]byte(opsObj), ro)
	if err != nil {
		return nil, err
	}

	opsPerms := make(map[string]*Permission)
	for _, rop := range ro.Ops {
		p := &Permission{}
		rop.AllowAttrs = strings.TrimSpace(rop.AllowAttrs)
		if len(rop.AllowAttrs) != 0 {
			if rop.AllowAttrs == "*" {
				p.AllowAll = true
			} else {
				//p.AllowAttrs = make([]*schema.AttrType,0)
				parseAttrs(rop.AllowAttrs, rt)
			}
		}
		rop.DenyAttrs = strings.TrimSpace(rop.DenyAttrs)
		rop.Filter = strings.TrimSpace(rop.Filter)
	}

	return opsPerms, nil
}

func parseAttrs(attrCsv string, rt *schema.ResourceType) []*AttributeParam {
	attrMap, subAtPresent := SplitAttrCsv(attrCsv, rt)
	return ConvertToParamAttributes(attrMap, subAtPresent)
}

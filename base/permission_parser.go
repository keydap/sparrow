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
			opsPerms, err := parseOpsObj(opsObj, rt)
			if err != nil {
				log.Debugf("failed to parse the operation permissions %s", err)
				continue
			}

			rp.ReadPerm = opsPerms["read"] // the keys are lowered in the call to parseOpsObj
			rp.WritePerm = opsPerms["write"]
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
			if allAttrsRegex.MatchString(rop.AllowAttrs) {
				p.AllowAll = true
			} else {
				p.AllowAttrs = parseAttrs(rop.AllowAttrs, rt)
			}
		} else if len(rop.DenyAttrs) != 0 {
			rop.DenyAttrs = strings.TrimSpace(rop.DenyAttrs)
			if allAttrsRegex.MatchString(rop.DenyAttrs) {
				p.AllowAttrs = nil
			} else {
				deniedAttrMap := parseAttrs(rop.DenyAttrs, rt)
				// remove the denied attributes and mark the rest as allowed attributes
				p.AllowAttrs = filterDenied(deniedAttrMap, rt)
			}
		}

		rop.Filter = strings.TrimSpace(rop.Filter)
		if len(rop.Filter) > 0 {
			tmp := strings.ToUpper(rop.Filter)
			if "ANY" == tmp {
				p.OnAnyResource = true
			} else if "NONE" == tmp {
				p.OnNone = true
			} else {
				node, err := ParseFilter(rop.Filter)
				if err != nil {
					log.Debugf("Error while parsing filter %s, dropping all the permissions for the %s operation", rop.Filter, rop.Op)
					continue // deny the operation completely, this is safer than allowing without filter
				}

				p.Filter = node
			}
		}

		opsPerms[strings.ToLower(rop.Op)] = p
	}

	return opsPerms, nil
}

func parseAttrs(attrCsv string, rt *schema.ResourceType) map[string]*AttributeParam {
	attrMap, subAtPresent := SplitAttrCsv(attrCsv, rt)
	return ConvertToParamAttributes(attrMap, subAtPresent)
}

func filterDenied(denied map[string]*AttributeParam, rt *schema.ResourceType) map[string]*AttributeParam {
	attrMap := make(map[string]int)
	collectAllAtNames(rt.GetMainSchema(), attrMap, true)
	allowed := ConvertToParamAttributes(attrMap, false)
	for k, v := range denied {
		if v.SubAts == nil {
			delete(allowed, k)
		} else {
			allowedParam := allowed[k]
			atType := rt.GetAtType(allowedParam.Name)
			allowedParam.SubAts = make(map[string]string)
			for _, s := range atType.SubAttributes {
				if _, ok := v.SubAts[s.NormName]; !ok {
					allowedParam.SubAts[s.NormName] = s.NormName
				}
			}
		}
	}

	return allowed
}

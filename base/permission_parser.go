// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"encoding/json"
	"sparrow/schema"
	"strings"
)

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
			opsArrAt := subAtMap["opsarr"]

			resName := ""
			if resNameAt != nil {
				resName = resNameAt.Values[0].(string)
			}

			opsArr := "[]"
			if opsArrAt != nil {
				opsArr = opsArrAt.Values[0].(string)
			}

			if resName == "*" {
				// wildcard for all resources
				for _, rt := range resTypes {
					rp, err := createResPerms(opsArr, rt)
					if err == nil {
						resPerms[rt.Name] = rp
					}
				}

				break // we do not need to process anything else
			} else {
				rt := resTypes[resName]
				if rt == nil {
					log.Warningf("No resource type found with the name %s, ignoring permissions", resName)
					continue
				}
				rp, err := createResPerms(opsArr, rt)
				if err == nil {
					resPerms[resName] = rp
				}
			}
		}
	}

	return resPerms
}

func createResPerms(opsArr string, rt *schema.ResourceType) (*ResourcePermission, error) {
	rp := &ResourcePermission{RType: rt}
	opsPerms, err := parseOpsArr(opsArr, rt)
	if err != nil {
		log.Debugf("failed to parse the operation permissions %s", err)
		return nil, err
	}

	rp.ReadPerm = opsPerms["read"] // the keys are lowered in the call to parseOpsObj
	if rp.ReadPerm == nil {
		log.Debugf("No read permission present using default")
		rp.ReadPerm = &Permission{Name: "read"}
	}

	rp.WritePerm = opsPerms["write"]
	if rp.WritePerm == nil {
		log.Debugf("No write permission present using default")
		rp.WritePerm = &Permission{Name: "write"}
	}

	return rp, nil
}

func parseOpsArr(opsArr string, rt *schema.ResourceType) (map[string]*Permission, error) {
	var ops []opsObj
	err := json.Unmarshal([]byte(opsArr), &ops)
	if err != nil {
		return nil, err
	}

	opsPerms := make(map[string]*Permission)
	for _, rop := range ops {
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

		// only parse the filter if either all attributes are allowed
		// or there are some attributes specified
		if p.AllowAll || p.AllowAttrs != nil {
			rop.Filter = strings.TrimSpace(rop.Filter)
			if len(rop.Filter) > 0 {
				tmp := strings.ToUpper(rop.Filter)
				if "ANY" == tmp {
					p.OnAnyResource = true
				} else if "NONE" == tmp {
					p.Filter = nil
					p.AllowAll = false
					p.AllowAttrs = nil
				} else {
					node, err := ParseFilter(rop.Filter)
					if err != nil {
						log.Debugf("Error while parsing filter %s, dropping all the permissions for the %s operation", rop.Filter, rop.Op)
						continue // deny the operation completely, this is safer than allowing without filter
					}

					p.Filter = node
				}
			}
		}

		opsPerms[strings.ToLower(rop.Op)] = p
	}

	return opsPerms, nil
}

func parseAttrs(attrCsv string, rt *schema.ResourceType) map[string]*AttributeParam {
	attrMap, subAtPresent := SplitAttrCsv(attrCsv, rt)
	// the mandatory attributes that will always be returned
	for k, _ := range rt.AtsAlwaysRtn {
		attrMap[k] = 1
	}

	// and those that are never returned
	for k, _ := range rt.AtsNeverRtn {
		if _, ok := attrMap[k]; ok {
			delete(attrMap, k)
		}
	}

	m := ConvertToParamAttributes(attrMap, subAtPresent)

	if len(m) == 0 {
		m = nil
	}

	return m
}

func filterDenied(denied map[string]*AttributeParam, rt *schema.ResourceType) map[string]*AttributeParam {
	if denied == nil {
		return nil
	}

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

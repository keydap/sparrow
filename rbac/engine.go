// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package rbac

import (
	"sparrow/base"
	"sparrow/schema"
	"sparrow/utils"
	"time"
)

type RbacEngine struct {
	TokenTtl int64
	Domain   string
	allRoles map[string]*base.Role
}

func NewEngine() *RbacEngine {
	engine := &RbacEngine{}
	engine.allRoles = make(map[string]*base.Role)
	engine.TokenTtl = 8 * 60 * 60 // 8 hours

	return engine
}

func (engine *RbacEngine) NewRbacSession(rs *base.Resource) *base.RbacSession {

	session := &base.RbacSession{}
	session.Sub = rs.GetId()

	session.Roles = make(map[string]string)

	//session.Aud = ""
	session.Domain = engine.Domain
	session.Iat = time.Now().Unix()
	session.LastAccAt = session.Iat
	session.Exp = session.Iat + engine.TokenTtl
	session.Jti = utils.NewRandShaStr()
	session.Username = rs.GetAttr("username").GetSimpleAt().GetStringVal()

	groups := rs.GetAttr("groups")
	if groups == nil {
		return session
	}

	ca := groups.GetComplexAt()

	effPerms := make(map[string]*base.ResourcePermission)
	for _, subAtMap := range ca.SubAts {
		gAt := subAtMap["value"]
		if gAt != nil {
			roleId := gAt.Values[0].(string)
			role := engine.allRoles[roleId]
			session.Roles[roleId] = role.Name

			// now gather the permissions from role
			if role != nil {
				for _, resPerm := range role.Perms {
					existingResPerm, ok := effPerms[resPerm.RType.Name]

					if !ok {
						effPerms[resPerm.RType.Name] = resPerm
					} else {
						effPerms[resPerm.RType.Name] = merge(existingResPerm, resPerm)
					}
				}
			}
		}
	}

	session.EffPerms = effPerms

	return session
}

func (engine *RbacEngine) DeleteRole(groupId string) {
	delete(engine.allRoles, groupId)
}

func (engine *RbacEngine) UpsertRole(groupRes *base.Resource, resTypes map[string]*schema.ResourceType) {
	role := &base.Role{}
	role.Id = groupRes.GetId()

	dispName := groupRes.GetAttr("displayname")
	if dispName != nil {
		role.Name = dispName.GetSimpleAt().Values[0].(string)
	}

	role.Perms = base.ParseResPerms(groupRes, resTypes)

	engine.allRoles[role.Id] = role
}

// Merges the existing and nextPerm and returns a new ResourcePermission instance
// the resulting instance contains a union of operation permissions
func merge(existing *base.ResourcePermission, nextPerm *base.ResourcePermission) *base.ResourcePermission {
	merged := &base.ResourcePermission{}
	merged.RType = existing.RType

	merged.ReadPerm = mergePermission(existing.ReadPerm, nextPerm.ReadPerm)
	merged.WritePerm = mergePermission(existing.WritePerm, nextPerm.WritePerm)

	return merged
}

func mergePermission(erp *base.Permission, nrp *base.Permission) *base.Permission {
	var p *base.Permission
	if erp == nil && nrp != nil {
		p = nrp.Clone()
	} else if erp != nil && nrp != nil {
		p = &base.Permission{}
		if erp.AllowAll || nrp.AllowAll {
			p.AllowAll = true
		} else {
			if erp.AllowAttrs != nil {
				allowAttrMap := base.CloneAtParamMap(erp.AllowAttrs)
				cloneAndMergeAttrMapInto(allowAttrMap, nrp.AllowAttrs)
				p.AllowAttrs = allowAttrMap
			}
		}

		if erp.OnAnyResource || nrp.OnAnyResource {
			p.OnAnyResource = true
		} else if erp.Filter != nil && nrp.Filter != nil {
			fn := &base.FilterNode{}
			fn.Op = "OR"
			fn.Children = make([]*base.FilterNode, 2)
			fn.Children[0] = erp.Filter.Clone()
			fn.Children[1] = nrp.Filter.Clone()
			p.Filter = fn
		} else if erp.Filter == nil && nrp.Filter != nil {
			p.Filter = nrp.Filter.Clone()
		}
	}

	return p
}

func cloneAndMergeAttrMapInto(dest map[string]*base.AttributeParam, src map[string]*base.AttributeParam) {
	if src == nil {
		return
	}

	tmp := base.CloneAtParamMap(src)
	for k, v := range tmp {
		dest[k] = v
	}
}

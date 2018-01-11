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
	session.Exp = session.Iat + engine.TokenTtl
	session.Jti = utils.NewRandShaStr()

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

	if existing.ReadPerm == nil && nextPerm.ReadPerm != nil {
		merged.ReadPerm = nextPerm.ReadPerm.Clone()
	} else if existing.ReadPerm != nil && nextPerm.ReadPerm != nil {
		erp := existing.ReadPerm
		nrp := nextPerm.ReadPerm

		p := &base.Permission{}
		merged.ReadPerm = p
		if erp.AllowAll || nrp.AllowAll {
			p.AllowAll = true
		} else {
			if erp.AllowAttrs != nil {
				allowAttrMap := base.CloneAtParamMap(erp.AllowAttrs)
				cloneAndMergeAttrMapInto(allowAttrMap, nrp.AllowAttrs)
			}
		}
	}

	return nil
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

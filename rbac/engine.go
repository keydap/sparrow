package rbac

import (
	"fmt"
	"sparrow/base"
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
	session.EffPerms = make(map[string]int)

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

	for _, subAtMap := range ca.SubAts {
		gAt := subAtMap["value"]
		if gAt != nil {
			fmt.Println(gAt)
			roleId := gAt.Values[0].(string)
			role := engine.allRoles[roleId]
			session.Roles[roleId] = role.Name

			// now gather the permissions from role
			if role != nil {
				for _, p := range role.Perms {
					session.EffPerms[p.Name] = 1
				}
			}
		}
	}

	return session
}

func (engine *RbacEngine) DeleteRole(groupId string) {
	delete(engine.allRoles, groupId)
}

func (engine *RbacEngine) UpsertRole(groupRes *base.Resource) {
	role := &base.Role{}
	role.Id = groupRes.GetId()
	role.Perms = make(map[string]*base.Permission)

	dispName := groupRes.GetAttr("displayname")
	if dispName != nil {
		role.Name = dispName.GetSimpleAt().Values[0].(string)
	}

	perms := groupRes.GetAttr("permissions")
	if perms != nil {
		permSubAts := perms.GetComplexAt().SubAts
		for _, subAtMap := range permSubAts {
			valAt := subAtMap["value"]
			if valAt != nil {
				permName := valAt.Values[0].(string)
				p := &base.Permission{Name: permName}
				role.Perms[permName] = p
			}
		}
	}

	engine.allRoles[role.Id] = role
}

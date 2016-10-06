package rbac

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"sparrow/base"
	"sparrow/utils"
	"time"
)

type RbacEngine struct {
	TokenTtl int64
	allRoles map[string]*Role
}

func NewEngine() *RbacEngine {
	engine := &RbacEngine{}
	engine.allRoles = make(map[string]*Role)
	engine.TokenTtl = 8 * 60 * 60 // 8 hours

	return engine
}

func (engine *RbacEngine) NewRbacSession(rs *base.Resource) *RbacSession {

	session := &RbacSession{}
	session.Sub = rs.GetId()

	session.Roles = make(map[string]string)
	session.EffPerms = make(map[string]int)

	//session.Aud = ""
	session.Iat = time.Now().Unix()
	session.Exp = session.Iat + engine.TokenTtl
	session.Jti = utils.GenUUID()

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
	role := &Role{}
	role.Id = groupRes.GetId()
	role.Perms = make(map[string]*Permission)

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
				p := &Permission{Name: permName}
				role.Perms[permName] = p
			}
		}
	}

	engine.allRoles[role.Id] = role
}

func (session *RbacSession) ToJwt() string {
	//sm := jwt.SigningMethodRSA{}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, session)
	str, err := token.SignedString([]byte("abcdefg"))
	if err != nil {
		panic(fmt.Errorf("could not create the JWT from session %#v", err))
	}

	data, _ := json.Marshal(session)
	fmt.Println(string(data))

	return str
}

func (session *RbacSession) IsAllowCreate() bool {
	return session._PermAllowed(PERM_CREATE)
}

func (session *RbacSession) IsAllowRead() bool {
	return session._PermAllowed(PERM_READ)
}

func (session *RbacSession) IsAllowUpdate() bool {
	return session._PermAllowed(PERM_UPDATE)
}

func (session *RbacSession) IsAllowDelete() bool {
	return session._PermAllowed(PERM_DELETE)
}

func (session *RbacSession) _PermAllowed(perm string) bool {
	_, ok := session.EffPerms[perm]

	return ok
}

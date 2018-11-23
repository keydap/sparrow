// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"sparrow/schema"
	"time"
)

// the permissions allowed in Sparrow
// here, though some permissions look identical to CRUD operations, the similarity ends there.

const PERM_READ string = "READ"

const PERM_CREATE string = "CREATE"

const PERM_UPDATE string = "UPDATE"

const PERM_DELETE string = "DELETE"

const PERM_CHANGE_ATTRIBUTE string = "CHANGE_ATTRIBUTE"

var admin_perm_array []string = []string{PERM_CREATE, PERM_DELETE, PERM_READ, PERM_UPDATE}

type RbacUser struct {
	Rid   string
	Roles map[string]string // <roleID, displayName> key-value pairs
}

type Role struct {
	Id    string
	Name  string
	Perms map[string]*ResourcePermission
}

type ResourcePermission struct {
	RType     *schema.ResourceType
	ReadPerm  *Permission
	WritePerm *Permission
}

type Permission struct {
	Name          string                     `json:"-"`
	Filter        *FilterNode                `json:"-"`
	OnAnyResource bool                       `json:"onAnyRes"`
	AllowAttrs    map[string]*AttributeParam `json:"-"`
	AllowAll      bool                       `json:"allowAll"`
	evaluator     Evaluator                  `json:"-"`
}

type SamlAppSession struct {
	SessionIndex string
	NameID       string
	NameIDFormat string
}

type RbacSession struct {
	Roles    map[string]string              `json:"roles"`
	EffPerms map[string]*ResourcePermission `json:"-"`
	Domain   string                         `json:"iss"`
	Sub      string                         `json:"sub"`
	Exp      int64                          `json:"exp"`
	Iat      int64                          `json:"iat"`
	Jti      string                         `json:"jti"`
	Ito      string                         `json:"ito"` // The ID of the oAuth client to who this JWT was sent to
	Apps     map[string]SamlAppSession      `json:"-"`   // a map of application SAML issuer IDs and their SessionIndexes
	Username string                         `json:"-"`
	//Aud      string         `json:"aud"`
	//Nbf	int64 `json:"nbf"`
}

// Implementing Valid() makes RbacSession a valid Claims instance
func (session *RbacSession) Valid() error {
	return nil
}

func (session *RbacSession) ToJwt(key crypto.PrivateKey) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, session)
	token.Header["d"] = session.Domain
	str, err := token.SignedString(key)
	if err != nil {
		panic(fmt.Errorf("could not create the JWT from session %#v", err))
	}

	data, _ := json.Marshal(session)
	fmt.Println(string(data))

	return str
}

func (session *RbacSession) IsExpired() bool {
	now := time.Now().Unix()

	if session.Exp <= 0 {
		//FIXME never expires, is it wise to allow permanent tokens??
		return false
	}

	return session.Exp <= now
}

//func VerifyJwt(tokenString string) bool {
//	jwt.Parse(tokenString, keyFunc)
//}

func (p *Permission) Clone() *Permission {
	n := &Permission{}
	*n = *p

	if p.Filter != nil {
		n.Filter = p.Filter.Clone()
	}

	if p.AllowAttrs != nil {
		n.AllowAttrs = CloneAtParamMap(p.AllowAttrs)
	}

	return n
}

func (p *Permission) EvalFilter(rs *Resource) bool {
	if p.Filter == nil {
		return false
	}

	if p.evaluator == nil {
		p.evaluator = BuildEvaluator(p.Filter)
	}

	return p.evaluator.Evaluate(rs)
}

func CloneAtParamMap(m map[string]*AttributeParam) map[string]*AttributeParam {
	if m == nil {
		return nil
	}
	nMap := make(map[string]*AttributeParam)
	for k, v := range m {
		ap := &AttributeParam{}
		*ap = *v
		nMap[k] = ap
	}
	return nMap
}

func (rp *ResourcePermission) MarshalJSON() ([]byte, error) {
	tmpl := "\"%s\": {\"onAnyRes\": %t, \"allowAll\": %t}"
	read := fmt.Sprintf(tmpl, "read", rp.ReadPerm.OnAnyResource, rp.ReadPerm.AllowAll)
	write := fmt.Sprintf(tmpl, "write", rp.WritePerm.OnAnyResource, rp.WritePerm.AllowAll)
	str := fmt.Sprintf("{\"resName\": \"%s\", %s, %s}", rp.RType.Name, read, write)

	return []byte(str), nil
}

package saml

import (
//	"sparrow/base"
)

type SamlGroupConfig struct {
	ScimGroupName string
	SamlGroupName string
	Desc          string
}

type SamlAttrConfig struct {
	SamlAtName   string
	ScimAtPath   string
	StaticValues []string
	IsStatic     bool
}

func NewDefaultSamlAttrs() []SamlAttrConfig {
	uid := CreateSamlAt("uid", "username")
	email := CreateSamlAt("email", "emails.value")
	displayName := CreateSamlAt("displayName", "displayName")
	firstName := CreateSamlAt("firstName", "name.givenName")
	lastName := CreateSamlAt("lastName", "name.familyName")
	members := CreateSamlAt("members", "groups.display")

	return []SamlAttrConfig{uid, email, displayName, firstName, lastName, members}
}

func CreateSamlAt(samlAtName string, scimAtPath string) SamlAttrConfig {
	sac := SamlAttrConfig{}
	sac.IsStatic = false
	sac.SamlAtName = samlAtName
	sac.ScimAtPath = scimAtPath

	return sac
}

//func GenSamlResponse(user *base.Resource, sgc SamlGroupConfig, sac SamlAttrConfig) {
//}

package schema

import (
	"encoding/json"
	"fmt"
	"strings"
)

var ldif_user = `dn: uid={{username}},ou=Users,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
givenName: Aaren
sn: Atp
cn: Aaren Atp
initials: AA
uid: user.2
mail: user.2@null
userPassword: password
telephoneNumber: 493-242-3893
homePhone: 409-324-3038
pager: 972-389-7751
mobile: 004-637-5140
employeeNumber: 2
street: 05509 Church Street
l: Harlingen
st: NC
postalCode: 90192
postalAddress: Aaren Atp$05509 Church Street$Harlingen, NC  90192
description: This is the description for Aaren Atp.`

const LDAP_User_Entry = `{
	"type": "User",
	"objectClasses": ["top", "person", "organizationalPerson", "inetOrgPerson"],
	"dnPrefix": "uid={{userName}},ou=Users",
	"attributes": [
		{
			"scimAttrPath": "userName",
			"ldapAttrName": "uid"
		},
		{
			"scimAttrPath": "name.familyName",
			"ldapAttrName": "sn"
		},
		{
			"scimAttrPath": "emails",
			"ldapAttrName": "mail",
			"format": "value"
		}
	]
}`

type LdapAttribute struct {
	ScimAttrPath string
	AtType       *AttrType
	LdapAttrName string
	Format       string
}

type LdapEntryTemplate struct {
	Type            string
	DnPrefix        string
	DnAtName        string
	ObjectClasses   []string
	Attributes      []*LdapAttribute
	AttrMap         map[string]*LdapAttribute
	LdapToScimAtMap map[string]string
}

func NewLdapTemplate(tmpl []byte, rsTypes map[string]*ResourceType) (entry *LdapEntryTemplate, err error) {
	err = json.Unmarshal(tmpl, &entry)

	if err != nil {
		return nil, err
	}

	rt := rsTypes[entry.Type]
	if rt == nil {
		err = fmt.Errorf("Invalid LDAP entry template, resource type %s is not found", entry.Type)
		return nil, err
	}

	entry.AttrMap = make(map[string]*LdapAttribute)
	entry.LdapToScimAtMap = make(map[string]string)

	for _, ldapAt := range entry.Attributes {
		tmpPath := ldapAt.ScimAttrPath
		ldapAt.ScimAttrPath = strings.ToLower(tmpPath)
		ldapAt.AtType = rt.GetAtType(ldapAt.ScimAttrPath)
		if ldapAt.AtType == nil {
			err = fmt.Errorf("Invalid SCIM attribute, %s is not found", tmpPath)
			return nil, err
		}

		entry.AttrMap[ldapAt.ScimAttrPath] = ldapAt
		entry.LdapToScimAtMap[strings.ToLower(ldapAt.LdapAttrName)] = ldapAt.ScimAttrPath
	}

	parseDnPrefix(entry)

	return entry, nil
}

func parseDnPrefix(entry *LdapEntryTemplate) {
	startPos := strings.Index(entry.DnPrefix, "{{")

	if startPos <= 0 {
		return
	}

	endPos := strings.Index(entry.DnPrefix, "}}")
	if endPos <= 0 || endPos < startPos {
		return
	}

	entry.DnAtName = strings.TrimSpace(entry.DnPrefix[startPos+2 : endPos])
	// convert DnPrefix into the format "uid=%s,ou=Users,%s"
	entry.DnPrefix = entry.DnPrefix[:startPos] + "%s" + entry.DnPrefix[endPos+2:] + ",%s"
}

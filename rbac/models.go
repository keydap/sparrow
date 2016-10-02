package rbac

import ()

// the permissions allowed in Sparrow
// here, though some permissions look identical to CRUD operations, the similarity ends there.

const PERM_READ string = "READ"

const PERM_CREATE string = "CREATE"

const PERM_UPDATE string = "UPDATE"

const PERM_DELETE string = "DELETE"

const PERM_CHANGE_ATTRIBUTE string = "CHANGE_ATTRIBUTE"

type RbacUser struct {
	Rid   string
	Roles map[string]string // <roleID, displayName> key-value pairs
}

type Role struct {
	Id    string
	Name  string
	Perms map[string]*Permission
}

type Permission struct {
	Name string
	//Filters  map[string]int
}

type RbacSession struct {
	Roles    map[string]string `json:"roles"`
	EffPerms map[string]int    `json:"ep"`
	Domain   string            `json:"iss"`
	Sub      string            `json:"sub"`
	Exp      int64             `json:"exp"`
	Iat      int64             `json:"iat"`
	Jti      string            `json:"jti"`
	//Aud      string         `json:"aud"`
	//Nbf	int64 `json:"nbf"`
}

// Implementing Valid() makes RbacSession a valid Claims instance
func (session *RbacSession) Valid() error {
	return nil
}

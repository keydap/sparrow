package silo

import (
	"fmt"
	"sparrow/rbac"
	"testing"
)

func TestCreateJwt(t *testing.T) {
	initSilo()

	user := createTestUser()
	user, _ = sl.Insert(user)

	group := prepareGroup(user)
	sl.Insert(group)

	user, _ = sl.Get(user.GetId(), userType)

	session := rbac.NewRbacSession(user)

	fmt.Println(session.ToJwt())
}

package silo

import (
	"fmt"
	"testing"
)

func TestCreateJwt(t *testing.T) {
	initSilo()

	user := createTestUser()
	user, _ = sl.Insert(user)

	group := prepareGroup(user)
	sl.Insert(group)

	user, _ = sl.Get(user.GetId(), userType)

	session := sl.Engine.NewRbacSession(user)

	fmt.Println(session.ToJwt())
}

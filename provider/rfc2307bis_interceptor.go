package provider

import (
	"sparrow/base"
	"sparrow/conf"
	"sync"
)

const posixUserSchemaId = "urn:keydap:params:scim:schemas:extension:posix:2.0:User"
const posixGroupSchemaId = "urn:keydap:params:scim:schemas:extension:posix:2.0:Group"

// Adds the uidnumber, gidnumber, loginshell and homeDirectory attibutes if they are not already present
type Rfc2307BisAttrInterceptor struct {
	uidNumber int64
	gidNumber int64
	lock      sync.Mutex
	Conf      *conf.Rfc2307bis
}

func (ri *Rfc2307BisAttrInterceptor) nextUidNumber() int64 {
	ri.lock.Lock()
	ri.uidNumber++
	ri.lock.Unlock()

	return ri.uidNumber
}

func (ri *Rfc2307BisAttrInterceptor) setUidNumber(latest int64) {
	ri.lock.Lock()
	// check one more time if the passed value is higher than the
	// current value inside the lock
	if latest > ri.uidNumber {
		ri.uidNumber = latest
	}
	ri.lock.Unlock()
}

func (ri *Rfc2307BisAttrInterceptor) nextGidNumber() int64 {
	ri.lock.Lock()
	ri.gidNumber++
	ri.lock.Unlock()

	return ri.gidNumber
}

func (ri *Rfc2307BisAttrInterceptor) setGidNumber(latest int64) {
	ri.lock.Lock()
	// check one more time if the passed value is higher than the
	// current value inside the lock
	if latest > ri.gidNumber {
		ri.gidNumber = latest
	}
	ri.lock.Unlock()
}

func (ri *Rfc2307BisAttrInterceptor) PreCreate(crCtx *base.CreateContext) error {
	rs := crCtx.InRes
	return ri._preCreate(rs)
}

func (ri *Rfc2307BisAttrInterceptor) _preCreate(rs *base.Resource) error {
	name := rs.GetType().Name

	if name == "User" {
		uidAtName := posixUserSchemaId + ":uidNumber"
		gidAtName := posixUserSchemaId + ":gidNumber"
		lsAtName := posixUserSchemaId + ":loginShell"
		hdAtName := posixUserSchemaId + ":homeDirectory"

		atUidNum := rs.GetAttr(uidAtName)
		var uidNum int64
		if atUidNum == nil {
			uidNum = ri.nextUidNumber()
			rs.AddSA(uidAtName, uidNum)
		} else {
			uidNum = atUidNum.GetSimpleAt().Values[0].(int64)
			if uidNum < 0 {
				return base.NewBadRequestError("uidNumber cannot be negative")
			}
		}

		gidAt := rs.GetAttr(gidAtName)
		if gidAt == nil {
			rs.AddSA(gidAtName, uidNum) // same as uidNumber
		}

		lsAt := rs.GetAttr(lsAtName)
		if lsAt == nil {
			rs.AddSA(lsAtName, ri.Conf.LoginShell)
		}

		hdAt := rs.GetAttr(hdAtName)
		if hdAt == nil {
			// required attribute check happens later after interceptors fire, so safe to do a nil check
			usernameAt := rs.GetAttr("username")
			if usernameAt != nil {
				hd := ri.Conf.HomeDirectoryPrefix + usernameAt.GetSimpleAt().GetStringVal()
				rs.AddSA(hdAtName, hd)
			}
		}
	} else if name == "Group" {
		gidAtName := posixGroupSchemaId + ":gidNumber"
		atGid := rs.GetAttr(gidAtName)
		if atGid == nil {
			gidNum := ri.nextGidNumber()
			rs.AddSA(gidAtName, gidNum)
		}
	}

	return nil
}

func (ri *Rfc2307BisAttrInterceptor) PostCreate(crCtx *base.CreateContext) {
	rs := crCtx.InRes
	name := rs.GetType().Name

	if name == "User" {
		uidAtName := posixUserSchemaId + ":uidNumber"
		atUidNum := rs.GetAttr(uidAtName)
		uidNum := atUidNum.GetSimpleAt().Values[0].(int64)
		if uidNum > ri.uidNumber {
			ri.setUidNumber(uidNum)
		}
	} else if name == "Group" {
		gidAtName := posixGroupSchemaId + ":gidNumber"
		atGid := rs.GetAttr(gidAtName)
		gidNum := atGid.GetSimpleAt().Values[0].(int64)
		if gidNum > ri.gidNumber {
			ri.setGidNumber(gidNum)
		}
	}
}

func (ri *Rfc2307BisAttrInterceptor) PrePatch(patchCtx *base.PatchContext) error {
	return nil
}

func (ri *Rfc2307BisAttrInterceptor) PostPatch(patchedRs *base.Resource, patchCtx *base.PatchContext) {
}

func (ri *Rfc2307BisAttrInterceptor) PreDelete(delCtx *base.DeleteContext) error {
	return nil
}

func (ri *Rfc2307BisAttrInterceptor) PostDelete(delCtx *base.DeleteContext) {
}

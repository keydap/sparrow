// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package provider

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sparrow/base"
	"sparrow/schema"
	"sparrow/silo"
	"time"
)

type AuditLogger struct {
	queue        chan base.AuditEvent
	roller       chan time.Time
	rt           *schema.ResourceType
	sl           *silo.Silo
	dataFilePath string
	prv          *Provider // it is necessary to hold the reference to provider instance for rolling audit logs
}

var aeschemasAt = []string{"urn:keydap:params:scim:schemas:core:2.0:AuditEvent"}

func NewLocalAuditLogger(prv *Provider) *AuditLogger {
	al := &AuditLogger{}
	al.rt = prv.RsTypes["AuditEvent"]
	al.prv = prv

	var err error
	al.dataFilePath = filepath.Join(prv.layout.DataDir, "auditlog.db")
	al.sl, err = openAuditLog(al.dataFilePath, prv)
	if err != nil {
		panic(err)
	}

	al.queue = make(chan base.AuditEvent, 1000)
	al.roller = make(chan time.Time) // unbuffered channel

	go start(al)
	go startRoller(al.roller)

	return al
}

func openAuditLog(path string, prv *Provider) (sl *silo.Silo, err error) {
	return silo.Open(path, prv.ServerId, prv.Config, prv.RsTypes, prv.Schemas)
}

func start(al *AuditLogger) {
	log.Debugf("initialized local audit logger")

	al.roller <- time.Now()

	ctx := &base.CreateContext{}
loop:
	for {
		select {
		case ae := <-al.queue:

			if ae.Id == "" {
				break loop
			}

			log.Debugf("%s", ae.Id)
			res := al.eventToRes(ae)
			ctx.InRes = res
			err := al.sl.InsertInternal(ctx)
			if err != nil {
				log.Warningf("failed to insert audit log event")
			}

		case now := <-al.roller:
			log.Infof("rolling up the audit log")
			timestamp := now.Format(time.RFC3339)[:19] // strip the +timezone detail
			oldLog := "auditlog-" + timestamp + ".db"
			oldLog = filepath.Join(al.prv.layout.DataDir, oldLog)
			al.sl.Close() // TODO how to prevent active searches on audit log from failing? it is not critical for now
			os.Rename(al.dataFilePath, oldLog)
			var err error
			// open a new audit log
			al.sl, err = openAuditLog(al.dataFilePath, al.prv)
			if err != nil {
				panic(err)
			}

			go al.rollLog(oldLog)
			al.roller <- time.Now()
		}
	}
}

func (al *AuditLogger) eventToRes(ae base.AuditEvent) *base.Resource {
	res := base.NewResource(al.rt)
	res.AddSA("id", ae.Id)
	res.AddSA("actorid", ae.ActorId)
	res.AddSA("desc", ae.Desc)
	res.AddSA("ipaddress", ae.IpAddress)
	res.AddSA("operation", ae.Operation)
	res.AddSA("payload", ae.Payload)
	res.AddSA("statuscode", ae.StatusCode)
	res.AddSA("uri", ae.Uri)
	res.AddSA("actorname", ae.ActorName)
	res.AddSA("schemas", aeschemasAt)

	return res
}

func (al *AuditLogger) LogEvent(ae base.AuditEvent) {
	ae.Id = al.sl.Csn().String()
	al.queue <- ae
}

func (al *AuditLogger) Close() {
	ae := base.AuditEvent{}
	ae.Id = ""
	al.queue <- ae
	//FIXME wait for the channel to be empty
	// also close the channel
	al.sl.Close()
}

func (al *AuditLogger) Log(ctx interface{}, res *base.Resource, err error) {
	go al._log(ctx, res, err)
}

func (al *AuditLogger) _log(ctx interface{}, res *base.Resource, err error) {
	ae := base.AuditEvent{}

	_fillFromErr(&ae, err)

	switch ctx.(type) {
	case *base.GetContext:
		gc := ctx.(*base.GetContext)
		ae.IpAddress = gc.ClientIP
		ae.ActorId = gc.Session.Sub
		ae.ActorName = gc.Session.Username
		ae.Operation = "Get"
		if gc.Rt == al.rt {
			ae.Operation = "AuditGet"
		}

		if gc.ParamAttrs != "" {
			ae.Payload = "{\"attributes\": \"" + gc.ParamAttrs + "\"}"
		} else if gc.ParamExclAttrs != "" {
			ae.Payload = "{\"excludedAttributes\": \"" + gc.ParamExclAttrs + "\"}"
		}

		ae.Uri = gc.Endpoint
		if err == nil {
			ae.Desc = "Read a single resource of type " + gc.Rt.Name
			ae.StatusCode = 200
		}

	case *base.SearchContext:
		sc := ctx.(*base.SearchContext)
		ae.IpAddress = sc.ClientIP
		ae.ActorId = sc.Session.Sub
		ae.ActorName = sc.Session.Username
		ae.Operation = "Search"
		ae.Uri = sc.Endpoint
		singleRt := (len(sc.ResTypes) == 1)
		if singleRt && sc.ResTypes[0] == al.rt {
			ae.Operation = "AuditSearch"
		}
		if sc.RawReq != nil {
			data, _ := json.Marshal(sc.RawReq)
			ae.Payload = string(data)
		}
		if err == nil {
			if singleRt {
				ae.Desc = "Searched for resources of type " + sc.ResTypes[0].Name
			} else {
				ae.Desc = "Searched for multiple resources"
			}
			ae.StatusCode = 200
		}

	case *base.CreateContext:
		cc := ctx.(*base.CreateContext)
		ae.IpAddress = cc.ClientIP
		ae.ActorId = cc.Session.Sub
		ae.ActorName = cc.Session.Username
		ae.Operation = "Create"
		if res != nil {
			ae.Uri = res.GetType().Endpoint + "/" + res.GetId()
		}
		if err == nil {
			ae.Desc = "Created a " + res.GetType().Name + " resource"
			ae.StatusCode = 201
		}

	case *base.PatchContext:
		pc := ctx.(*base.PatchContext)
		ae.IpAddress = pc.ClientIP
		ae.ActorId = pc.Session.Sub
		ae.ActorName = pc.Session.Username
		ae.Operation = "Patch"
		ae.Uri = pc.Endpoint
		if err == nil {
			ae.Desc = "Modified a " + pc.Rt.Name + " resource"
			ae.StatusCode = 200
		}

	case *base.ReplaceContext:
		rc := ctx.(*base.ReplaceContext)
		ae.IpAddress = rc.ClientIP
		ae.ActorId = rc.Session.Sub
		ae.ActorName = rc.Session.Username
		ae.Operation = "Replace"
		ae.Uri = rc.Endpoint
		if err == nil {
			ae.Desc = "Replaced a " + rc.Rt.Name + " resource"
			ae.StatusCode = 200
		}

	case *base.DeleteContext:
		dc := ctx.(*base.DeleteContext)
		ae.IpAddress = dc.ClientIP
		ae.ActorId = dc.Session.Sub
		ae.ActorName = dc.Session.Username
		ae.Operation = "Delete"
		ae.Uri = dc.Endpoint
		if err == nil {
			ae.Desc = "Deleted a " + dc.Rt.Name + " resource"
			ae.StatusCode = 200
		}
	}

	al.LogEvent(ae)
}

func _fillFromErr(ae *base.AuditEvent, err error) {
	if err == nil {
		return
	}

	switch err.(type) {
	case *base.ScimError:
		se := err.(*base.ScimError)
		ae.StatusCode = se.Code()
		ae.Desc = se.Detail

	default:
		ae.Desc = err.Error()
		ae.StatusCode = 520 // an unofficial code for all unhandled errors
	}
}

func (al *AuditLogger) LogAuth(rid string, username string, ip string, status base.LoginStatus) {
	go al._logAuth(rid, username, ip, status)
}

func (al *AuditLogger) _logAuth(rid string, username string, ip string, status base.LoginStatus) {
	ae := base.AuditEvent{}
	ae.IpAddress = ip
	ae.ActorId = rid
	ae.ActorName = username
	ae.Operation = "PasswordCheck"
	_setDesc(username, &ae, status)
	al.LogEvent(ae)
}

func _setDesc(username string, ae *base.AuditEvent, status base.LoginStatus) {
	ae.StatusCode = 401 // default
	desc := ""
	switch status {
	case base.LOGIN_ACCOUNT_NOT_ACTIVE:
		desc = "%s's account is not active"
	case base.LOGIN_CHANGE_PASSWORD:
		desc = "Successfully authenticated %s"
		ae.StatusCode = 200
	case base.LOGIN_FAILED:
		desc = "Login failed for %s due to invalid credentials"
	case base.LOGIN_NO_PASSWORD:
		desc = "Account of %s has no password, login failed"
	case base.LOGIN_SUCCESS:
		desc = "Successfully authenticated %s"
		ae.StatusCode = 200
	case base.LOGIN_TFA_REGISTER:
		desc = "Successfully verified password of %s"
		ae.StatusCode = 200
	case base.LOGIN_TFA_REQUIRED:
		desc = "Successfully verified password of %s"
		ae.StatusCode = 200
	case base.LOGIN_USER_NOT_FOUND:
		desc = "User %s not found"
		ae.StatusCode = 404
	}

	ae.Desc = fmt.Sprintf(desc, username)
}

func (al *AuditLogger) LogOtp(rid string, clientIP string, user *base.Resource, status base.LoginStatus) {
	go al._logOtp(rid, clientIP, user, status)
}

func (al *AuditLogger) _logOtp(rid string, clientIP string, user *base.Resource, status base.LoginStatus) {
	ae := base.AuditEvent{}
	ae.IpAddress = clientIP
	ae.ActorId = rid
	ae.ActorName = user.GetAttr("username").GetSimpleAt().GetStringVal()
	ae.Operation = "OtpCheck"
	username := ""
	if user != nil {
		username = user.GetAttr("username").GetSimpleAt().GetStringVal()
	}

	// in case of OTP there are only three cases
	if status == base.LOGIN_SUCCESS || status == base.LOGIN_CHANGE_PASSWORD {
		ae.Desc = "successfully verified OTP of " + username
		ae.StatusCode = 200
	} else {
		ae.Desc = "login failed, OTP of " + username + " is invalid"
		ae.StatusCode = 401
	}
	al.LogEvent(ae)
}

func (al *AuditLogger) LogChangePasswd(rid string, clientIP string, user *base.Resource) {
	go al._logChangePasswd(rid, clientIP, user)
}

func (al *AuditLogger) _logChangePasswd(rid string, clientIP string, user *base.Resource) {
	ae := base.AuditEvent{}
	ae.IpAddress = clientIP
	ae.ActorId = rid
	ae.ActorName = user.GetAttr("username").GetSimpleAt().GetStringVal()
	ae.Operation = "ChangePassword"
	username := ""
	if user != nil {
		username = user.GetAttr("username").GetSimpleAt().GetStringVal()
		ae.Desc = "successfully changed password of " + username
		ae.StatusCode = 200
	} else {
		ae.Desc = "failed to change password of " + username
		ae.StatusCode = 403
	}

	al.LogEvent(ae)
}

func (al *AuditLogger) LogStoreTotp(rid string, clientIP string, err error) {
	go al._logStoreTotp(rid, clientIP, err)
}

func (al *AuditLogger) _logStoreTotp(rid string, clientIP string, err error) {
	ae := base.AuditEvent{}
	ae.IpAddress = clientIP
	ae.ActorId = rid
	ae.Operation = "StoreTotpSecret"
	if err == nil {
		ae.Desc = "successfully stored TOTP secret"
		ae.StatusCode = 200
	} else {
		_fillFromErr(&ae, err)
	}

	al.LogEvent(ae)
}

func (al *AuditLogger) LogDelSession(opCtx *base.OpContext, deleted bool) {
	go al._logDelSession(opCtx, deleted)
}

func (al *AuditLogger) _logDelSession(opCtx *base.OpContext, deleted bool) {
	ae := base.AuditEvent{}
	ae.IpAddress = opCtx.ClientIP
	ae.ActorId = opCtx.Session.Sub
	ae.ActorName = opCtx.Session.Username
	ae.Uri = opCtx.Session.Jti
	ae.Operation = "Logout"
	if deleted {
		if opCtx.Sso {
			ae.Desc = "Deleted SSO session"
		} else {
			ae.Desc = "Deleted OAuth session"
		}
		ae.StatusCode = 200
	} else {
		ae.Desc = "Session not found"
		ae.StatusCode = 404
	}

	al.LogEvent(ae)
}

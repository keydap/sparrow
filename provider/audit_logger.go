// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package provider

import (
	"encoding/json"
	"fmt"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/schema"
	"sparrow/silo"
)

type AuditLogger struct {
	queue chan base.AuditEvent
	rt    *schema.ResourceType
	sl    *silo.Silo
}

func NewLocalAuditLogger(path string, serverId uint16, config *conf.DomainConfig, rtypes map[string]*schema.ResourceType, sm map[string]*schema.Schema) *AuditLogger {
	al := &AuditLogger{}
	al.rt = rtypes["AuditEvent"]

	var err error
	al.sl, err = silo.Open(path, serverId, config, rtypes, sm)
	if err != nil {
		panic(err)
	}

	al.queue = make(chan base.AuditEvent, 1000)
	go start(al)
	return al
}

func start(al *AuditLogger) {
	log.Debugf("initialized local audit logger")
	for {
		ae := <-al.queue

		if ae.Id == "" {
			break
		}

		log.Debugf("%s", ae.Id)
		res := al.eventToRes(ae)
		al.sl.InsertInternal(res)
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

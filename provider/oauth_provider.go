// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package provider

import (
	//logger "github.com/juju/loggo"
	"sparrow/base"
	"sparrow/oauth"
	"sparrow/utils"
)

func (pr *Provider) GetClient(id string) (cl *oauth.Client) {
	rs, err := pr.sl.Get(id, pr.RsTypes["Application"])
	if err != nil {
		log.Debugf("Could not find the oauth client with id %s [%#v]", id, err)
		return nil
	}

	cl = &oauth.Client{}
	cl.ConsentRequired = rs.GetAttr("consentRequired").GetSimpleAt().Values[0].(bool)
	desc := rs.GetAttr("descritpion")
	if desc != nil {
		cl.Desc = desc.GetSimpleAt().GetStringVal()
	}

	cl.HasQueryInUri = rs.GetAttr("hasqueryinuri").GetSimpleAt().Values[0].(bool)
	cl.Id = rs.GetId()
	cl.Name = rs.GetAttr("name").GetSimpleAt().GetStringVal()
	cl.RedUri = rs.GetAttr("redirecturi").GetSimpleAt().GetStringVal()
	cl.Secret = rs.GetAttr("secret").GetSimpleAt().GetStringVal()
	ss := rs.GetAttr("serversecret").GetSimpleAt().GetStringVal()
	cl.ServerSecret = utils.B64Decode(ss)
	cl.Time = rs.GetMeta().GetValue("created").(int64)

	tmpResAt := rs.GetAttr("attributes")
	cl.Attributes = make(map[string]*base.SsoAttr)

	if tmpResAt != nil {
		resAt := tmpResAt.GetComplexAt()
		for _, subAt := range resAt.SubAts {
			ssoAt := &base.SsoAttr{}
			for _, at := range subAt {
				switch at.GetType().NormName {
				case "name":
					ssoAt.Name = at.GetStringVal()

				case "scimexpr":
					ssoAt.ScimExpr = at.GetStringVal()

				case "staticval":
					ssoAt.StaticVal = at.GetStringVal()

				case "staticmultivaldelim":
					ssoAt.StaticMultiValDelim = at.GetStringVal()
				}
			}
			cl.Attributes[ssoAt.Name] = ssoAt
		}
	}

	return cl
}

func (pr *Provider) StoreOauthSession(session *base.RbacSession) {
	pr.osl.StoreOauthSession(session)
}

func (pr *Provider) StoreSsoSession(session *base.RbacSession) {
	pr.osl.StoreSsoSession(session)
}

func (pr *Provider) RevokeOauthSession(ctx *base.OpContext, sessionToBeRevoked *base.RbacSession) {
	pr.osl.RevokeOauthSession(sessionToBeRevoked)
}

func (pr *Provider) IsRevokedSession(ctx *base.OpContext, session *base.RbacSession) bool {
	return pr.osl.IsRevokedSession(session)
}

func (pr *Provider) GetOauthSession(jti string) *base.RbacSession {
	return pr.osl.GetOauthSession(jti)
}

func (pr *Provider) GetSsoSession(jti string) *base.RbacSession {
	return pr.osl.GetSsoSession(jti)
}

func (pr *Provider) DeleteOauthSession(jti string) bool {
	return pr.osl.DeleteOauthSession(jti)
}

func (pr *Provider) DeleteSsoSession(jti string) bool {
	return pr.osl.DeleteSsoSession(jti)
}

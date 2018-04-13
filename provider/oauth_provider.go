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
	cl.Id = rs.GetId()
	cl.Name = safeGetStrVal("name", rs)
	cl.Desc = safeGetStrVal("descritpion", rs)
	cl.Time = rs.GetMeta().GetValue("created").(int64)

	oauthConf := &oauth.ClientOauthConf{}
	redUri := safeGetStrVal("redirecturi", rs)
	if len(redUri) > 0 {
		cl.Oauth = oauthConf
		oauthConf.RedUri = redUri
		oauthConf.ConsentRequired = rs.GetAttr("consentRequired").GetSimpleAt().Values[0].(bool)
		oauthConf.HasQueryInUri = rs.GetAttr("hasqueryinuri").GetSimpleAt().Values[0].(bool)
		oauthConf.Secret = safeGetStrVal("secret", rs)
		ss := safeGetStrVal("serversecret", rs)
		oauthConf.ServerSecret, _ = utils.B64Decode(ss) // safe to ignore error
		oauthAt := rs.GetAttr("oauthattributes")
		oauthConf.Attributes = parseSsoAttributes(oauthAt)
	}

	samlConf := &oauth.ClientSamlConf{}
	samlConf.ACSUrl = safeGetStrVal("acsurl", rs)
	samlConf.SLOUrl = safeGetStrVal("slourl", rs)
	samlConf.MetaUrl = safeGetStrVal("metaurl", rs)

	if len(samlConf.ACSUrl) > 0 || len(samlConf.MetaUrl) > 0 { // enable SAML only if ACS or Metadata URLs are not empty

		samlAt := rs.GetAttr("samlattributes")
		samlConf.Attributes = parseSsoAttributes(samlAt)

		validityAt := rs.GetAttr("assertionvalidity")
		if validityAt != nil {
			val := validityAt.GetSimpleAt().Values[0].(int64)
			samlConf.AssertionValidity = int(val)
		}

		cl.Saml = samlConf
	}

	cl.Cert = pr.Cert
	cl.PrivKey = pr.PrivKey
	return cl
}

func safeGetStrVal(atName string, rs *base.Resource) string {
	at := rs.GetAttr(atName)
	if at == nil {
		return ""
	}

	return at.GetSimpleAt().GetStringVal()
}

func parseSsoAttributes(tmpResAt base.Attribute) map[string]*base.SsoAttr {
	m := make(map[string]*base.SsoAttr)
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

				case "format":
					ssoAt.Format = at.GetStringVal()
				}
			}
			m[ssoAt.Name] = ssoAt
		}
	}

	return m
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

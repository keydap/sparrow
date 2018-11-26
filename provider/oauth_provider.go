// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package provider

import (
	//logger "github.com/juju/loggo"
	"encoding/hex"
	"encoding/xml"
	samlTypes "github.com/russellhaering/gosaml2/types"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/oauth"
	"strings"
)

func (pr *Provider) GetClientById(id string) (cl *oauth.Client) {
	rs, err := pr.sl.Get(id, pr.RsTypes["Application"])
	if err != nil {
		log.Debugf("Could not find the oauth client with id %s [%#v]", id, err)
		return nil
	}

	return pr._toClient(rs)
}

func (pr *Provider) GetClientByIssuer(issuer string) (cl *oauth.Client) {
	filter, _ := base.ParseFilter("spissuer EQ \"" + issuer + "\"")
	results := pr.sl.FindResources(filter, pr.RsTypes["Application"])
	if len(results) == 0 {
		return nil
	}

	return pr._toClient(results[0])
}

func (pr *Provider) GetAllClients() (clients []*oauth.Client) {
	filter, _ := base.ParseFilter("name PR")
	results := pr.sl.FindResources(filter, pr.RsTypes["Application"])

	clients = make([]*oauth.Client, len(results))

	for i, rs := range results {
		c := pr._toClient(rs)
		clients[i] = c
	}

	return clients
}

func (pr *Provider) _toClient(rs *base.Resource) (cl *oauth.Client) {
	cl = &oauth.Client{}
	cl.Id = rs.GetId()
	cl.Name = safeGetStrVal("name", rs)
	cl.Desc = safeGetStrVal("descritpion", rs)
	cl.Time = rs.GetMeta().GetValue("created").(int64)
	cl.HomeUrl = safeGetStrVal("homeurl", rs)
	cl.Icon = safeGetStrVal("icon", rs)

	groupIdsAt := rs.GetAttr("groupids")
	if groupIdsAt != nil {
		cl.GroupIds = make(map[string]int)
		gropIds := groupIdsAt.GetSimpleAt().Values
		for _, v := range gropIds {
			cl.GroupIds[v.(string)] = 1
		}
	}

	oauthConf := &oauth.ClientOauthConf{}
	redUri := safeGetStrVal("redirecturi", rs)
	if len(redUri) > 0 {
		cl.Oauth = oauthConf
		oauthConf.RedUri = redUri
		oauthConf.ConsentRequired = rs.GetAttr("consentRequired").GetSimpleAt().Values[0].(bool)
		oauthConf.HasQueryInUri = rs.GetAttr("hasqueryinuri").GetSimpleAt().Values[0].(bool)
		oauthConf.Secret = safeGetStrVal("secret", rs)
		ss := safeGetStrVal("serversecret", rs)
		oauthConf.ServerSecret, _ = hex.DecodeString(ss) // safe to ignore error
		oauthAt := rs.GetAttr("oauthattributes")
		oauthConf.Attributes = parseSsoAttributes(oauthAt)

		validityAt := rs.GetAttr("tokenvalidity")
		var tokenValidity int64
		if validityAt != nil {
			tokenValidity = validityAt.GetSimpleAt().Values[0].(int64)
		}
		if tokenValidity <= 0 {
			tokenValidity = 120 // 2 minutes is the default
		}
		oauthConf.TokenValidity = tokenValidity
	}

	samlConf := &oauth.ClientSamlConf{}
	samlConf.SpIssuer = safeGetStrVal("spissuer", rs)
	samlConf.MetaUrl = safeGetStrVal("metaurl", rs)
	if len(samlConf.MetaUrl) > 0 {
		spmd := pr.SamlMdCache[samlConf.SpIssuer]
		if spmd == nil {
			spmd, err := parseMetadata(samlConf.MetaUrl)
			if err != nil {
				log.Warningf("failed to parse the SAML metadata of app %s from location %s", cl.Name, samlConf.MetaUrl)
			} else {
				pr.SamlMdCache[samlConf.SpIssuer] = spmd
			}
		}
		samlConf.MetaData = spmd
	}

	samlConf.SLOUrl = safeGetStrVal("slourl", rs)
	samlConf.IdpIssuer = safeGetStrVal("idpissuer", rs)

	samlAt := rs.GetAttr("samlattributes")
	samlConf.Attributes = parseSsoAttributes(samlAt)

	validityAt := rs.GetAttr("assertionValidity")
	var assertionValidity int64
	if validityAt != nil {
		assertionValidity = validityAt.GetSimpleAt().Values[0].(int64)
	}
	if assertionValidity <= 0 {
		assertionValidity = 120 // 2 minutes is the default
	}
	samlConf.AssertionValidity = assertionValidity

	cl.Saml = samlConf

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
					ssoAt.NormName = strings.ToLower(ssoAt.Name)

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

func (pr *Provider) DeleteOauthSession(opCtx *base.OpContext) bool {
	deleted := pr.osl.DeleteOauthSession(opCtx.Session.Jti)
	pr.Al.LogDelSession(opCtx, deleted)
	return deleted
}

func (pr *Provider) DeleteSsoSession(opCtx *base.OpContext) bool {
	deleted := pr.osl.DeleteSsoSession(opCtx.Session.Jti)
	pr.Al.LogDelSession(opCtx, deleted)
	return deleted
}

func parseMetadata(location string) (spmd *samlTypes.SPSSODescriptor, err error) {
	// TODO add support for trusting self-signed certificates
	resp, err := http.Get(location)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = xml.Unmarshal(data, spmd)
	if err != nil {
		return nil, err
	}

	return spmd, err
}

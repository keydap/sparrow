// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package provider

import (
	//logger "github.com/juju/loggo"
	"sparrow/base"
	"sparrow/oauth"
)

func (pr *Provider) AddClient(ctx *base.OpContext, cl *oauth.Client) (err error) {
	return pr.osl.AddClient(cl)
}

func (pr *Provider) DeleteClient(ctx *base.OpContext, id string) error {
	return pr.osl.DeleteClient(id)
}

func (pr *Provider) GetClient(id string) (cl *oauth.Client) {
	return pr.osl.GetClient(id)
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

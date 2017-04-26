// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"fmt"
	"net/http"
	"net/url"
	"sparrow/base"
	"sparrow/oauth"
	"sparrow/utils"
	"strings"
	"time"
)

// STEP 1 Client sends the request to the Authorization Server
// Handles the OAuth2 authorization request
func authorize(w http.ResponseWriter, r *http.Request) {

	session := getSession(r)
	if session != nil {
		// valid session exists serve the code or id_token
		log.Debugf("Valid session exists, sending the final response")
		sendFinalResponse(w, r, session, nil)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Debugf("Failed to parse the oauth request %s", err)
		sendOauthError(w, r, "", err)
		return
	}

	af := &authFlow{}
	af.FromOauth = true

	setAuthFlow(af, w)
	paramMap := make(map[string]string)

	for k, v := range r.Form {
		if len(v) > 1 {
			err = fmt.Errorf("Invalid request the parameter %s is included more than once", k)
			sendOauthError(w, r, "", err)
			return
		}

		paramMap[k] = v[0]
	}

	// do a redirect to /login with all the parameters
	redirect("/login", w, r, paramMap)
}

// STEP 2 Authorization Server Authenticates the End-User
// show login form
func showLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	paramMap := copyParams(r)

	ologin := templates["login.html"]
	ologin.Execute(w, paramMap)
}

// STEP 2 Authorization Server Authenticates the End-User
func verifyPassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Debugf("Failed to parse the oauth request %s", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	domain := defaultDomain

	pos := strings.LastIndexByte(username, '@')
	unameLen := len(username) - 1
	if pos > 0 && pos != unameLen {
		username = username[:pos]
		domain = strings.ToLower(username[pos+1:])
	}

	prv := providers[domain]

	paramMap := copyParams(r)
	delete(paramMap, "username")
	delete(paramMap, "password")

	if prv == nil {
		login := templates["login.html"]
		login.Execute(w, paramMap)
		return
	}

	user := prv.Authenticate(username, password)
	if user == nil {
		login := templates["login.html"]
		login.Execute(w, paramMap)
		return
	}

	session := prv.GenSessionForUser(user)
	osl.StoreSsoSession(session)

	cookie := &http.Cookie{}
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(time.Duration(prv.Config.Oauth.SsoSessionIdleTime) * time.Second)
	cookie.HttpOnly = true
	cookie.Name = SSO_COOKIE
	cookie.Value = session.Jti
	//cookie.Secure
	http.SetCookie(w, cookie)

	af := getAuthFlow(r)

	if af == nil {
		af = &authFlow{}
	}

	if af.FromOauth {
		af.PsVerified = true
		// TODO enable it when the account has TFA capability
		af.TfaRequired = false
		af.UserId = user.GetId()
		af.DomainCode = prv.DomainCode()
		setAuthFlow(af, w)
		login := templates["consent.html"]
		login.Execute(w, paramMap)
		return
	}

	w.Write([]byte("password verified"))
}

// STEP 3. Authorization Server obtains End-User Consent/Authorization.
func verifyConsent(w http.ResponseWriter, r *http.Request) {
	af := getAuthFlow(r)

	if af != nil {
		if af.PsVerified {
			r.ParseForm()
			consent := r.Form.Get("consent")
			if consent == "authorize" {
				sendFinalResponse(w, r, nil, af)
			} else {
				clientId := r.Form.Get("client_id")
				cl := osl.GetClient(clientId)
				ep := &oauth.ErrorResp{}
				ep.State = r.Form.Get("state")
				if cl == nil {
					ep.Desc = "Invalid client ID " + clientId
					ep.Err = oauth.ERR_INVALID_REQUEST
				} else {
					ep.Desc = "User did not authorize the request"
					ep.Err = oauth.ERR_ACCESS_DENIED
				}
				sendOauthError(w, r, cl.RedUri, ep)
			}
		}
	}
}

// STEP 4 Authorization Server sends the End-User back to the Client with an Authorization Code
func sendFinalResponse(w http.ResponseWriter, r *http.Request, session *base.RbacSession, af *authFlow) {
	err := r.ParseForm()
	if err != nil {
		log.Debugf("Failed to parse the form, sending error to the user agent")
		sendOauthError(w, r, "", err)
		return
	}

	areq := oauth.ParseAuthzReq(r)

	valid := isValidAuthzReq(w, r, areq)

	if !valid {
		return
	}

	log.Debugf("Received authorization request is valid, searching for client")

	cl := osl.GetClient(areq.ClientId)
	if cl == nil {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid client ID " + areq.ClientId
		log.Debugf(ep.Desc)
		ep.Err = oauth.ERR_INVALID_REQUEST
		ep.State = areq.State
		sendOauthError(w, r, areq.RedUri, ep)
		return
	}

	if cl.RedUri != areq.RedUri {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Mismatched redirect URI. Registered URI of the client is not matching with the value of redirect_uri parameter"
		log.Debugf(ep.Desc)
		ep.Err = oauth.ERR_INVALID_REQUEST
		ep.State = areq.State
		sendOauthError(w, r, areq.RedUri, ep)
		return
	}

	// send code to the redirect URI
	tmpUri := cl.RedUri
	if cl.HasQueryInUri {
		tmpUri += "&"
	} else {
		tmpUri += "?"
	}

	cType := OAuth2
	if _, ok := areq.Scopes["openid"]; ok {
		cType = OIDC
	}

	// check the response_type
	// supported types are "code", "id_token" and "code id_token"

	hasCode := false
	if areq.RespType == "code" || strings.HasPrefix(areq.RespType, "code ") {
		ttl := time.Now()
		var userId string
		var domainCode uint32

		if af != nil {
			userId = af.UserId
			domainCode = af.DomainCode
		} else {
			// can happen when there is a redirect for consent
			if session == nil {
				session = getSession(r)
			}

			userId = session.Sub
			domainCode = providers[session.Domain].DomainCode()
		}
		code := newOauthCode(cl, ttl, userId, domainCode, cType)
		tmpUri += ("code=" + url.QueryEscape(code))
		hasCode = true
	}

	if !hasCode && cType == OAuth2 {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid response type for non-OpenIdConnect request" + areq.RespType
		ep.Err = oauth.ERR_INVALID_REQUEST
		ep.State = areq.State
		sendOauthError(w, r, areq.RedUri, ep)
		return
	}

	// can happen when there is a redirect for consent
	if session == nil {
		session = getSession(r)
	}

	if areq.RespType == "id_token" || strings.HasSuffix(areq.RespType, " id_token") {
		// create RbacSession and then generate ID Token
		idt := createIdToken(session, cl)
		idt.Nonce = areq.Nonce
		strIdt := idt.ToJwt(srvConf.PrivKey)
		if hasCode {
			tmpUri += "&"
		}

		tmpUri += ("id_token=" + url.QueryEscape(strIdt))
	}

	state := r.Form.Get("state")

	if len(state) > 0 {
		tmpUri += "&state=" + state
	}

	log.Debugf("redirecting to the client with response")

	// delete the authflow cookie
	setAuthFlow(nil, w)
	http.Redirect(w, r, tmpUri, http.StatusFound)

	// ignore the received redirect URI
	/*
		if cl.RedUri != areq.RedUri {
			ep := &oauth.ErrorResp{}
			ep.Desc = "Mismatching redirect URI " + areq.RedUri
			ep.Err = oauth.ERR_INVALID_REQUEST
			ep.State = areq.State
			sendOauthError(w, r, areq, ep)
			return
		}
	*/
}

func createIdToken(session *base.RbacSession, cl *oauth.Client) oauth.IdToken {
	idt := oauth.IdToken{}
	idt.Aud = cl.RedUri
	idt.AuthTime = session.Iat
	idt.Domain = session.Domain
	idt.Iat = time.Now().Unix()
	idt.Exp = idt.Iat + 600 // TODO config
	idt.Iss = issuerUrl
	idt.Jti = utils.NewRandShaStr()
	idt.Sub = session.Sub

	return idt
}

func getSession(r *http.Request) *base.RbacSession {
	ssoCookie, _ := r.Cookie(SSO_COOKIE)

	if ssoCookie != nil {
		session := osl.GetSsoSession(ssoCookie.Value)
		if (session != nil) && !session.IsExpired() {
			return session
		}
	}

	return nil
}

func isValidAuthzReq(w http.ResponseWriter, r *http.Request, areq *oauth.AuthorizationReq) bool {
	log.Debugf("Validating authorization request")

	errStr := ""
	if areq.RespType == "" {
		errStr = "No response_type parameter is present. "
	}

	if (areq.RespType != "code") && (areq.RespType != "code id_token") && (areq.RespType != "id_token") {
		errStr = "Unsupported response type " + areq.RespType + ". Only 'code', 'code id_token' and 'id_token' are supported. "
	}

	if areq.RespType == "" {
		errStr += "No client_id parameter is present. "
	}

	if len(errStr) == 0 {
		return true
	}

	ep := &oauth.ErrorResp{}
	ep.Desc = errStr
	ep.Err = oauth.ERR_INVALID_REQUEST
	sendOauthError(w, r, areq.RedUri, ep)

	return false
}
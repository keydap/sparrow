// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"net/url"
	"sparrow/base"
	"sparrow/oauth"
	"sparrow/provider"
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
	af.SetFromOauth(true)

	setAuthFlow(af, w)
	paramMap, err := parseParamMap(r)
	if err != nil {
		sendOauthError(w, r, "", err)
		return
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

func showOtpPage(w http.ResponseWriter, paramMap map[string]string) {
	totp := templates["totp-send.html"]
	totp.Execute(w, paramMap)
}

func showChangePasswordPage(w http.ResponseWriter, paramMap map[string]string) {
	cp := templates["changepassword.html"]
	cp.Execute(w, paramMap)
}

// STEP 2 Authorization Server Authenticates the End-User
func verifyPassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Debugf("Failed to parse the oauth request %s", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	af := getAuthFlow(r)

	if af == nil {
		af = &authFlow{}
	}

	paramMap := copyParams(r)

	domain := defaultDomain
	var prv *provider.Provider

	username := r.Form.Get("username")
	if !af.VerifiedPassword() {
		pos := strings.LastIndexByte(username, '@')
		unameLen := len(username) - 1
		if pos > 0 && pos != unameLen {
			username = username[:pos]
			domain = strings.ToLower(username[pos+1:])
		}
		prv = providers[domain]
	} else {
		prv = dcPrvMap[af.DomainCode]
	}

	if prv == nil {
		login := templates["login.html"]
		login.Execute(w, paramMap)
		return
	}

	if !af.VerifiedPassword() {
		password := r.Form.Get("password")

		delete(paramMap, "username")
		delete(paramMap, "password")

		lr := prv.Authenticate(username, password)
		if lr.Status == base.LOGIN_FAILED {
			login := templates["login.html"]
			login.Execute(w, paramMap)
			return
		} else if lr.Status == base.LOGIN_SUCCESS {
			af.SetPasswordVerified(true)
			af.UserId = lr.Id
			af.DomainCode = prv.DomainCode()
			setAuthFlow(af, w) // FIXME shouldn't af be set to nil here?
			setSessionCookie(lr.User, af, prv, w, r, paramMap)
			return
		}

		log.Debugf("password verified")

		af.SetPasswordVerified(true)
		af.UserId = lr.Id
		af.DomainCode = prv.DomainCode()

		// check TFA settings and enable appropriate flags
		if lr.Status == base.LOGIN_TFA_REGISTER {
			af.SetTfaRegister(true)
		} else if lr.Status == base.LOGIN_TFA_REQUIRED {
			af.SetTfaRequired(true)
		} else if lr.Status == base.LOGIN_CHANGE_PASSWORD {
			af.SetChangePassword(true)
		}

		setAuthFlow(af, w)

		if af.RegisterTfa() {
			showTotpRegistration(username, prv, af, w, paramMap)
			return
		}

		if af.ChangePassword() {
			showChangePasswordPage(w, paramMap)
			return
		}
	}

	if af.ChangePassword() {
		newPassword := r.Form.Get("newPassword")
		cnfNewPassword := r.Form.Get("cnfNewPassword")
		delete(paramMap, "newPassword")
		delete(paramMap, "cnfNewPassword")
		if newPassword != cnfNewPassword {
			paramMap["errMsg"] = "New passwords didn't match"
			showChangePasswordPage(w, paramMap)
			return
		}

		user, err := prv.ChangePassword(af.UserId, newPassword)
		if err != nil {
			showChangePasswordPage(w, paramMap)
			return
		} else {
			af.SetChangePassword(false)
			setAuthFlow(nil, w)
			setSessionCookie(user, af, prv, w, r, paramMap)
			return
		}
	}

	if af.RequiredTfa() {
		otp := r.Form.Get("otp")
		delete(paramMap, "otp")

		if otp == "" {
			showOtpPage(w, paramMap)
			return
		}

		lr := prv.VerifyOtp(af.UserId, otp)
		if lr.Status == base.LOGIN_FAILED {
			showOtpPage(w, paramMap)
			return
		} else if lr.Status == base.LOGIN_SUCCESS {
			setAuthFlow(nil, w)
			setSessionCookie(lr.User, af, prv, w, r, paramMap)
		} else if lr.Status == base.LOGIN_CHANGE_PASSWORD {
			af.SetChangePassword(true)
			setAuthFlow(af, w)
			showChangePasswordPage(w, paramMap)
		}
	}
}

// STEP 3. Authorization Server obtains End-User Consent/Authorization.
func verifyConsent(w http.ResponseWriter, r *http.Request) {
	af := getAuthFlow(r)

	if af != nil {
		if af.VerifiedPassword() {
			r.ParseForm()
			consent := r.Form.Get("consent")
			if consent == "authorize" {
				sendFinalResponse(w, r, nil, af)
			} else {
				clientId := r.Form.Get("client_id")
				pr, _ := getPrFromParam(r)
				var cl *oauth.Client
				if pr != nil {
					cl = pr.GetClient(clientId)
				}
				ep := &oauth.ErrorResp{}
				ep.State = r.Form.Get("state")
				if cl == nil {
					ep.Desc = "Invalid client ID " + clientId
					ep.Err = oauth.ERR_INVALID_REQUEST
				} else {
					ep.Desc = "User did not authorize the request"
					ep.Err = oauth.ERR_ACCESS_DENIED
				}
				sendOauthError(w, r, cl.Oauth.RedUri, ep)
			}
		}
	} else {
		setAuthFlow(nil, w)
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
		// FIXME return a meaningful error response
		return
	}

	log.Debugf("Received authorization request is valid, searching for client")

	pr, _ := getPrFromParam(r)
	var cl *oauth.Client
	if pr != nil {
		cl = pr.GetClient(areq.ClientId)
	}

	if cl == nil {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid client ID " + areq.ClientId
		log.Debugf(ep.Desc)
		ep.Err = oauth.ERR_INVALID_REQUEST
		ep.State = areq.State
		sendOauthError(w, r, areq.RedUri, ep)
		return
	}

	if cl.Oauth.RedUri != areq.RedUri {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Mismatched redirect URI. Registered URI of the client is not matching with the value of redirect_uri parameter"
		log.Debugf(ep.Desc)
		ep.Err = oauth.ERR_INVALID_REQUEST
		ep.State = areq.State
		sendOauthError(w, r, areq.RedUri, ep)
		return
	}

	// send code to the redirect URI
	tmpUri := cl.Oauth.RedUri
	if cl.Oauth.HasQueryInUri {
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
		idt := createIdToken(session, cl, pr)
		idt["nonce"] = areq.Nonce // TODO set the nonce to the UUID of the session
		strIdt := oauth.ToJwt(idt, srvConf.PrivKey)
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

func createIdToken(session *base.RbacSession, cl *oauth.Client, pr *provider.Provider) jwt.MapClaims {
	idt := jwt.MapClaims{}

	user, err := pr.GetUserById(session.Sub)
	if err != nil {
		// TODO what to do?? return empty claims?
		return idt
	}

	for _, ssoAt := range cl.Oauth.Attributes {
		ssoAt.GetValueInto(user, idt)
	}

	idt["aud"] = cl.Oauth.RedUri
	idt["d"] = session.Domain
	iat := time.Now().Unix()
	idt["iat"] = iat
	idt["exp"] = iat + 600 // TODO config
	idt["iss"] = issuerUrl
	idt["jti"] = utils.NewRandShaStr()
	idt["sub"] = session.Sub

	return idt
}

func getSession(r *http.Request) *base.RbacSession {
	ssoCookie, _ := r.Cookie(SSO_COOKIE)

	if ssoCookie != nil {
		pr, _ := getPrFromParam(r)
		var session *base.RbacSession

		if pr != nil {
			session = pr.GetSsoSession(ssoCookie.Value)
		}

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

func setSessionCookie(user *base.Resource, af *authFlow, prv *provider.Provider, w http.ResponseWriter, r *http.Request, paramMap map[string]string) *base.RbacSession {
	session := prv.GenSessionForUser(user)
	prv.StoreSsoSession(session)

	cookie := &http.Cookie{}
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(time.Duration(prv.Config.Oauth.SsoSessionIdleTime) * time.Second)
	cookie.HttpOnly = true
	cookie.Name = SSO_COOKIE
	cookie.Value = session.Jti
	//cookie.Secure
	http.SetCookie(w, cookie)

	if af.FromOauth() {
		// FIXME show consent only if application/client config enforces it
		login := templates["consent.html"]
		login.Execute(w, paramMap)
		return session
	} else if af.FromSaml() {
		log.Debugf("resuming SAML flow")
		sendSamlResponse(w, r, session, af)
		return session
	}

	http.Redirect(w, r, "/ui", http.StatusFound)

	return session
}

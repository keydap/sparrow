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
func (sp *Sparrow) authorize(w http.ResponseWriter, r *http.Request) {

	session := getSessionUsingCookie(r, sp)
	if session != nil {
		// valid session exists serve the code or id_token
		log.Debugf("Valid session exists, sending the final response")
		sendFinalResponse(sp, w, r, session, nil)
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

	setAuthFlow(sp, af, w)
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
func (sp *Sparrow) showLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	paramMap := copyParams(r)

	ologin := sp.templates["login.html"]
	ologin.Execute(w, paramMap)
}

func showOtpPage(sp *Sparrow, w http.ResponseWriter, paramMap map[string]string) {
	totp := sp.templates["totp-send.html"]
	totp.Execute(w, paramMap)
}

func showChangePasswordPage(sp *Sparrow, w http.ResponseWriter, paramMap map[string]string) {
	cp := sp.templates["changepassword.html"]
	cp.Execute(w, paramMap)
}

// STEP 2 Authorization Server Authenticates the End-User
func (sp *Sparrow) verifyPassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Debugf("Failed to parse the login form %s", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	af := getAuthFlow(r, sp)

	if af == nil {
		log.Debugf("authflow data is nil, initializing")
		af = &authFlow{}
	}

	paramMap := copyParams(r)

	domain := sp.srvConf.DefaultDomain
	var prv *provider.Provider

	username := r.Form.Get("username")
	if !af.VerifiedPassword() {
		pos := strings.LastIndexByte(username, '@')
		unameLen := len(username) - 1
		if pos > 0 && pos != unameLen {
			domain = strings.ToLower(username[pos+1:])
			username = username[:pos]
		}
		prv = sp.providers[domain]
	} else {
		prv = sp.dcPrvMap[af.DomainCode]
	}

	if prv == nil {
		login := sp.templates["login.html"]
		login.Execute(w, paramMap)
		return
	}

	if !af.VerifiedPassword() {
		password := r.Form.Get("password")

		delete(paramMap, "username")
		delete(paramMap, "password")

		ar := base.AuthRequest{Username: username, Password: password, ClientIP: utils.GetRemoteAddr(r)}
		lr := prv.Authenticate(ar)
		if lr.Status == base.LOGIN_FAILED {
			login := sp.templates["login.html"]
			login.Execute(w, paramMap)
			return
		} else if lr.Status == base.LOGIN_SUCCESS {
			af.SetPasswordVerified(true)
			af.markLoginSuccessful()
		} else if lr.Status == base.LOGIN_TFA_REGISTER { // check TFA settings and enable appropriate flags
			af.SetTfaRegister(true)
		} else if lr.Status == base.LOGIN_TFA_REQUIRED {
			af.SetTfaRequired(true)
		} else if lr.Status == base.LOGIN_CHANGE_PASSWORD {
			af.SetChangePassword(true)
		}

		log.Debugf("password verified")

		af.SetPasswordVerified(true)
		af.UserId = lr.Id
		af.DomainCode = prv.DomainCode()

		if af.RegisterTfa() {
			showTotpRegistration(username, prv, af, w, paramMap, sp)
			return
		}

		if af.ChangePassword() {
			setAuthFlow(sp, af, w)
			showChangePasswordPage(sp, w, paramMap)
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
			showChangePasswordPage(sp, w, paramMap)
			return
		}

		_, err := prv.ChangePassword(af.UserId, newPassword, utils.GetRemoteAddr(r))
		if err != nil {
			showChangePasswordPage(sp, w, paramMap)
			return
		} else {
			af.SetChangePassword(false)
			af.markLoginSuccessful()
		}
	}

	if af.RequiredTfa() {
		otp := r.Form.Get("otp")
		delete(paramMap, "otp")

		if otp == "" {
			setAuthFlow(sp, af, w)
			showOtpPage(sp, w, paramMap)
			return
		}

		log.Debugf("verifying otp")
		lr := prv.VerifyOtp(af.UserId, otp, utils.GetRemoteAddr(r))
		if lr.Status == base.LOGIN_FAILED {
			showOtpPage(sp, w, paramMap)
			return
		} else if lr.Status == base.LOGIN_SUCCESS {
			af.SetTfaRequired(false)
			setAuthFlow(sp, af, w)
			af.markLoginSuccessful()
		} else if lr.Status == base.LOGIN_CHANGE_PASSWORD {
			af.SetChangePassword(true)
			af.SetTfaRequired(false) // otp has been validated earlier, so not required again
			setAuthFlow(sp, af, w)
			showChangePasswordPage(sp, w, paramMap)
			return
		}
	}

	redirectToUrl(sp, af, prv, w, r, paramMap)
}

// STEP 3. Authorization Server obtains End-User Consent/Authorization.
func (sp *Sparrow) verifyConsent(w http.ResponseWriter, r *http.Request) {
	af := getAuthFlow(r, sp)

	if af != nil {
		log.Debugf("verifying consent...")
		if af.isLoginSuccessful() {
			r.ParseForm()
			consent := r.Form.Get("consent")
			if consent == "authorize" {
				log.Debugf("sending final response in oauth flow")
				sendFinalResponse(sp, w, r, nil, af)
			} else {
				clientId := r.Form.Get("client_id")
				pr, _ := getPrFromParam(r, sp)
				var cl *oauth.Client
				if pr != nil {
					cl = pr.GetClientById(clientId)
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
				log.Debugf("%s", ep.Desc)
				sendOauthError(w, r, cl.Oauth.RedUri, ep)
			}
		}
	} else {
		log.Debugf("received request for verifying consent but authflow cookie is missing")
		setAuthFlow(sp, nil, w)
	}
}

// STEP 4 Authorization Server sends the End-User back to the Client with an Authorization Code
func sendFinalResponse(sp *Sparrow, w http.ResponseWriter, r *http.Request, session *base.RbacSession, af *authFlow) {
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

	pr, _ := getPrFromParam(r, sp)
	var cl *oauth.Client
	if pr != nil {
		cl = pr.GetClientById(areq.ClientId)
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
		var domainCode string

		if af != nil {
			userId = af.UserId
			domainCode = af.DomainCode
		} else {
			// can happen when there is a redirect for consent
			if session == nil {
				session = getSessionUsingCookie(r, sp)
			}

			userId = session.Sub
			domainCode = sp.providers[session.Domain].DomainCode()
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
		session = getSessionUsingCookie(r, sp)
	}

	if areq.RespType == "id_token" || strings.HasSuffix(areq.RespType, " id_token") {
		// create RbacSession and then generate ID Token
		idt := createIdToken(sp, session, cl, pr)
		idt["nonce"] = areq.Nonce
		strIdt := oauth.ToJwt(idt, sp.srvConf.PrivKey)
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
	setAuthFlow(sp, nil, w)
	headers := w.Header()
	headers.Add("Cache-Control", "no-store")
	headers.Add("Pragma", "no-cache")
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

func createIdToken(sp *Sparrow, session *base.RbacSession, cl *oauth.Client, pr *provider.Provider) jwt.MapClaims {
	idt := jwt.MapClaims{}

	user, err := pr.GetUserById(session.Sub)
	if err != nil {
		// TODO what to do?? return empty claims?
		return idt
	}

	for _, ssoAt := range cl.Oauth.Attributes {
		ssoAt.GetValueInto(user, idt)
	}

	idt["aud"] = cl.Id
	idt["d"] = session.Domain
	iat := time.Now().Unix()
	idt["iat"] = iat
	idt["exp"] = iat + cl.Oauth.TokenValidity
	idt["iss"] = sp.homeUrl + "/" + session.Domain
	idt["jti"] = utils.NewRandShaStr()
	// if sub is not already filled with custom attribute config
	// fill it with the default value
	if _, ok := idt["sub"]; !ok {
		idt["sub"] = session.Sub
	}

	// the below claims are not supported yet
	// and deleting them as a defense against spoofing them using app attribute configuration
	delete(idt, "acr")
	delete(idt, "amr")
	delete(idt, "azp")

	return idt
}

func getSessionUsingCookie(r *http.Request, sp *Sparrow) *base.RbacSession {
	ssoCookie, _ := r.Cookie(SSO_COOKIE)

	if ssoCookie != nil {
		pr, _ := getPrFromParam(r, sp)
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

func redirectToUrl(sp *Sparrow, af *authFlow, prv *provider.Provider, w http.ResponseWriter, r *http.Request, paramMap map[string]string) {
	if !af.isLoginSuccessful() {
		log.Debugf("login is not marked as successful returning to login page")
		setAuthFlow(sp, nil, w)
		sp.showLogin(w, r)
		return
	}

	user, err := prv.GetUserById(af.UserId)
	if err != nil {
		log.Debugf("could not find the authenticated user. [%v]", err)
		setAuthFlow(sp, nil, w)
		sp.showLogin(w, r)
		return
	}

	if af.FromOauth() || af.FromSaml() {
		log.Debugf("oauth/saml workflow")
		setSessionCookie(sp, user, af, prv, w, r, paramMap)
		return
	} else {
		rt := paramMap[PARAM_REDIRECT_TO]
		if rt != "" {
			log.Debugf("redirecting to %s after authentication", rt)
			setSessionCookie(sp, user, af, prv, w, r, paramMap)
			return
		}
	}

	log.Debugf("successfully authenticated, there is no redirect parameter, not creating session")
	setAuthFlow(sp, nil, w)
	// close the window
	if paramMap["cl"] == "1" {
		script := `<script type="text/javascript">window.close();</script>`
		w.Write([]byte(script))
	}
}

func setSessionCookie(sp *Sparrow, user *base.Resource, af *authFlow, prv *provider.Provider, w http.ResponseWriter, r *http.Request, paramMap map[string]string) *base.RbacSession {
	session := prv.GenSessionForUser(user)
	prv.StoreSsoSession(session)

	setSsoCookie(prv, session, w)

	if af.FromOauth() {
		log.Debugf("sending oauth request for consent")
		// FIXME show consent only if application/client config enforces it
		setAuthFlow(sp, af, w)
		consentTmpl := sp.templates["consent.html"]
		consentTmpl.Execute(w, paramMap)
		return session
	} else if af.FromSaml() {
		log.Debugf("resuming SAML flow")
		setAuthFlow(sp, nil, w)
		sendSamlResponse(sp, w, r, session, af)
		return session
	}

	setAuthFlow(sp, nil, w)

	rt := paramMap[PARAM_REDIRECT_TO]
	http.Redirect(w, r, rt, http.StatusFound)

	return session
}

func (sp *Sparrow) handleChangePasswordReq(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	paramMap := copyParams(r)
	path := "/login"
	query := "?"
	for k, v := range paramMap {
		k = url.QueryEscape(k) + "=" + url.QueryEscape(v)
		query = query + k
	}
	if query != "?" {
		path += query
	}

	af := &authFlow{}
	af.SetChangePassword(true)
	setAuthFlow(sp, af, w)
	http.Redirect(w, r, path, http.StatusFound)
}

func setSsoCookie(pr *provider.Provider, session *base.RbacSession, w http.ResponseWriter) {
	cookie := &http.Cookie{}
	cookie.Path = "/"
	cookie.MaxAge = pr.Config.Oauth.SsoSessionMaxLife
	cookie.Expires = time.Now().Add(time.Duration(cookie.MaxAge) * time.Second)
	cookie.HttpOnly = true
	cookie.SameSite = http.SameSiteStrictMode
	cookie.Name = SSO_COOKIE
	cookie.Value = session.Jti
	//cookie.Secure
	http.SetCookie(w, cookie)
}

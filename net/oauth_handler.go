// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"bytes"
	"encoding/gob"
	"net/http"
	"net/url"
	"sparrow/oauth"
	"sparrow/utils"
	"strings"
	"time"
)

// the authflow cookie
const AUTHFLOW_COOKIE string = "_afc"
const BASIC_AUTHZ_PREFIX string = "Basic "

// the number of seconds an oauth code is valid for
const OAUTH_CODE_TTL int = 600

const (
	verified_password = 1 << iota
	verified_tfa
	required_tfa
	from_oauth
	from_saml
	register_tfa
	change_password
	login_complete // flag when set indicates that login is verified including all factors
)

type authFlow struct {
	BitFlag         uint16 // holds the state of login options in various bits
	UserId          string
	DomainCode      string
	TotpSecret      string // the TOTP 2F secret
	PasswdFailCount uint8
	OtpFailCount    uint8
}

func (af *authFlow) setBit(bit uint16, yes bool) {
	if yes {
		af.BitFlag |= bit
	} else {
		af.BitFlag &= ^bit
	}
}

func (af *authFlow) isSet(bit uint16) bool {
	return (af.BitFlag & bit) == bit
}

func (af *authFlow) VerifiedPassword() bool {
	return af.isSet(verified_password)
}

func (af *authFlow) SetPasswordVerified(yes bool) {
	af.setBit(verified_password, yes)
}

func (af *authFlow) VerifiedTfa() bool {
	return af.isSet(verified_tfa)
}

func (af *authFlow) SetTfaVerified(yes bool) {
	af.setBit(verified_tfa, yes)
}

func (af *authFlow) RequiredTfa() bool {
	return af.isSet(required_tfa)
}

func (af *authFlow) SetTfaRequired(yes bool) {
	af.setBit(required_tfa, yes)
}

func (af *authFlow) RegisterTfa() bool {
	return af.isSet(register_tfa)
}

func (af *authFlow) SetTfaRegister(yes bool) {
	af.setBit(register_tfa, yes)
}

//func (af *authFlow) GrantedAuthz() bool {
//}

func (af *authFlow) FromOauth() bool {
	return af.isSet(from_oauth)
}

func (af *authFlow) SetFromOauth(yes bool) {
	af.setBit(from_oauth, yes)
}

func (af *authFlow) FromSaml() bool {
	return af.isSet(from_saml)
}

func (af *authFlow) SetFromSaml(yes bool) {
	af.setBit(from_saml, yes)
}

func (af *authFlow) SetChangePassword(yes bool) {
	af.setBit(change_password, yes)
}

func (af *authFlow) ChangePassword() bool {
	return af.isSet(change_password)
}

func (af *authFlow) markLoginSuccessful() {
	af.setBit(login_complete, true)
}

func (af *authFlow) isLoginSuccessful() bool {
	return af.isSet(login_complete)
}

func (af *authFlow) IncPasswdFailCount() {
	af.PasswdFailCount++
}

func (af *authFlow) IncOtpFailCount() {
	af.OtpFailCount++
}

func (sp *Sparrow) sendToken(w http.ResponseWriter, r *http.Request) {
	atr, err := oauth.ParseAccessTokenReq(r)
	if err != nil {
		log.Debugf("Sending error to the oauth client %s", atr.ClientId)
		sendOauthError(w, r, "", err)
		return
	}

	authzHeader := r.Header.Get("Authorization")
	if len(authzHeader) != 0 {
		pos := strings.Index(authzHeader, BASIC_AUTHZ_PREFIX)
		if pos != 0 {
			ep := &oauth.ErrorResp{}
			ep.Desc = "Unsupported authorization type, only Basic is supported"
			ep.Err = oauth.ERR_INVALID_REQUEST
			sendOauthError(w, r, "", ep)
			return
		}

		decodedSecret, err := utils.B64Decode(authzHeader[len(BASIC_AUTHZ_PREFIX):])
		if err != nil {
			ep := &oauth.ErrorResp{}
			ep.Desc = "Failed to decode authorization header"
			ep.Err = oauth.ERR_INVALID_REQUEST
			sendOauthError(w, r, "", ep)
			return
		}

		idSecretPair := string(decodedSecret)
		tokens := strings.Split(idSecretPair, ":")
		if len(tokens) != 2 {
			ep := &oauth.ErrorResp{}
			ep.Desc = "Invalid authorization header"
			ep.Err = oauth.ERR_INVALID_REQUEST
			sendOauthError(w, r, "", ep)
			return
		}

		atr.ClientId = tokens[0]
		atr.Secret = tokens[1]
	}

	invalidCreds := &oauth.ErrorResp{}
	invalidCreds.Desc = "Invalid client ID or secret"
	invalidCreds.Err = oauth.ERR_INVALID_REQUEST

	var cl *oauth.Client

	pr, _ := getPrFromParam(r, sp)
	if pr != nil {
		cl = pr.GetClientById(atr.ClientId)
	}

	if cl == nil {
		log.Debugf("Client not found with the id %s", atr.ClientId)
		sendOauthError(w, r, "", invalidCreds)
		return
	}

	if atr.Secret != cl.Oauth.Secret {
		log.Debugf("Invalid secret of the client %s [%s != %s]", atr.ClientId, atr.Secret, cl.Oauth.Secret)
		sendOauthError(w, r, "", invalidCreds)
		return
	}

	ac := decryptOauthCode(atr.Code, cl)
	if ac == nil {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid code"
		ep.Err = oauth.ERR_INVALID_REQUEST
		sendOauthError(w, r, "", ep)
		return
	}

	now := time.Now().Unix()
	ttl := ac.CreatedAt + 600 // + 10 minutes

	if ttl < now {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Expired authorization grant code"
		ep.Err = oauth.ERR_INVALID_REQUEST
		sendOauthError(w, r, "", ep)
		return
	}

	if ac.CType == OAuth2 {
		if atr.GrantType != "authorization_code" {
			ep := &oauth.ErrorResp{}
			ep.Desc = "Unsupported grant type"
			ep.Err = oauth.ERR_INVALID_REQUEST
			sendOauthError(w, r, "", ep)
			return
		}
	}

	prv := sp.dcPrvMap[ac.DomainCode]
	if prv == nil || (pr.Name != prv.Name) {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid code"
		ep.Err = oauth.ERR_INVALID_REQUEST
		sendOauthError(w, r, "", ep)
		return
	}

	// section 4.1.2 - if the grant code is reused should revoke all the older tokens issued using this grant code
	if pr.HasGrantCodeId(ac.CreatedAt, ac.IvAsId) {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid code, this was already used once"
		ep.Err = oauth.ERR_INVALID_REQUEST
		sendOauthError(w, r, "", ep)
		// TODO revoke all tokens issued against this grant code
		return
	}

	go pr.StoreGrantCodeId(ac.CreatedAt, ac.IvAsId)

	session, err := prv.GenSessionForUserId(ac.UserId)
	if err != nil {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Failed to generate token - " + err.Error()
		ep.Err = oauth.ERR_SERVER_ERROR
		sendOauthError(w, r, "", ep)
		return
	}

	prv.StoreOauthSession(session)

	tresp := &oauth.AccessTokenResp{}
	tresp.AcToken = session.Jti
	//tresp.ExpiresIn = session.Exp // will be same as the Exp value present in token
	tresp.TokenType = "Bearer"

	if ac.CType == OIDC {
		idt := createIdToken(sp, session, cl, pr)
		strIdt := oauth.ToJwt(idt, sp.srvConf.PrivKey)
		tresp.IdToken = strIdt
	}

	headers := w.Header()
	headers.Add("Cache-Control", "no-store")
	headers.Add("Pragma", "no-cache")
	headers.Add("Content-Type", JSON_TYPE)
	w.Write(tresp.Serialize())
}

func sendOauthCode(sp *Sparrow, w http.ResponseWriter, r *http.Request, af *authFlow, areq *oauth.AuthorizationReq, cl *oauth.Client) {
	tmpUri := cl.Oauth.RedUri
	// send code to the redirect URI
	if cl.Oauth.HasQueryInUri {
		tmpUri += "&code="
	} else {
		tmpUri += "?code="
	}

	cType := OAuth2
	if _, ok := areq.Scopes["openid"]; ok {
		cType = OIDC
	}

	ttl := time.Now()
	code := newOauthCode(cl, ttl, af.UserId, af.DomainCode, cType)
	tmpUri += url.QueryEscape(code)

	state := r.Form.Get("state")

	if len(state) > 0 {
		tmpUri += "&state=" + state
	}

	// delete the authflow cookie
	setAuthFlow(sp, nil, w)
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

func getAuthFlow(r *http.Request, sp *Sparrow) *authFlow {
	ck, err := r.Cookie(AUTHFLOW_COOKIE)
	if err != nil {
		return nil
	}

	data, err := sp.ckc.Decrypt(ck.Value)
	if err != nil {
		// todo audit
		log.Debugf("failed to decrypt authflow cookie [%s]", err.Error())
		return nil
	}

	dec := gob.NewDecoder(bytes.NewBuffer(data))

	var af authFlow
	err = dec.Decode(&af)
	if err != nil {
		log.Debugf("unable to decode the authflow cookie %s", err)
		return nil
	}

	return &af
}

func redirect(path string, w http.ResponseWriter, r *http.Request, paramMap map[string]string) {
	var buf bytes.Buffer
	for k, v := range paramMap {
		if buf.Len() > 0 {
			buf.WriteByte('&')
		}

		buf.WriteString(url.QueryEscape(k) + "=")
		buf.WriteString(url.QueryEscape(v))
	}

	http.Redirect(w, r, path+"?"+buf.String(), http.StatusFound)
}

// copies the Form values into a Map
// the request must have been parsed using r.ParseForm()
// before calling this method
func copyParams(r *http.Request) map[string]string {
	paramMap := make(map[string]string)

	for k, v := range r.Form {
		paramMap[k] = v[0]
	}

	return paramMap
}

func setAuthFlow(sp *Sparrow, af *authFlow, w http.ResponseWriter) {
	ck := &http.Cookie{}
	ck.HttpOnly = true
	ck.Name = AUTHFLOW_COOKIE
	ck.SameSite = http.SameSiteStrictMode
	ck.Path = "/"
	ck.Value = ""

	if af != nil {
		var buf bytes.Buffer

		enc := gob.NewEncoder(&buf)
		enc.Encode(af)

		data := sp.ckc.Encrypt(buf.Bytes())
		sessionToken := utils.B64Encode(data)

		ck.Value = sessionToken
		ck.Expires = time.Now().Add(5 * time.Minute)
	} else {
		ck.MaxAge = -1
	}

	http.SetCookie(w, ck)
}

func sendOauthError(w http.ResponseWriter, r *http.Request, redUri string, err error) {
	ep, ok := err.(*oauth.ErrorResp)
	if ok {
		if len(redUri) == 0 {
			http.Error(w, ep.Desc+" "+ep.Err, http.StatusBadRequest)
		} else {
			w.Header().Add("Content-Type", FORM_URL_ENCODED_TYPE)
			http.Redirect(w, r, ep.BuildErrorUri(redUri), http.StatusBadRequest)
		}
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

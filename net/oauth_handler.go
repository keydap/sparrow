package net

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sparrow/base"
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

type authFlow struct {
	PsVerified   bool
	TfaVerified  bool
	TfaRequired  bool
	FromOauth    bool
	GrantedAuthz bool
	UserId       string
	DomainCode   uint32
}

func registerClient(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		writeError(w, base.NewBadRequestError(err.Error()))
		return
	}

	desc := strings.TrimSpace(r.Form.Get("desc"))
	redUri := strings.TrimSpace(r.Form.Get("uri"))
	if len(redUri) == 0 {
		writeError(w, base.NewBadRequestError("Missing redirect URI"))
		return
	}

	redUrl, err := url.Parse(strings.ToLower(redUri))

	if err != nil {
		msg := fmt.Sprintf("Invalid redirect URI %s", redUri)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	if redUrl.Scheme != "http" && redUrl.Scheme != "https" {
		msg := fmt.Sprintf("Unknown protocol in the redirect URI %s", redUri)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	cl := oauth.NewClient()
	cl.Desc = desc
	cl.RedUri = redUri
	if len(redUrl.RawQuery) != 0 {
		cl.HasQueryInUri = true
	}

	osl.AddClient(cl)

	w.WriteHeader(http.StatusCreated)
	enc := json.NewEncoder(w)
	err = enc.Encode(cl)
	if err != nil {
		log.Warningf("Failed to write serialized oauth client data to user %s", err)
	} else {
		log.Debugf("Successfully created oauth client %s", cl.Id)
	}
}

// Handles the OAuth2 authorization request
func authorize(w http.ResponseWriter, r *http.Request) {
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

func verifyConsent(w http.ResponseWriter, r *http.Request) {
	af := getAuthFlow(r)

	if af != nil {
		if af.PsVerified {
			r.ParseForm()
			consent := r.Form.Get("consent")
			if consent == "authorize" {
				sendOauthCode(w, r, af)
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

func sendToken(w http.ResponseWriter, r *http.Request) {
	atr, err := oauth.ParseAccessTokenReq(r)
	if err != nil {
		log.Debugf("Sending error to the oauth client %s", atr.ClientId)
		sendOauthError(w, r, "", err)
		return
	}

	if atr.GrantType != "authorization_code" {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Unsupported grant type"
		ep.Err = oauth.ERR_INVALID_REQUEST
		sendOauthError(w, r, "", ep)
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

		idSecretPair := string(utils.B64Decode(authzHeader[len(BASIC_AUTHZ_PREFIX):]))
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

	cl := osl.GetClient(atr.ClientId)
	if cl == nil {
		sendOauthError(w, r, "", invalidCreds)
		return
	}

	if atr.Secret != cl.Secret {
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

	prv := dcPrvMap[ac.DomainCode]
	if prv == nil {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid code"
		ep.Err = oauth.ERR_INVALID_REQUEST
		sendOauthError(w, r, "", ep)
		return
	}

	token, err := prv.GetToken(ac.UserId)
	if err != nil {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Failed to generate token - " + err.Error()
		ep.Err = oauth.ERR_SERVER_ERROR
		sendOauthError(w, r, "", ep)
		return
	}

	tresp := &oauth.AccessTokenResp{}
	tresp.AcToken = token
	//tresp.ExpiresIn = // will be same as the Exp value present in token
	tresp.TokenType = "bearer"

	w.Header().Add("Content-Type", JSON_TYPE)
	w.Write(tresp.Serialize())
}

func sendOauthCode(w http.ResponseWriter, r *http.Request, af *authFlow) {
	areq, err := oauth.ParseAuthzReq(r)

	if err != nil {
		log.Debugf("Sending error to the oauth client %s", areq.ClientId)
		sendOauthError(w, r, areq.RedUri, err)
		return
	}

	cl := osl.GetClient(areq.ClientId)
	if cl == nil {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid client ID " + areq.ClientId
		ep.Err = oauth.ERR_INVALID_REQUEST
		ep.State = areq.State
		sendOauthError(w, r, areq.RedUri, ep)
		return
	}

	tmpUri := cl.RedUri
	// send code to the redirect URI
	if cl.HasQueryInUri {
		tmpUri += "&code="
	} else {
		tmpUri += "?code="
	}

	ttl := time.Now()
	code := newOauthCode(cl, ttl, af.UserId, af.DomainCode)
	tmpUri += url.QueryEscape(code)

	state := r.Form.Get("state")

	if len(state) > 0 {
		tmpUri += "&state=" + state
	}

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

func getAuthFlow(r *http.Request) *authFlow {
	ck, err := r.Cookie(AUTHFLOW_COOKIE)
	if err != nil {
		return nil
	}

	data := utils.B64Decode(ck.Value)
	if data == nil {
		return nil
	}

	dec := gob.NewDecoder(bytes.NewBuffer(data))

	var af authFlow
	err = dec.Decode(&af)
	if err != nil {
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

func showLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	paramMap := copyParams(r)

	ologin := templates["login.html"]
	ologin.Execute(w, paramMap)
}

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

func setAuthFlow(af *authFlow, w http.ResponseWriter) {
	ck := &http.Cookie{}
	ck.HttpOnly = true
	ck.Name = AUTHFLOW_COOKIE
	ck.Path = "/"
	ck.Value = ""

	if af != nil {
		var buf bytes.Buffer

		enc := gob.NewEncoder(&buf)
		enc.Encode(af)

		sessionToken := utils.B64Encode(buf.Bytes())

		ck.Value = sessionToken
		ck.Expires = time.Now().Add(2 * time.Minute)
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

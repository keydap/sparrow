package http

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

const COOKIE_SUM string = "ps"
const BASIC_AUTHZ_PREFIX string = "Basic "

type authFlow struct {
	PsVerified  bool
	TfaVerified bool
	TfaRequired bool
	Hash        []byte
}

func newOauthCode(key []byte, ttl time.Time) string {
	ttlBytes := utils.Itob(ttl.Unix())
	ttlBytesLen := len(ttlBytes)

	block, _ := aes.NewCipher(key)
	randBytes := utils.RandBytes() // contains 32 bytes
	iv := randBytes[:aes.BlockSize]
	cbc := cipher.NewCBCEncrypter(block, iv)
	dst := make([]byte, aes.BlockSize+ttlBytesLen+8)
	copy(dst, iv)
	copy(dst[aes.BlockSize:], ttlBytes)
	copy(dst[aes.BlockSize+ttlBytesLen:], randBytes[24:])

	cbc.CryptBlocks(dst[aes.BlockSize:], dst[aes.BlockSize:])

	return utils.B64Encode(dst)
}

func decryptOauthCode(code string, key []byte) *time.Time {
	data := utils.B64Decode(code)
	if data == nil {
		return nil
	}

	if len(data) != 32 { // 16 bytes of IV, 8 bytes of time and 8 random bytes
		log.Debugf("Invalid authorization code received, insufficent bytes")
		return nil
	}

	block, _ := aes.NewCipher(key)
	cbc := cipher.NewCBCDecrypter(block, data[:aes.BlockSize])
	dst := make([]byte, len(data)-aes.BlockSize)

	cbc.CryptBlocks(dst, data[aes.BlockSize:])

	unixTime := utils.Btoi(dst[:8])
	t := time.Unix(unixTime, 0)

	return &t
}

func createClient(w http.ResponseWriter, r *http.Request) {
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

	if redUrl.Scheme != "http" || redUrl.Scheme != "https" {
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

	af := decodeAfCookie(r)

	if af != nil {
		if af.PsVerified {
			sendOauthCode(w, r)
			return
		}
	}

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

func sendToken(w http.ResponseWriter, r *http.Request) {
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
			sendOauthError(w, r, "", err)
			return
		}

		idSecretPair := string(utils.B64Decode(authzHeader[len(BASIC_AUTHZ_PREFIX):]))
		tokens := strings.Split(idSecretPair, ":")
		if len(tokens) != 2 {
			ep := &oauth.ErrorResp{}
			ep.Desc = "Invalid authorization header"
			ep.Err = oauth.ERR_INVALID_REQUEST
			sendOauthError(w, r, "", err)
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

	ttl := decryptOauthCode(atr.Code, cl.ServerSecret)
	if ttl == nil {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid code"
		ep.Err = oauth.ERR_INVALID_REQUEST
		sendOauthError(w, r, "", err)
		return
	}

	ttl.Add(10 * time.Minute)
	if ttl.After(time.Now()) {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Expired authorization grant code"
		ep.Err = oauth.ERR_INVALID_REQUEST
		sendOauthError(w, r, "", err)
		return
	}

	// TODO send the code
}

func sendOauthCode(w http.ResponseWriter, r *http.Request) {
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
	code := newOauthCode(cl.ServerSecret, ttl)
	tmpUri += url.QueryEscape(code)

	state := r.Form.Get("state")

	if len(state) > 0 {
		tmpUri += "&state=" + state
	}

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

func decodeAfCookie(r *http.Request) *authFlow {
	ck, err := r.Cookie(COOKIE_SUM)
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
	prv, _ := getPrFromParam(r)
	ar := &base.AuthRequest{}
	ar.Username = r.Form.Get("username")
	ar.Password = r.Form.Get("password")
	ar.Domain = prv.Name

	token, err := prv.Authenticate(ar)
	if err != nil {
		login := templates["login.html"]
		paramMap := copyParams(r)
		delete(paramMap, "username")
		delete(paramMap, "password")
		login.Execute(w, paramMap)
		return
	}

	af := &authFlow{}
	af.PsVerified = true
	// TODO enable it when the account has TFA capability
	af.TfaRequired = false

	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)
	enc.Encode(af)

	sessionToken := utils.B64Encode(buf.Bytes())

	ck := &http.Cookie{}
	ck.Expires = time.Now().Add(1 * time.Minute)
	ck.HttpOnly = true
	ck.Name = COOKIE_SUM
	ck.Path = "/"
	ck.Value = sessionToken

	r.AddCookie(ck)

	w.Write([]byte(token))
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

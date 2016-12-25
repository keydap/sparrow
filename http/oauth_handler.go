package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sparrow/base"
	"sparrow/oauth"
	"strings"
)

func createClient(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		writeError(w, base.NewBadRequestError(err.Error()))
		return
	}

	desc := strings.TrimSpace(r.Form.Get("desc"))
	reduri := strings.TrimSpace(r.Form.Get("uri"))
	if len(reduri) == 0 {
		writeError(w, base.NewBadRequestError("Missing redirect URI"))
		return
	}

	tmpUri := strings.ToLower(reduri)
	if !strings.HasPrefix(tmpUri, "http://") && !strings.HasPrefix(tmpUri, "https://") {
		msg := fmt.Sprintf("Unknown protocol in the redirect URI %s", reduri)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	cl := oauth.NewClient()
	cl.Desc = desc
	cl.RedUri = reduri

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
	areq, err := oauth.ParseAuthzReq(r)

	if err != nil {
		log.Debugf("Sending error to the oauth client %s", areq.ClientId)
		sendOauthError(w, r, areq, err)
		return
	}

	cl := osl.GetClient(areq.ClientId)
	if cl == nil {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Invalid client ID " + areq.ClientId
		ep.Err = oauth.ERR_INVALID_REQUEST
		ep.State = areq.State
		sendOauthError(w, r, areq, ep)
		return
	}

	if cl.RedUri != areq.RedUri {
		ep := &oauth.ErrorResp{}
		ep.Desc = "Mismatching redirect URI " + areq.RedUri
		ep.Err = oauth.ERR_INVALID_REQUEST
		ep.State = areq.State
		sendOauthError(w, r, areq, ep)
		return
	}

	oAuthLogin(w, r, areq)
	//cs.New(r, "")
}

func oAuthLogin(w http.ResponseWriter, r *http.Request, areq *oauth.AuthorizationReq) {
	//http.Redirect(w, r, "oauth-login", http.StatusTemporaryRedirect)
	ologin := templates["ologin.html"]
	ologin.Execute(w, nil)
}

func sendOauthError(w http.ResponseWriter, r *http.Request, areq *oauth.AuthorizationReq, err error) {
	ep, ok := err.(*oauth.ErrorResp)
	if ok {
		if len(areq.RedUri) == 0 {
			http.Error(w, ep.Desc+" "+ep.Err, http.StatusBadRequest)
		} else {
			w.Header().Add("Content-Type", FORM_URL_ENCODED_TYPE)
			http.Redirect(w, r, ep.BuildErrorUri(areq.RedUri), http.StatusBadRequest)
		}
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

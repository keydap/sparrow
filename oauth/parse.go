package oauth

import (
	"net/http"
	"strings"
)

func ParseAuthzReq(r *http.Request) (areq *AuthorizationReq) {
	areq = &AuthorizationReq{}
	areq.RespType = strings.TrimSpace(r.Form.Get("response_type"))

	areq.ClientId = strings.TrimSpace(r.Form.Get("client_id"))

	areq.RedUri = strings.TrimSpace(r.Form.Get("redirect_uri"))

	areq.Scopes = make(map[string]int)
	scopes := strings.Split(r.Form.Get("scope"), " ")
	for _, v := range scopes {
		areq.Scopes[v] = 1
	}

	areq.State = r.Form.Get("state")

	areq.Display = strings.TrimSpace(r.Form.Get("display"))
	areq.Nonce = strings.TrimSpace(r.Form.Get("nonce"))
	areq.Prompt = strings.TrimSpace(r.Form.Get("prompt"))
	areq.ResponseMode = strings.TrimSpace(r.Form.Get("response_mode"))

	return areq
}

func ParseAccessTokenReq(r *http.Request) (atr *AccessTokenReq, err error) {
	err = r.ParseForm()
	if err != nil {
		return nil, err
	}

	atr = &AccessTokenReq{}
	atr.ClientId = r.Form.Get("client_id")
	atr.RedUri = r.Form.Get("redirect_uri")
	atr.Code = r.Form.Get("code")
	atr.GrantType = r.Form.Get("grant_type")

	return atr, nil
}

func ValidateAuthReq(areq *AuthorizationReq) *ErrorResp {
	e := &ErrorResp{}
	e.State = areq.State

	if areq.RespType != "code" {
		e.Err = ERR_UNSUPPORTED_RESPONSE_TYPE
		e.Desc = "Unsupported response_type " + areq.RespType
		return e
	}

	if len(areq.ClientId) == 0 {
		e.Err = ERR_INVALID_REQUEST
		e.Desc = "Missing client_id"
		return e
	}

	return nil
}

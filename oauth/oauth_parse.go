package oauth

import (
	"net/http"
)

func ParseAuthzReq(r *http.Request) (areq *AuthorizationReq, err error) {
	err = r.ParseForm()
	if err != nil {
		return nil, err
	}

	areq = &AuthorizationReq{}
	areq.RespType = r.Form.Get("response_type")
	areq.ClientId = r.Form.Get("client_id")
	areq.RedUri = r.Form.Get("redirect_uri")
	areq.Scope = r.Form.Get("scope")
	areq.State = r.Form.Get("state")

	return areq, nil
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

// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package oauth

import (
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	samlTypes "github.com/russellhaering/gosaml2/types"
	"sparrow/base"
	"strings"
)

const (
	AUTHORIZATION_CODE = "authorization_code"
	IMPLICIT           = "implicit"
	RES_OWN_PASS_CRED  = "resource_owner_password_credentials"
	CLIENT_CRED        = "client_credentials"
)

const (
	ERR_INVALID_REQUEST           = "invalid_request"
	ERR_UNAUTHORIZED_CLIENT       = "unauthorized_client"
	ERR_ACCESS_DENIED             = "access_denied"
	ERR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
	ERR_INVALID_SCOPE             = "invalid_scope"
	ERR_SERVER_ERROR              = "server_error"
	ERR_TEMPORARILY_UNAVAILABLE   = "temporarily_unavailable"
)

type Client struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Time     int64  `json:"time"`
	Desc     string `json:"desc"`
	HomeUrl  string `json:"homeurl"`
	GroupIds map[string]int
	Oauth    *ClientOauthConf
	Saml     *ClientSamlConf
}

type ClientSamlConf struct {
	SLOUrl            string // Single LOgout URL
	MetaUrl           string // URL serving SP's metadata
	HomeUrl           string // URL of the home page
	MetaData          samlTypes.SPSSODescriptor
	Attributes        map[string]*base.SsoAttr `json:"attrs"`
	AssertionValidity int
	IdpIssuer         string
	SpIssuer          string
}

type ClientOauthConf struct {
	Secret          string                   `json:"secret"`
	RedUri          string                   `json:"redUri"`
	ServerSecret    []byte                   `json:"-"` // this secret is used as a key
	HasQueryInUri   bool                     `json:"-"` // flag to indicate if there is query part in the path
	ConsentRequired bool                     `json:"consentRequired"`
	Attributes      map[string]*base.SsoAttr `json:"attrs"`
}

type AuthorizationReq struct {
	RespType string         `json:"response_type"`
	ClientId string         `json:"client_id"`
	RedUri   string         `json:"redirect_uri"`
	Scopes   map[string]int `json:"scope"`
	State    string         `json:"state"`

	// OIDC specific parameters
	Nonce        string
	Display      string
	Prompt       string
	ResponseMode string `json:"response_mode"`
}

type AuthorizationResp struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type ErrorResp struct {
	Err   string `json:"error"`
	Desc  string `json:"error_description"`
	Uri   string `json:"error_uri"`
	State string `json:"state"`
}

type AccessTokenReq struct {
	GrantType string `json:"grant_type"`
	Code      string `json:"code"`
	RedUri    string `json:"redirect_uri"`
	ClientId  string `json:"client_id"`
	Secret    string `json:"client_secret"`
}

type AccessTokenResp struct {
	AcToken   string `json:"access_token"`
	IdToken   string `json:"id_token,omitempty"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in,omitempty"`
}

type AttrProfile struct {
	Id         string
	Name       string
	Attributes []*base.SsoAttr
}

type OauthScope struct {
	Name       string
	UserGroups []string
}

func (atr *AccessTokenResp) Serialize() []byte {
	data, err := json.Marshal(atr)
	if err != nil {
		return []byte(err.Error())
	}

	return data
}

func (ep *ErrorResp) Serialize() []byte {
	data, err := json.Marshal(ep)
	if err != nil {
		return []byte(err.Error())
	}

	return data
}

func (ep *ErrorResp) Error() string {
	return string(ep.Serialize())
}

func (ep *ErrorResp) BuildErrorUri(redUri string) string {
	if !strings.ContainsRune(redUri, '?') {
		redUri += "?"
	} else {
		redUri += "&"
	}

	redUri += "error=" + ep.Err

	if len(ep.State) != 0 {
		redUri += "state=" + ep.State
	}

	return redUri
}

func ToJwt(claims jwt.MapClaims, key crypto.PrivateKey) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	str, err := token.SignedString(key)
	if err != nil {
		panic(fmt.Errorf("could not create the JWT from IdToken %#v", err))
	}

	return str
}

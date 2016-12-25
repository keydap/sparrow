package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sparrow/utils"
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

var urlEncoder = base64.URLEncoding.WithPadding(base64.NoPadding)

type Client struct {
	Id     string `json:"id"`
	Secret string `json:"secret"`
	Time   int64  `json:"time"`
	Desc   string `json:"desc"`
	RedUri string `json:"redUri"`
}

type AuthorizationReq struct {
	RespType string `json:"response_type"`
	ClientId string `json:"client_id"`
	RedUri   string `json:"redirect_uri"`
	Scope    string `json:"scope"`
	State    string `json:"state"`
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
}

type AccessTokenResp struct {
	AcToken   string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

func NewClient() *Client {
	cl := &Client{}
	cl.Id = newRandStr()
	cl.Secret = newRandStr()
	cl.Time = utils.DateTimeMillis()

	return cl
}

func newRandStr() string {
	b := make([]byte, 32)
	rand.Read(b)
	return urlEncoder.EncodeToString(b)
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

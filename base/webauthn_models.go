package base

type PublicKeyCredentialCreationOptions struct {
	Attestation        string                          `json:"attestation"`
	Challenge          string                          `json:"challenge"`
	RpId               string                          `json:"rpId"`
	RpName             string                          `json:"rpName"`
	UserId             string                          `json:"userId"`
	UserName           string                          `json:"userName"`
	UserDisplayName    string                          `json:"userDisplayName"`
	Timeout            uint64                          `json:"timeout"`
	ExcludeCredentials []PublicKeyCredentialDescriptor `json:"excludeCredentials"`
	PubKeyCredParams   []PubKeyCredParam               `json:"pubKeyCredParams"`
}

type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type PublicKeyCredentialRequestOptions struct {
	Challenge        string   `json:"challenge"`
	RpId             string   `json:"rpId"`
	Timeout          uint64   `json:"timeout"`
	CredIds          []string `json:"credIds"`
	UserVerification string   `json:"userVerification"`
}

type CollectedClientData struct {
	Type             string                 `json:"type"`
	Challenge        string                 `json:"challenge"`
	Origin           string                 `json:"origin"`
	HashAlgorithm    string                 `json:"hashAlgorithm"`
	TokenBinding     TokenBinding           `json:"tokenBinding"`
	ClientExtensions map[string]interface{} `codec:"clientExtensions"`
	RawBytes         []byte
}

type TokenBinding struct {
	Status string `json:"status"`
	Id     string `json:"id"`
}

type PublicKeyCredentialDescriptor struct {
	Type       string `json:"type,omitempty"`
	Id         string `json:"id,omitempty"`
	Transports string `json:"transports,omitempty"`
}

type AuthenticatorData struct {
	RpIdHash     []byte
	Flags        byte
	SignCount    uint32
	AAGUID       string
	CredentialId string
	PubKeyCOSE   map[int]interface{}
	Extensions   map[int]interface{}
	RawData      []byte
}

type WebauthnResponse struct {
	ClientData CollectedClientData
	AuthData   AuthenticatorData
	AttStmt    map[string]interface{}
	Fmt        string
	Signature  []byte
	UserHandle string // the handle that authenticator returns, can be null. This field is unused at the moment

	// sparrow specific internal fields
	ResId string // user resource's ID
	PrId  string // domaincode of provider
	CTime int64  // the time at which challenge was created
}

var DEFAULT_PUB_KEY_CRED_PARAMS = []PubKeyCredParam{
	PubKeyCredParam{Type: "public-key", Alg: -7},  // "ES256"
	PubKeyCredParam{Type: "public-key", Alg: -35}, // "ES384"
	PubKeyCredParam{Type: "public-key", Alg: -36}, // "ES512"
	PubKeyCredParam{Type: "public-key", Alg: -37}, // "PS256"
}

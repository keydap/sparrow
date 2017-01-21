package conf

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"sparrow/utils"
)

type ServerConf struct {
	Https              bool   `json:"enable-https"`
	HttpPort           int    `json:"http-port"`
	LdapPort           int    `json:"ldap-port"`
	LdapOverTlsOnly    bool   `json:"ldap-over-tls-only"`
	Ipaddress          string `json:"ipaddress"`
	CertFile           string `json:"certificate"`
	PrivKeyFile        string `json:"privatekey"`
	TmplDir            string // template directory
	OauthDir           string // template directory
	CertChain          []*x509.Certificate
	PrivKey            crypto.PrivateKey
	PubKey             crypto.PublicKey
	TokenPurgeInterval int `json:"token-purge-interval"` // the number of seconds to wait between successive purges of expired tokens
}

type AuthenticationScheme struct {
	Description      string
	DocumentationURI string
	Name             string
	Primary          bool
	SpecURI          string
	Type             string
	Notes            string
}

type Bulk struct {
	MaxOperations  int
	MaxPayloadSize int
	Supported      bool
	Notes          string
}
type ChangePassword struct {
	Supported bool
	Notes     string
}

type Etag struct {
	Supported bool
	Notes     string
}
type Filter struct {
	MaxResults int
	Supported  bool
	Notes      string
}
type Patch struct {
	Supported bool
	Notes     string
}
type Sort struct {
	Supported bool
	Notes     string
}

type ResourceConf struct {
	Name        string
	IndexFields []string
	Notes       string
}

type Config struct {
	Scim           *ScimConfig
	Oauth          *OauthConfig
	Ppolicy        *Ppolicy
	PasswdHashAlgo string `json:"password-hash-algo"`
	PasswdHashType utils.HashType
}

type Ppolicy struct {
}

type OauthConfig struct {
}

type ScimConfig struct {
	DocumentationURI      string
	AuthenticationSchemes []AuthenticationScheme
	Bulk                  Bulk
	ChangePassword        ChangePassword
	Etag                  Etag
	Filter                Filter
	Patch                 Patch
	Sort                  Sort
	Resources             []ResourceConf
	Notes                 string
}

func DefaultConfig() *Config {
	scim := &ScimConfig{DocumentationURI: "http://keydap.com/sparrow/scim"}
	oauth := AuthenticationScheme{Type: "oauthbearertoken", Primary: true, Name: "OAuth Bearer Token", Description: "Authentication scheme using the OAuth Bearer Token Standard", SpecURI: "http://www.rfc-editor.org/info/rfc6750", DocumentationURI: "http://keydap.com/sparrow/scim"}
	basic := AuthenticationScheme{Type: "httpbasic", Name: "HTTP Basic", Description: "Authentication scheme using the HTTP Basic Standard", SpecURI: "http://www.rfc-editor.org/info/rfc2617", DocumentationURI: "http://keydap.com/sparrow/scim"}
	scim.AuthenticationSchemes = []AuthenticationScheme{oauth, basic}

	bulk := Bulk{Supported: true, MaxOperations: 1000, MaxPayloadSize: 1048576}
	scim.Bulk = bulk

	chpw := ChangePassword{Supported: true}
	scim.ChangePassword = chpw

	etag := Etag{Supported: true}
	scim.Etag = etag

	filter := Filter{Supported: true, MaxResults: 200}
	scim.Filter = filter

	patch := Patch{Supported: true}
	scim.Patch = patch

	sort := Sort{Supported: true}
	scim.Sort = sort

	userRc := ResourceConf{Name: "User", IndexFields: []string{"userName", "name.givenName", "employeeNumber", "organization", "emails.value", "groups.value"}}
	deviceRc := ResourceConf{Name: "Device", IndexFields: []string{"manufacturer", "serialNumber", "rating", "price", "location.latitude", "installedDate", "repairDates", "photos.value"}}
	groupRc := ResourceConf{Name: "Group", IndexFields: []string{"members.value"}}

	scim.Resources = []ResourceConf{userRc, deviceRc, groupRc}

	oauthCf := &OauthConfig{}

	ppolicy := &Ppolicy{}

	cf := &Config{}
	cf.Scim = scim
	cf.Oauth = oauthCf
	cf.Ppolicy = ppolicy
	cf.PasswdHashAlgo = "sha256"
	cf.PasswdHashType = utils.SHA256

	return cf
}

func ParseConfig(file string) (*Config, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	cf := &Config{}

	err = json.Unmarshal(data, cf)
	if err != nil {
		return nil, err
	}

	return cf, nil
}

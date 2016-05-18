package conf

import (
	"encoding/json"
	"io/ioutil"
)

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
	cf := &Config{DocumentationURI: "http://keydap.com/sparrow/scim"}

	oauth := AuthenticationScheme{Type: "oauthbearertoken", Primary: true, Name: "OAuth Bearer Token", Description: "Authentication scheme using the OAuth Bearer Token Standard", SpecURI: "http://www.rfc-editor.org/info/rfc6750", DocumentationURI: "http://keydap.com/sparrow/scim"}
	basic := AuthenticationScheme{Type: "httpbasic", Name: "HTTP Basic", Description: "Authentication scheme using the HTTP Basic Standard", SpecURI: "http://www.rfc-editor.org/info/rfc2617", DocumentationURI: "http://keydap.com/sparrow/scim"}
	cf.AuthenticationSchemes = []AuthenticationScheme{oauth, basic}

	bulk := Bulk{Supported: true, MaxOperations: 1000, MaxPayloadSize: 1048576}
	cf.Bulk = bulk

	chpw := ChangePassword{Supported: true}
	cf.ChangePassword = chpw

	etag := Etag{Supported: true}
	cf.Etag = etag

	filter := Filter{Supported: true, MaxResults: 200}
	cf.Filter = filter

	patch := Patch{Supported: true}
	cf.Patch = patch

	sort := Sort{Supported: true}
	cf.Sort = sort

	userRc := ResourceConf{Name: "User", IndexFields: []string{"userName", "name.givenName", "employeeNumber", "organization", "emails.value"}}
	deviceRc := ResourceConf{Name: "Device", IndexFields: []string{"manufacturer", "serialNumber", "rating", "price", "location.lat", "installedDate", "repairDates", "photos.value"}}
	cf.Resources = []ResourceConf{userRc, deviceRc}

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

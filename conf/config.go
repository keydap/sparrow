// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package conf

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sparrow/utils"
	"time"
)

type ServerConf struct {
	ServerId        uint16              `json:"serverId"` // used while generating CSNs
	Https           bool                `json:"enableHttps"`
	HttpPort        int                 `json:"httpPort"`
	LdapPort        int                 `json:"ldapPort"`
	LdapOverTlsOnly bool                `json:"ldapOverTlsOnly"`
	IpAddress       string              `json:"ipAddress"`
	CertFile        string              `json:"certificateFile"`
	PrivKeyFile     string              `json:"privatekeyFile"`
	TmplDir         string              `json:"-"` // template directory
	CertChain       []*x509.Certificate `json:"-"`
	PrivKey         crypto.PrivateKey   `json:"-"`
	PubKey          crypto.PublicKey    `json:"-"`
}

type AuthenticationScheme struct {
	Description      string `json:"description"`
	DocumentationURI string `json:"documentationUri"`
	Name             string `json:"name"`
	Primary          bool   `json:"primary"`
	SpecURI          string `json:"specUri"`
	Type             string `json:"type"`
	Notes            string `json:"notes"`
}

type Bulk struct {
	MaxOperations  int    `json:"maxOperations"`
	MaxPayloadSize int    `json:"maxPayloadSize"`
	Supported      bool   `json:"supported"`
	Notes          string `json:"notes"`
}
type ChangePassword struct {
	Supported bool   `json:"supported"`
	Notes     string `json:"notes"`
}

type Etag struct {
	Supported bool   `json:"supported"`
	Notes     string `json:"notes"`
}
type Filter struct {
	MaxResults int    `json:"maxResults"`
	Supported  bool   `json:"supported"`
	Notes      string `json:"notes"`
}
type Patch struct {
	Supported bool   `json:"supported"`
	Notes     string `json:"notes"`
}
type Sort struct {
	Supported bool   `json:"supported"`
	Notes     string `json:"notes"`
}

type ResourceConf struct {
	Name        string   `json:"name"`
	IndexFields []string `json:"indexFields"`
	Notes       string   `json:"notes"`
}

type DomainConfig struct {
	Scim    *ScimConfig  `json:"scim"`
	Oauth   *OauthConfig `json:"oauth"`
	Ppolicy *Ppolicy     `json:"ppolicy"`
}

type Ppolicy struct {
	PasswdHashAlgo string `json:"passwordHashAlgo"`
}

type OauthConfig struct {
	TokenTTL           int    `json:"tokenTtl"`           // the life time of an OAuth token in seconds
	SsoSessionIdleTime int    `json:"ssoSessionIdleTime"` // the idle time of a SSO session in seconds
	TokenPurgeInterval int    `json:"tokenPurgeInterval"` // the number of seconds to wait between successive purges of expired tokens
	Notes              string `json:"notes"`
}

type Meta struct {
	Location     string `json:"location"`
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Version      string `json:"version"`
}

type ScimConfig struct {
	Schemas               []string               `json:"schemas"`
	DocumentationURI      string                 `json:"documentationUri"`
	AuthenticationSchemes []AuthenticationScheme `json:"authenticationSchemes"`
	Bulk                  Bulk                   `json:"bulk"`
	ChangePassword        ChangePassword         `json:"changePassword"`
	Etag                  Etag                   `json:"etag"`
	Filter                Filter                 `json:"filter"`
	Patch                 Patch                  `json:"patch"`
	Sort                  Sort                   `json:"sort"`
	Resources             []ResourceConf         `json:"resources"`
	Notes                 string                 `json:"notes"`
	Meta                  Meta                   `json:"meta"`
}

func DefaultDomainConfig() *DomainConfig {
	scim := &ScimConfig{DocumentationURI: "http://keydap.com/sparrow/scim"}

	oauth := AuthenticationScheme{Type: "oauthbearertoken", Primary: true, Name: "OAuth Bearer Token", Description: "Authentication scheme using the OAuth Bearer Token Standard", SpecURI: "http://www.rfc-editor.org/info/rfc6750", DocumentationURI: "http://keydap.com/sparrow/scim"}
	scim.AuthenticationSchemes = []AuthenticationScheme{oauth}

	bulk := Bulk{Supported: false, MaxOperations: 1000, MaxPayloadSize: 1048576}
	scim.Bulk = bulk

	chpw := ChangePassword{Supported: true}
	scim.ChangePassword = chpw

	scim.DocumentationURI = "http://keydap.com/sparrow/scim"

	etag := Etag{Supported: true}
	scim.Etag = etag

	filter := Filter{Supported: true, MaxResults: 200}
	scim.Filter = filter

	patch := Patch{Supported: true}
	scim.Patch = patch

	userRc := ResourceConf{Name: "User", IndexFields: []string{"userName", "name.givenName", "employeeNumber", "organization", "emails.value", "groups.value"}}
	deviceRc := ResourceConf{Name: "Device", IndexFields: []string{"manufacturer", "serialNumber", "rating", "price", "location.latitude", "installedDate", "repairDates", "photos.value"}}
	groupRc := ResourceConf{Name: "Group", IndexFields: []string{"members.value"}}
	scim.Resources = []ResourceConf{userRc, deviceRc, groupRc}

	sort := Sort{Supported: false}
	scim.Sort = sort

	scim.Schemas = []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}

	meta := Meta{}
	now := time.Now()
	meta.Created = now.Format(time.RFC3339)
	meta.Location = "/v2/ServiceProviderConfig"
	meta.ResourceType = "ServiceProviderConfig"
	meta.Version = meta.Created
	meta.LastModified = meta.Created
	scim.Meta = meta

	oauthCf := &OauthConfig{}
	oauthCf.TokenTTL = 8 * 3600           // 8 hours
	oauthCf.SsoSessionIdleTime = 1 * 3600 // 1 hour
	oauthCf.TokenPurgeInterval = 2 * 60   // 2 minutes

	ppolicy := &Ppolicy{}
	ppolicy.PasswdHashAlgo = "sha256"

	cf := &DomainConfig{}
	cf.Scim = scim
	cf.Oauth = oauthCf
	cf.Ppolicy = ppolicy

	return cf
}

func ParseDomainConfig(file string) (*DomainConfig, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	cf := &DomainConfig{}

	err = json.Unmarshal(data, cf)
	if err != nil {
		return nil, err
	}

	if !utils.IsHashAlgoSupported(cf.Ppolicy.PasswdHashAlgo) {
		panic(fmt.Errorf("%s is not a supported hashing algorithm", cf.Ppolicy.PasswdHashAlgo))
	}

	return cf, nil
}

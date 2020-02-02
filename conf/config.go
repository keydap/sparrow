// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package conf

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/utils"
	"time"
)

type ServerConf struct {
	ServerId          uint16              `json:"serverId" valid:"required~Server ID is required"` // used while generating CSNs
	Https             bool                `json:"enableHttps" valid:"checkTLSSettings"`
	HttpPort          int                 `json:"httpPort" valid:"required"`
	LdapPort          int                 `json:"ldapPort"`
	LdapEnabled       bool                `json:"ldapEnabled"`
	LdapOverTlsOnly   bool                `json:"ldapOverTlsOnly"`
	IpAddress         string              `json:"ipAddress" valid:"ip"`
	CertFile          string              `json:"certificateFile"`
	PrivKeyFile       string              `json:"privatekeyFile"`
	ControllerDomain  string              `json:"controllerDomain"` // the domain whose admin can manage other domains
	DefaultDomain     string              `json:"defaultDomain"`    // the default domain
	SkipPeerCertCheck bool                `json:"skipPeerCertCheck"`
	TmplDir           string              `json:"-"` // template directory
	ReplDir           string              `json:"-"` // replication data directory
	DomainsDir        string              `json:"-"` // domains' data directory
	CertChain         []*x509.Certificate `json:"-"`
	PrivKey           crypto.PrivateKey   `json:"-"`
	PubKey            crypto.PublicKey    `json:"-"`
	ReplTransport     *http.Transport     `json:"-"`
	ReplWebHookToken  string              `json:"-"`
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
	CsnGen      *base.CsnGenerator `json:"-"`
	Scim        *ScimConfig        `json:"scim"`
	Oauth       *OauthConfig       `json:"oauth"`
	Ppolicy     *PpolicyConfig     `json:"ppolicy"`
	Resources   []*ResourceConf    `json:"resources"`
	Rfc2307bis  *Rfc2307bis        `json:"rfc2307bis"`
	Replication *ReplicationConfig `json:"replication"`
}

type Rfc2307bis struct {
	Enabled             bool   `json:"enabled"`
	LoginShell          string `json:"loginShell"`
	HomeDirectoryPrefix string `json:"homeDirectoryPrefix"`
	UidNumberStart      int64  `json:"uidNumberStart"`
	GidNumberStart      int64  `json:"gidNumberStart"`
}

type PpolicyConfig struct {
	PasswdHashAlgo      string `json:"passwordHashAlgo" valid:"checkHashAlgo"`
	PasswdMinLen        int    `json:"passwordMinLen"`
	LockAccAfterNumFail int    `json:"lockAccAfterNumFail"`
	UnlockAccAfterSec   int    `json:"unlockAccAfterSec"`
}

type ReplicationConfig struct {
	EventTtl      int `json:"eventTtl"`      // the life of each event in seconds
	PurgeInterval int `json:"purgeInterval"` // the interval(in seconds) at which the purging should repeat
}

type OauthConfig struct {
	SsoSessionIdleTime     int    `json:"ssoSessionIdleTime"`     // the idle time of a SSO session in seconds
	SsoSessionMaxLife      int    `json:"ssoSessionMaxLife"`      // the max life time of a SSO session in seconds
	TokenPurgeInterval     int    `json:"tokenPurgeInterval"`     // the number of seconds to wait between successive purges of expired tokens
	GrantCodePurgeInterval int    `json:"grantCodePurgeInterval"` // the number of seconds to wait before purging the OAuth grant codes
	GrantCodeMaxLife       int    `json:"grantCodeMaxLife"`       // the number of seconds an OAuth grant code is valid for
	Notes                  string `json:"notes"`
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
	Meta                  Meta                   `json:"meta"`
}

func DefaultDomainConfig() *DomainConfig {
	scim := &ScimConfig{DocumentationURI: "http://keydap.com/sparrow"}

	oauth := AuthenticationScheme{Type: "oauthbearertoken", Primary: true, Name: "OAuth Bearer Token", Description: "Authentication scheme using the OAuth Bearer Token Standard", SpecURI: "http://www.rfc-editor.org/info/rfc6750", DocumentationURI: "http://keydap.com/sparrow"}
	scim.AuthenticationSchemes = []AuthenticationScheme{oauth}

	bulk := Bulk{Supported: false, MaxOperations: 1000, MaxPayloadSize: 1048576}
	scim.Bulk = bulk

	chpw := ChangePassword{Supported: true}
	scim.ChangePassword = chpw

	scim.DocumentationURI = "http://keydap.com/sparrow"

	etag := Etag{Supported: true}
	scim.Etag = etag

	filter := Filter{Supported: true, MaxResults: 200}
	scim.Filter = filter

	patch := Patch{Supported: true}
	scim.Patch = patch

	cf := &DomainConfig{}

	userRc := &ResourceConf{Name: "User", IndexFields: []string{"userName", "emails.value", "groups.value"}}
	deviceRc := &ResourceConf{Name: "Device", IndexFields: []string{"manufacturer", "serialNumber", "rating", "price", "location.latitude", "installedDate", "repairDates", "photos.value"}}
	groupRc := &ResourceConf{Name: "Group", IndexFields: []string{"members.value"}}
	cf.Resources = []*ResourceConf{userRc, deviceRc, groupRc}

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
	oauthCf.SsoSessionIdleTime = 1 * 3600   // 1 hour
	oauthCf.SsoSessionMaxLife = 24 * 3600   // 24 hours
	oauthCf.TokenPurgeInterval = 1 * 3600   // 1 hour
	oauthCf.GrantCodePurgeInterval = 5 * 60 // 5 minutes
	oauthCf.GrantCodeMaxLife = 2 * 60       // 2 minutes

	ppolicy := &PpolicyConfig{}
	ppolicy.PasswdHashAlgo = "sha256"
	ppolicy.LockAccAfterNumFail = 10
	ppolicy.UnlockAccAfterSec = 600 // 10 minutes

	rfc2307bis := &Rfc2307bis{Enabled: false, LoginShell: "/bin/bash", HomeDirectoryPrefix: "/home/", UidNumberStart: 200, GidNumberStart: 200}

	replication := &ReplicationConfig{}
	replication.EventTtl = 60 * 60 * 24 * 2      // 2 days
	replication.PurgeInterval = 60 * 60 * 24 * 1 // 1 day

	cf.Rfc2307bis = rfc2307bis
	cf.Scim = scim
	cf.Oauth = oauthCf
	cf.Ppolicy = ppolicy
	cf.Replication = replication

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

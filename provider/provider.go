// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package provider

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	_ "github.com/dgrijalva/jwt-go"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"os"
	"path/filepath"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/oauth"
	_ "sparrow/rbac"
	"sparrow/schema"
	"sparrow/silo"
	"sparrow/utils"
	"strings"
)

type Provider struct {
	ServerId      uint16
	Schemas       map[string]*schema.Schema       // a map of Schema ID to Schema
	RsTypes       map[string]*schema.ResourceType // a map of Name to ResourceTye
	RtPathMap     map[string]*schema.ResourceType // a map of EndPoint to ResourceTye
	LdapTemplates map[string]*schema.LdapEntryTemplate
	Config        *conf.DomainConfig
	sl            *silo.Silo
	layout        *Layout
	Name          string // the domain name
	Cert          *x509.Certificate
	PrivKey       crypto.PrivateKey
	immResIds     map[string]int // map of IDs of resources that cannot be deleted
	domainCode    uint32
	osl           *oauth.OauthSilo
}

const adminGroupId = "01000000-0000-4000-4000-000000000000"
const adminUserId = "00000000-0000-4000-4000-000000000000"

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.provider")
}

func NewProvider(layout *Layout) (prv *Provider, err error) {
	schemas, err := base.LoadSchemas(layout.SchemaDir)
	if err != nil {
		return nil, err
	}

	prv = &Provider{}
	prv.Schemas = schemas

	prv.RsTypes, prv.RtPathMap, err = base.LoadResTypes(layout.ResTypesDir, prv.Schemas)
	if err != nil {
		return nil, err
	}

	dConfPath := filepath.Join(layout.ConfDir, "domain.json")
	_, err = os.Stat(dConfPath)

	// store the config if not present
	if err != nil && os.IsNotExist(err) {
		data, _ := json.MarshalIndent(conf.DefaultDomainConfig(), "", "    ")
		err = ioutil.WriteFile(dConfPath, data, utils.FILE_PERM)
		if err != nil {
			panic(err)
		}
	}

	// parse again, just to be sure that the DefaultDomainConfig() produced correct config
	prv.Config, err = conf.ParseDomainConfig(dConfPath)
	if err != nil {
		return nil, err
	}

	cf := prv.Config
	cf.Ppolicy.PasswdHashAlgo = strings.ToLower(cf.Ppolicy.PasswdHashAlgo)
	cf.Ppolicy.PasswdHashType = utils.FindHashType(cf.Ppolicy.PasswdHashAlgo)

	prv.LdapTemplates = base.LoadLdapTemplates(layout.LdapTmplDir, prv.RsTypes)

	dataFilePath := filepath.Join(layout.DataDir, layout.name)

	prv.sl, err = silo.Open(dataFilePath, prv.ServerId, prv.Config, prv.RsTypes, prv.Schemas)

	if err != nil {
		return nil, err
	}

	prv.layout = layout
	prv.Name = layout.name
	prv.sl.Engine.Domain = layout.name
	prv.immResIds = make(map[string]int)
	prv.immResIds[adminGroupId] = 1
	prv.immResIds[adminUserId] = 1

	odbFilePath := filepath.Join(layout.DataDir, layout.name+"-tokens.db")
	prv.osl, err = oauth.Open(odbFilePath, prv.Config.Oauth.TokenPurgeInterval)

	if err != nil {
		return nil, err
	}

	err = prv.createDefaultResources()

	return prv, err
}

func (pr *Provider) Close() {
	log.Debugf("Closing provider %s", pr.Name)
	pr.sl.Close()
	pr.osl.Close()
}

func (prv *Provider) createDefaultResources() error {
	_, err := prv.sl.Get(adminUserId, prv.RsTypes["User"])

	if err != nil {
		adminUser := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
                   "id": "%s",
                   "userName":"admin",
                   "displayName":"Administrator",
                   "password":"secret",
				   "active": true,
                   "emails":[
                       {
                         "value":"admin@%s",
                         "type":"work",
                         "primary":true
                       }
                     ]
                   }`

		adminUser = fmt.Sprintf(adminUser, adminUserId, prv.Name) // fill in the placeholders
		buf := bytes.NewBufferString(adminUser)
		userRes, err := base.ParseResource(prv.RsTypes, prv.Schemas, buf)
		if err != nil {
			return err
		}

		_, err = prv.sl.InsertInternal(userRes)
		if err != nil {
			return err
		}

		log.Infof("Successfully inserted default administrator user %s", adminUserId)
	}

	groupName := "Administrator"
	_, err = prv.sl.Get(adminGroupId, prv.RsTypes["Group"])
	if err != nil {
		adminGroup := `{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
	                "id": "%s",
				    "displayName": "%s",
				    "permissions": [{"resName": "*", "opsArr" : "[{\"op\":\"read\",\"allowAttrs\": \"*\",\"filter\":\"ANY\"},{\"op\":\"write\",\"allowAttrs\":\"*\",\"filter\":\"ANY\"}]"}],
                   "members": [
                       {
                          "value": "%s"
                       }
                     ]
				   }`

		adminGroup = fmt.Sprintf(adminGroup, adminGroupId, groupName, adminUserId)

		buf := bytes.NewBufferString(adminGroup)

		grpRes, err := base.ParseResource(prv.RsTypes, prv.Schemas, buf)
		if err != nil {
			return err
		}

		_, err = prv.sl.InsertInternal(grpRes)
		if err != nil {
			return err
		}

		log.Infof("Successfully inserted default admin group %s", adminGroupId)
	}

	return nil
}

func (prv *Provider) GetSchemaJsonArray() string {
	json := "["

	for _, v := range prv.Schemas {
		json += v.Text + ","
	}

	json = strings.TrimSuffix(json, ",")

	return json + "]"
}

func (prv *Provider) GetSchema(id string) (string, error) {
	sc := prv.Schemas[id]

	if sc == nil {
		return "", fmt.Errorf("No schema present with the ID %s", id)
	}

	return sc.Text, nil
}

func (prv *Provider) GetResTypeJsonArray() string {
	json := "["

	for _, v := range prv.RsTypes {
		json += v.Text + ","
	}

	json = strings.TrimSuffix(json, ",")

	return json + "]"
}

func (prv *Provider) GetResourceType(name string) (string, error) {
	rt := prv.RsTypes[name]

	if rt == nil {
		return "", fmt.Errorf("No resource type present with the ID %s", name)
	}

	return rt.Text, nil
}

func (prv *Provider) GetConfigJson() (data []byte, err error) {
	return json.Marshal(prv.Config.Scim)
}

func (prv *Provider) CreateResource(crCtx *base.CreateContext) (res *base.Resource, err error) {
	if !crCtx.AllowOp() {
		return nil, base.NewForbiddenError("Insufficent privileges to create a resource")
	}

	return prv.sl.Insert(crCtx.InRes)
}

func (prv *Provider) DeleteResource(delCtx *base.DeleteContext) error {
	od := delCtx.GetDecision()
	if od.Deny {
		return base.NewForbiddenError("Insufficent privileges to delete the resource")
	}

	if od.EvalFilter {
		res, err := prv.sl.Get(delCtx.Rid, delCtx.Rt)
		if res != nil {
			if !delCtx.EvalDelete(res) {
				return base.NewForbiddenError("Insufficent privileges to delete the resource")
			}
		} else {
			// no need to attempt delete again, the entry is not found
			return err
		}
	}

	if delCtx.Rid == delCtx.Session.Sub {
		return base.NewForbiddenError("Cannot delete self")
	}

	if _, ok := prv.immResIds[delCtx.Rid]; ok {
		msg := fmt.Sprintf("Resource with ID %s cannot be deleted, it is required for the functioning of server", delCtx.Rid)
		log.Debugf(msg)
		return base.NewForbiddenError(msg)
	}

	return prv.sl.Delete(delCtx.Rid, delCtx.Rt)
}

func (prv *Provider) GetResource(getCtx *base.GetContext) (res *base.Resource, err error) {
	od := getCtx.GetDecision()
	if od.Deny {
		return nil, base.NewForbiddenError("Insufficent privileges to read the resource")
	} else if od.EvalFilter {
		res, err = prv.sl.Get(getCtx.Rid, getCtx.Rt)
		if err != nil {
			return nil, err
		}

		allow := getCtx.AllowRead(res)
		if allow {
			//FIXME filter resource attributes
			return res, nil
		} else {
			return nil, base.NewForbiddenError("Insufficent privileges to read the resource")
		}
	}

	return prv.sl.Get(getCtx.Rid, getCtx.Rt)
}

func (prv *Provider) Search(sc *base.SearchContext, outPipe chan *base.Resource) error {
	deny, fn := sc.CanDenyOp()
	if deny {
		return base.NewForbiddenError("Insufficent privileges to search resources")
	}

	if fn != nil {
		// modify the filter
		and := &base.FilterNode{Op: "AND"}
		and.Children = make([]*base.FilterNode, 2)
		and.Children[0] = sc.Filter
		and.Children[1] = fn
		sc.Filter = and
	}

	sc.MaxResults = prv.Config.Scim.Filter.MaxResults
	go prv.sl.Search(sc, outPipe)

	return nil
}

func (prv *Provider) Replace(replaceCtx *base.ReplaceContext) (res *base.Resource, err error) {
	if !replaceCtx.AllowOp() {
		return nil, base.NewForbiddenError("Insufficent privileges to replace the resource")
	}

	return prv.sl.Replace(replaceCtx.InRes, replaceCtx.IfNoneMatch)
}

func (prv *Provider) Patch(patchCtx *base.PatchContext) (res *base.Resource, err error) {
	od := patchCtx.GetDecision()
	if od.Deny {
		return nil, base.NewForbiddenError("Insufficent privileges to update the resource")
	}

	if od.EvalFilter {
		res, err = prv.sl.Get(patchCtx.Rid, patchCtx.Rt)
		if err != nil {
			return nil, err
		}

		if !patchCtx.EvalPatch(res) {
			return nil, base.NewForbiddenError("Insufficent privileges to update the resource")
		}
	} else if od.EvalWithoutFetch {
		if !patchCtx.EvalPatch(nil) {
			return nil, base.NewForbiddenError("Insufficent privileges to update the resource")
		}
	}

	return prv.sl.Patch(patchCtx.Rid, patchCtx.Pr, patchCtx.Rt)
}

func (prv *Provider) Authenticate(username string, password string) (res *base.Resource) {
	user, err := prv.sl.Authenticate(username, password)

	if err != nil {
		msg := "Invalid username or password"
		log.Debugf(msg)
		return nil
	}

	return user
}

func (prv *Provider) GetUserByName(getCtx *base.GetContext) (res *base.Resource) {
	user, err := prv.sl.GetUserByName(getCtx.Username)

	if err != nil {
		msg := "Invalid username"
		log.Debugf(msg)
		return nil
	}

	return user
}

func (prv *Provider) GenSessionForUserId(rid string) (session *base.RbacSession, err error) {
	user, err := prv.sl.GetUser(rid)
	if err != nil {
		return nil, err
	}

	session = prv.GenSessionForUser(user)
	return session, nil
}

func (prv *Provider) GenSessionForUser(user *base.Resource) *base.RbacSession {
	return prv.sl.Engine.NewRbacSession(user)
}

func (prv *Provider) GetUserById(rid string) (user *base.Resource, err error) {
	user, err = prv.sl.GetUser(rid)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (prv *Provider) DomainCode() uint32 {
	if prv.domainCode != 0 {
		return prv.domainCode
	}

	prv.domainCode = 0
	for _, r := range prv.Name {
		prv.domainCode += uint32(r)
	}

	return prv.domainCode
}

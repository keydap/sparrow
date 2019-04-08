// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package provider

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	_ "github.com/dgrijalva/jwt-go"
	logger "github.com/juju/loggo"
	samlTypes "github.com/russellhaering/gosaml2/types"
	"html/template"
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
	domainCode    string
	osl           *oauth.OauthSilo
	interceptors  []base.Interceptor
	Al            *AuditLogger
	SamlMdCache   map[string]*samlTypes.SPSSODescriptor
}

const AdminGroupId = "01000000-0000-4000-4000-000000000000"
const SystemGroupId = "01100000-0000-4000-4000-000000000000"
const AdminUserId = "00000000-0000-4000-4000-000000000000"

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.provider")
}

func NewProvider(layout *Layout, serverId uint16) (prv *Provider, err error) {
	schemas, err := base.LoadSchemas(layout.SchemaDir)
	if err != nil {
		return nil, err
	}

	prv = &Provider{}
	prv.ServerId = serverId
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

	prv.Config.CsnGen = base.NewCsnGenerator(prv.ServerId)
	prv.layout = layout
	prv.Name = layout.name
	prv.immResIds = make(map[string]int)
	prv.immResIds[AdminGroupId] = 1
	prv.immResIds[SystemGroupId] = 1
	prv.immResIds[AdminUserId] = 1

	dataFilePath := filepath.Join(layout.DataDir, "data.db")
	prv.sl, err = silo.Open(dataFilePath, prv.ServerId, prv.Config, prv.RsTypes, prv.Schemas)
	if err != nil {
		return nil, err
	}
	prv.sl.Engine.Domain = layout.name

	odbFilePath := filepath.Join(layout.DataDir, "tokens.db")
	prv.osl, err = oauth.Open(odbFilePath, prv.Config.Oauth.TokenPurgeInterval, prv.Config.Oauth.GrantCodePurgeInterval, prv.Config.Oauth.GrantCodeMaxLife)

	if err != nil {
		return nil, err
	}

	prv.LdapTemplates = base.LoadLdapTemplates(layout.LdapTmplDir, prv.RsTypes)

	cf := prv.Config
	cf.Ppolicy.PasswdHashAlgo = strings.ToLower(cf.Ppolicy.PasswdHashAlgo)

	prv.interceptors = make([]base.Interceptor, 3)
	prv.interceptors[0] = &ApplicationInterceptor{}
	prv.interceptors[1] = &RemoveNeverAttrInterceptor{}
	prv.interceptors[2] = &PpolicyInterceptor{Config: cf.Ppolicy}

	var rfc2307i *Rfc2307BisAttrInterceptor
	if cf.Rfc2307bis.Enabled {
		uidNumber, err := prv.sl.GetMaxIndexedValOfAt(prv.RsTypes["User"], "uidNumber")
		if err != nil {
			log.Debugf("failed to get the highest uidNumber %s", err.Error())
		}
		if cf.Rfc2307bis.UidNumberStart > uidNumber {
			uidNumber = cf.Rfc2307bis.UidNumberStart - 1 // decrement by one so that it exactly starts at the configured number
		}

		gidNumber, err := prv.sl.GetMaxIndexedValOfAt(prv.RsTypes["Group"], "gidNumber")
		if err != nil {
			log.Debugf("failed get the highest gidNumber %s", err.Error())
		}
		if cf.Rfc2307bis.GidNumberStart > gidNumber {
			gidNumber = cf.Rfc2307bis.GidNumberStart - 1 // decrement by one so that it exactly starts at the configured number
		}

		rfc2307i = &Rfc2307BisAttrInterceptor{Conf: cf.Rfc2307bis, uidNumber: uidNumber, gidNumber: gidNumber}
		prv.interceptors = append(prv.interceptors, rfc2307i)
	}

	err = prv.createDefaultResources(rfc2307i)

	prv.Al = NewLocalAuditLogger(prv)
	prv.SamlMdCache = make(map[string]*samlTypes.SPSSODescriptor)

	return prv, err
}

func (pr *Provider) Close() {
	log.Debugf("closing provider %s", pr.Name)
	pr.sl.Close()
	pr.osl.Close()
	pr.Al.Close()
}

func (prv *Provider) createDefaultResources(rfc2307i *Rfc2307BisAttrInterceptor) error {
	_, err := prv.sl.Get(AdminUserId, prv.RsTypes["User"])

	if err != nil {
		adminUser := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
                   "id": "%s",
                   "userName":"admin",
                   "displayName":"Administrator",
				   "active": true,
                   "emails":[
                       {
                         "value":"admin@%s",
                         "type":"work",
                         "primary":true
                       }
                     ]
                   }`

		adminUser = fmt.Sprintf(adminUser, AdminUserId, prv.Name) // fill in the placeholders
		buf := bytes.NewBufferString(adminUser)
		userRes, err := base.ParseResource(prv.RsTypes, prv.Schemas, buf)
		if err != nil {
			return err
		}

		password := utils.HashPassword("secret", prv.Config.Ppolicy.PasswdHashAlgo)
		userRes.AddSA("password", password)
		if rfc2307i != nil {
			err = rfc2307i._preCreate(userRes)
			if err != nil {
				return err
			}
		}
		crCtx := &base.CreateContext{InRes: userRes}
		err = prv.sl.InsertInternal(crCtx)
		if err != nil {
			return err
		}

		log.Infof("successfully inserted default administrator user %s", AdminUserId)
	}

	groupName := "Administrator"
	_, err = prv.sl.Get(AdminGroupId, prv.RsTypes["Group"])
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

		adminGroup = fmt.Sprintf(adminGroup, AdminGroupId, groupName, AdminUserId)

		buf := bytes.NewBufferString(adminGroup)

		grpRes, err := base.ParseResource(prv.RsTypes, prv.Schemas, buf)
		if err != nil {
			return err
		}

		if rfc2307i != nil {
			err = rfc2307i._preCreate(grpRes)
			if err != nil {
				return err
			}
		}
		crCtx := &base.CreateContext{InRes: grpRes}
		err = prv.sl.InsertInternal(crCtx)
		if err != nil {
			return err
		}

		log.Infof("successfully inserted default admin group %s", AdminGroupId)
	}

	groupName = "System"
	_, err = prv.sl.Get(SystemGroupId, prv.RsTypes["Group"])
	if err != nil {
		systemGroup := `{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
	                "id": "%s",
				    "displayName": "%s",
                    "members": [
                       {
                          "value": "%s"
                       }
                     ]
				   }`

		systemGroup = fmt.Sprintf(systemGroup, SystemGroupId, groupName, AdminUserId)

		buf := bytes.NewBufferString(systemGroup)

		grpRes, err := base.ParseResource(prv.RsTypes, prv.Schemas, buf)
		if err != nil {
			return err
		}

		if rfc2307i != nil {
			err = rfc2307i._preCreate(grpRes)
			if err != nil {
				return err
			}
		}

		crCtx := &base.CreateContext{InRes: grpRes}
		err = prv.sl.InsertInternal(crCtx)
		if err != nil {
			return err
		}

		log.Infof("successfully inserted default system group %s", SystemGroupId)
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
		return "", fmt.Errorf("no schema present with the ID %s", id)
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
		return "", fmt.Errorf("no resource type present with the ID %s", name)
	}

	return rt.Text, nil
}

func (prv *Provider) GetConfigJson() (data []byte, err error) {
	return json.Marshal(prv.Config.Scim)
}

func (prv *Provider) CreateResource(crCtx *base.CreateContext) (res *base.Resource, err error) {
	if crCtx.Repl {
		err = prv.sl.InsertInternal(crCtx)
		// run the rfc2307bis interceptor, the syncing of uid and gid across cluster is a big thing and worth solving
		// how about deriving a number from the corresponding resource's UUID instead of incrementing??
		return crCtx.InRes, err
	}

	defer func() {
		prv.Al.Log(crCtx, res, err)
	}()

	isAuditRes := (crCtx.InRes.GetType() == prv.Al.rt)

	if isAuditRes || !crCtx.AllowOp() {
		return nil, base.NewForbiddenError("insufficent privileges to create a resource")
	}

	err = prv.firePreInterceptors(crCtx)
	if err != nil {
		return nil, err
	}

	err = prv.sl.Insert(crCtx)

	if err == nil {
		for _, intrcptr := range prv.interceptors {
			intrcptr.PostCreate(crCtx)
		}
	}

	return res, err
}

func (prv *Provider) DeleteResource(delCtx *base.DeleteContext) (err error) {
	defer func() {
		prv.Al.Log(delCtx, nil, err)
	}()

	od := delCtx.GetDecision()
	if od.Deny {
		err = base.NewForbiddenError("insufficent privileges to delete the resource")
		return err
	}

	if od.EvalFilter {
		res, err := prv.sl.Get(delCtx.Rid, delCtx.Rt)
		if res != nil {
			if !delCtx.EvalDelete(res) {
				err = base.NewForbiddenError("insufficent privileges to delete the resource")
				return err
			}
		} else {
			// no need to attempt delete again, the entry is not found
			return err
		}
	}

	if delCtx.Rid == delCtx.Session.Sub {
		err = base.NewForbiddenError("cannot delete self")
		return err
	}

	if _, ok := prv.immResIds[delCtx.Rid]; ok {
		msg := fmt.Sprintf("resource with ID %s cannot be deleted, it is required for the functioning of server", delCtx.Rid)
		log.Debugf(msg)
		err = base.NewForbiddenError(msg)
		return err
	}

	return prv.sl.Delete(delCtx.Rid, delCtx.Rt)
}

func (prv *Provider) GetResource(getCtx *base.GetContext) (res *base.Resource, err error) {
	defer func() {
		prv.Al.Log(getCtx, res, err)
	}()

	sl := prv.sl
	if getCtx.Rt == prv.Al.rt {
		sl = prv.Al.sl
	}

	od := getCtx.GetDecision()
	if od.Deny {
		return nil, base.NewForbiddenError("insufficent privileges to read the resource")
	} else if od.EvalFilter {
		res, err = sl.Get(getCtx.Rid, getCtx.Rt)
		if err != nil {
			return nil, err
		}

		allow := getCtx.AllowRead(res)
		if allow {
			return res, nil
		} else {
			return nil, base.NewForbiddenError("insufficent privileges to read the resource")
		}
	}

	return sl.Get(getCtx.Rid, getCtx.Rt)
}

func (prv *Provider) Search(sc *base.SearchContext, outPipe chan *base.Resource) (err error) {

	defer func() {
		prv.Al.Log(sc, nil, err)
	}()

	sl := prv.sl
	if len(sc.ResTypes) == 1 && sc.ResTypes[0] == prv.Al.rt {
		sl = prv.Al.sl
	}

	deny, fn := sc.CanDenyOp()
	if deny {
		err = base.NewForbiddenError("insufficent privileges to search resources")
		return err
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
	go sl.Search(sc, outPipe)

	return nil
}

func (prv *Provider) Replace(replaceCtx *base.ReplaceContext) (res *base.Resource, err error) {
	defer func() {
		prv.Al.Log(replaceCtx, res, err)
	}()

	if !replaceCtx.AllowOp() {
		return nil, base.NewForbiddenError("insufficent privileges to replace the resource")
	}

	return prv.sl.Replace(replaceCtx.InRes, replaceCtx.IfMatch)
}

func (prv *Provider) Patch(patchCtx *base.PatchContext) (res *base.Resource, err error) {
	defer func() {
		prv.Al.Log(patchCtx, res, err)
	}()

	od := patchCtx.GetDecision()
	if od.Deny {
		return nil, base.NewForbiddenError("insufficent privileges to update the resource")
	}

	if od.EvalFilter {
		res, err = prv.sl.Get(patchCtx.Rid, patchCtx.Rt)
		if err != nil {
			return nil, err
		}

		if !patchCtx.EvalPatch(res) {
			return nil, base.NewForbiddenError("insufficent privileges to update the resource")
		}
	} else if od.EvalWithoutFetch {
		if !patchCtx.EvalPatch(nil) {
			return nil, base.NewForbiddenError("insufficent privileges to update the resource")
		}
	}

	err = prv.firePreInterceptors(patchCtx)
	if err != nil {
		return nil, err
	}

	res, err = prv.sl.Patch(patchCtx.Rid, patchCtx.Pr, patchCtx.Rt)

	if err == nil {
		for _, intrcptr := range prv.interceptors {
			intrcptr.PostPatch(res, patchCtx)
		}
	}

	return res, err
}

func (prv *Provider) StoreTotpSecret(rid string, totpSecret string, clientIP string) (err error) {
	defer func() {
		prv.Al.LogStoreTotp(rid, clientIP, err)
	}()

	err = prv.sl.StoreTotpSecret(rid, totpSecret)
	if err != nil {
		log.Warningf("%s", err)
	}

	return err
}

func (prv *Provider) Authenticate(ar base.AuthRequest) (lr base.LoginResult) {
	var originalStatus base.LoginStatus

	defer func() {
		prv.Al.LogAuth(lr.Id, ar.Username, ar.ClientIP, originalStatus)
	}()

	lr, err := prv.sl.Authenticate(ar.Username, ar.Password)
	originalStatus = lr.Status

	if lr.Status != base.LOGIN_SUCCESS {
		log.Debugf("%s", err)
		if lr.Status != base.LOGIN_TFA_REGISTER && lr.Status != base.LOGIN_TFA_REQUIRED && lr.Status != base.LOGIN_CHANGE_PASSWORD {
			// erase all other statuses
			lr.Status = base.LOGIN_FAILED
		}
	}

	return lr
}

func (prv *Provider) VerifyOtp(rid string, totpCode string, clientIP string) (lr base.LoginResult) {
	var originalStatus base.LoginStatus

	defer func() {
		prv.Al.LogOtp(rid, clientIP, lr.User, originalStatus)
	}()

	lr, err := prv.sl.VerifyOtp(rid, totpCode)
	originalStatus = lr.Status

	if lr.Status != base.LOGIN_SUCCESS && lr.Status != base.LOGIN_CHANGE_PASSWORD {
		log.Debugf("%s", err)
		// erase all other statuses
		lr.Status = base.LOGIN_FAILED
	}

	return lr
}

func (prv *Provider) ChangePassword(rid string, newPassword string, clientIP string) (user *base.Resource, err error) {
	defer func() {
		prv.Al.LogChangePasswd(rid, clientIP, user)
	}()

	user, err = prv.sl.ChangePassword(rid, newPassword, prv.Config.Ppolicy.PasswdHashAlgo)

	if err != nil {
		log.Debugf("%s", err)
	}

	return user, err
}

func (prv *Provider) GetUserByName(username string) (res *base.Resource) {
	user, err := prv.sl.GetUserByName(username)

	if err != nil {
		log.Debugf("no user found with username %s", username)
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

func (prv *Provider) ModifyGroupsOfUser(autg base.ModifyGroupsOfUserRequest) (user *base.Resource, err error) {
	res, err := prv.sl.Get(autg.UserRid, prv.RsTypes["User"])
	if err != nil {
		return nil, err
	}

	if !autg.AllowOp(res) {
		return nil, base.NewForbiddenError("insufficent privileges to add groups to user")
	}

	return prv.sl.ModifyGroupsOfUser(autg)
}

func (prv *Provider) DomainCode() string {
	if prv.domainCode != "" {
		return prv.domainCode
	}

	sh2 := sha256.New()
	sh2.Write([]byte(prv.Name))
	hash := sh2.Sum([]byte{})
	hexVal := fmt.Sprintf("%x", hash[:])
	prv.domainCode = hexVal[:8]
	return prv.domainCode
}

func (prv *Provider) firePreInterceptors(ctx interface{}) (err error) {
	for _, i := range prv.interceptors {
		switch t := ctx.(type) {
		case *base.CreateContext:
			err = i.PreCreate(ctx.(*base.CreateContext))

		case *base.PatchContext:
			err = i.PrePatch(ctx.(*base.PatchContext))

		default:
			log.Warningf("unknown operation context type %t", t)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

// make provider a dsig.X509KeyStore
func (prv *Provider) GetKeyPair() (privateKey *rsa.PrivateKey, cert []byte, err error) {
	// TODO this is a dangerous cast and must be eliminated
	// when other privatekey types are supported
	rsaKey := prv.PrivKey.(*rsa.PrivateKey)
	return rsaKey, prv.Cert.Raw, nil
}

func (prv *Provider) SaveConf() error {
	csn := prv.Config.CsnGen.NewCsn()
	prv.Config.Scim.Meta.LastModified = csn.DateTime()
	prv.Config.Scim.Meta.Version = csn.String()
	data, _ := json.MarshalIndent(prv.Config, "", "    ")
	dConfPath := filepath.Join(prv.layout.ConfDir, "domain.json")
	err := ioutil.WriteFile(dConfPath, data, utils.FILE_PERM)
	return err
}

func (prv *Provider) ReadTemplate(name string) (data []byte, err error) {
	html := strings.HasSuffix(name, ".html") // HTML templates have .html suffix
	json := strings.HasSuffix(name, ".json") // LDAP templates have .json suffix

	log.Debugf("requested template %s", name)
	if !(html || json) {
		return nil, base.NewBadRequestError("unknown template type")
	}

	if html {
		f, err := os.Open(filepath.Join(prv.layout.TmplDir, name))
		if os.IsNotExist(err) {
			f, err = os.Open(filepath.Join(prv.layout.ConfDir, "..", "..", "..", "templates", name))
		}
		if err == nil {
			data, err = ioutil.ReadAll(f)
			f.Close()
		}
	} else if json {
		f, err := os.Open(filepath.Join(prv.layout.LdapTmplDir, name))
		if err == nil {
			data, err = ioutil.ReadAll(f)
			f.Close()
		}
	}

	return data, err
}

func (prv *Provider) UpdateTemplate(name string, data []byte) (t *template.Template, err error) {
	html := strings.HasSuffix(name, ".html") // HTML templates have .html suffix
	json := strings.HasSuffix(name, ".json") // LDAP templates have .json suffix

	if !(html || json) {
		return nil, base.NewBadRequestError("unknown template type")
	}

	if html {
		t = template.New(name)
		t, err = t.Parse(string(data))
		if err == nil {
			fullPath := filepath.Join(prv.layout.TmplDir, name)
			_, err := os.Stat(fullPath)
			if os.IsNotExist(err) {
				fullPath = filepath.Join(prv.layout.ConfDir, "..", "..", "..", "templates", name)
				log.Warningf(fullPath)
				_, err = os.Stat(fullPath)
			}

			if err == nil {
				err = ioutil.WriteFile(fullPath, data, utils.FILE_PERM)
			}
		} else {
			err = base.NewBadRequestError(err.Error())
		}
	} else if json {
		var ldapTmpl *schema.LdapEntryTemplate
		ldapTmpl, err = schema.NewLdapTemplate(data, prv.RsTypes)
		if err == nil {
			fullPath := filepath.Join(prv.layout.LdapTmplDir, name)
			_, err = os.Stat(fullPath)
			if err == nil {
				err = ioutil.WriteFile(fullPath, data, utils.FILE_PERM)
				if err == nil {
					prv.LdapTemplates[ldapTmpl.Type] = ldapTmpl
				}
			}
		} else {
			err = base.NewBadRequestError(err.Error())
		}
	}

	return t, err
}

func (prv *Provider) AddAppToSsoSession(jti string, spIssuer string, sas base.SamlAppSession) {
	prv.osl.AddAppToSsoSession(jti, spIssuer, sas)
}

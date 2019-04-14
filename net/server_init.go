// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/mholt/caddy"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/provider"
	"sparrow/repl"
	"sparrow/schema"
	"sparrow/utils"
	"strconv"
	"strings"
	"sync"
)

var DEFAULT_SRV_CONF string = `{
	"serverId": 0,
    "enableHttps" : true,
    "httpPort" : 7090,
    "ldapPort" : 7092,
	"ldapEnabled" : true,
    "ldapOverTlsOnly" : true,
    "ipAddress" : "0.0.0.0",
    "certificateFile": "default.cer",
    "privatekeyFile": "default.key",
	"controllerDomain": "example.com",
	"skipPeerCertCheck": true
}`

var COOKIE_LOGIN_NAME string = "SPLCN"

type Sparrow struct {
	providers map[string]*provider.Provider

	// a map of providers keyed using the hashcode of the domain name
	// this exists to keep the length of Oauth code fixed to N bytes
	dcPrvMap map[string]*provider.Provider

	// used for encrypting authflow cookies
	ckc *utils.CookieKeyCache

	homeUrl string

	uiHandler     http.Handler
	defaultDomain string
	srvConf       *conf.ServerConf
	templates     map[string]*template.Template
	instance      *caddy.Instance
	homeDir       string
	replDir       string
	listener      *net.TCPListener

	rl    *repl.ReplSilo
	peers map[uint16]*base.ReplicationPeer

	// Mutex to serialize updates to the domain configuration
	dconfUpdateMutex sync.Mutex
}

func NewSparrowServer(homeDir string) *Sparrow {
	sparrow := &Sparrow{}
	sparrow.homeDir = homeDir
	sparrow.defaultDomain = "example.com"
	sparrow.ckc = utils.NewCookieKeyCache()
	return sparrow
}

func (sp *Sparrow) Start() {
	log.Debugf("Starting server(s)...")

	sp.initHome()
	sp.templates = parseTemplates(sp.srvConf.TmplDir)

	if len(sp.providers) == 1 {
		for _, pr := range sp.providers {
			sp.defaultDomain = pr.Name
		}
	}

	var err error
	sp.rl, err = repl.OpenReplSilo(path.Join(sp.replDir, "repl-data.db"))
	if err != nil {
		panic(err)
	}

	// load the existing peers
	sp.peers = sp.rl.GetReplicationPeers()

	if sp.srvConf.LdapEnabled {
		err := sp.startLdap()
		if err != nil {
			panic(err)
		}
	}

	sp.startHttp()
}

func (sp *Sparrow) Stop() {
	if sp.srvConf.LdapEnabled {
		sp.stopLdap()
	}
	sp.stopHttp()
}

func (sp *Sparrow) initHome() *conf.ServerConf {
	srvHome := sp.homeDir
	log.Debugf("Checking server home directory %s", srvHome)
	utils.CheckAndCreate(srvHome)

	srvConfDir := filepath.Join(srvHome, "srvconf")
	log.Debugf("Checking server's configuration directory %s", srvConfDir)
	utils.CheckAndCreate(srvConfDir)

	tmplDir := filepath.Join(srvHome, "templates")
	log.Debugf("Checking server's templates directory %s", tmplDir)
	utils.CheckAndCreate(tmplDir)
	writeDefaultHtmlTemplates(tmplDir)

	sp.replDir = filepath.Join(srvHome, "replication")
	log.Debugf("Checking server's repication directory %s", sp.replDir)
	utils.CheckAndCreate(sp.replDir)

	srvConfPath := filepath.Join(srvConfDir, "server.json")
	_, err := os.Stat(srvConfPath)

	sc := &conf.ServerConf{}
	sc.TmplDir = tmplDir

	if os.IsNotExist(err) {
		strConf := DEFAULT_SRV_CONF
		addr := flag.Lookup("a").Value.(flag.Getter).Get().(string)
		enableTls := flag.Lookup("tls").Value.(flag.Getter).Get().(bool)
		addr = strings.TrimSpace(addr)

		var tmp conf.ServerConf
		err = json.Unmarshal([]byte(strConf), &tmp)
		if err != nil {
			panic(err)
		}

		if addr != "" || enableTls {
			parts := strings.Split(addr, ":")
			if len(parts) > 0 {
				tmp.IpAddress = parts[0]
			}
			if len(parts) == 2 {
				port, err := strconv.Atoi(parts[1])
				if err != nil {
					panic(err)
				}
				tmp.HttpPort = port
				if port == 443 {
					tmp.Https = true
				}
			}

			if enableTls {
				tmp.Https = true
			}

		}

		tmp.ServerId = genRandomServerId()
		data, err := json.MarshalIndent(tmp, "", "  ")
		if err != nil {
			panic(err)
		}
		strConf = string(data)

		err = ioutil.WriteFile(srvConfPath, []byte(strConf), utils.FILE_PERM)
		if err != nil {
			log.Criticalf("Couldn't write the default server configuration file %s %#v", srvConfPath, err)
			panic(err)
		}

		err = utils.CreateCert(srvConfDir, "default")
		if err != nil {
			log.Warningf("Failed to create the default certificate and key pair %#v", err)
		}
	}

	data, err := ioutil.ReadFile(srvConfPath)
	if err != nil {
		log.Criticalf("Couldn't read the server configuration file %s %#v", srvConfPath, err)
		panic(err)
	}

	err = json.Unmarshal(data, sc)
	if err != nil {
		log.Criticalf("Couldn't parse the server configuration file %s %#v", srvConfPath, err)
		panic(err)
	}

	sc.ControllerDomain = strings.ToLower(sc.ControllerDomain)

	// parse the certificate and privatekey
	pb, absFilePath, err := pemDecode(srvConfDir, sc.CertFile)
	if err == nil {
		sc.CertChain, err = x509.ParseCertificates(pb.Bytes)
		if err != nil {
			log.Warningf("Failed to parse certificate from file %s %#v", absFilePath, err)
		}
		sc.CertFile = absFilePath
		sc.PubKey = sc.CertChain[0].PublicKey
	}

	pb, absFilePath, err = pemDecode(srvConfDir, sc.PrivKeyFile)
	if err == nil {
		var pKey crypto.PrivateKey
		if pb.Type == "RSA PRIVATE KEY" {
			pKey, err = x509.ParsePKCS1PrivateKey(pb.Bytes)
		} else {
			pKey, err = x509.ParsePKCS8PrivateKey(pb.Bytes)
		}
		if err != nil {
			log.Warningf("Failed to parse privatekey from file %s %#v", absFilePath, err)
			panic(err)
		}
		sc.PrivKey = pKey
		sc.PrivKeyFile = absFilePath
		//TODO support other types of private keys
	}

	domainsDir := filepath.Join(srvHome, "domains")
	log.Debugf("Checking server domains directory %s", domainsDir)
	utils.CheckAndCreate(domainsDir)

	skipCertCheck := false
	if sc.SkipPeerCertCheck {
		skipCertCheck = true
	} else {
		// configure the trust store
	}
	tlsConf := &tls.Config{InsecureSkipVerify: skipCertCheck}
	sc.ReplTransport = &http.Transport{TLSClientConfig: tlsConf}

	sp.srvConf = sc
	sp.loadProviders(domainsDir)

	cwd, _ := os.Getwd()
	fmt.Println("Current working directory: ", cwd)

	if len(sp.providers) == 0 {
		sp.createDefaultDomain(domainsDir)
	}

	uiDir := filepath.Join(srvHome, "ui")
	log.Debugf("Checking server UI directory %s", uiDir)
	utils.CheckAndCreate(uiDir)
	writeDefaultUiStyle(uiDir)

	return sc
}

func pemDecode(srvConfDir string, givenFilePath string) (pb *pem.Block, absFilePath string, err error) {
	if !strings.ContainsRune(givenFilePath, os.PathSeparator) {
		givenFilePath = srvConfDir + string(os.PathSeparator) + givenFilePath
	}

	data, err := ioutil.ReadFile(givenFilePath)
	if err != nil {
		log.Debugf("Failed to read the PEM encoded file %s", givenFilePath)
		return nil, "", err
	}

	pb, _ = pem.Decode(data)
	if pb == nil {
		log.Debugf("Failed to decode the PEM file %s", givenFilePath)
		return nil, "", err
	}

	return pb, givenFilePath, nil
}

func (sp *Sparrow) loadProviders(domainsDir string) {
	sc := sp.srvConf
	sp.providers = make(map[string]*provider.Provider)
	sp.dcPrvMap = make(map[string]*provider.Provider)

	log.Infof("Loading domains")
	dir, err := os.Open(domainsDir)
	if err != nil {
		err = fmt.Errorf("Could not open domains directory %s [%s]", domainsDir, err.Error())
		panic(err)
	}

	files, err := dir.Readdir(-1)

	if err != nil {
		err = fmt.Errorf("Could not read domains from directory %s [%s]", domainsDir, err.Error())
		panic(err)
	}

	for _, f := range files {
		if f.IsDir() {
			lDir := filepath.Join(domainsDir, f.Name())
			layout, err := provider.NewLayout(lDir, false)
			if err != nil {
				log.Infof("Could not create a layout from the directory %s [%s]", lDir, err.Error())
			} else {
				lName := layout.Name()
				if _, ok := sp.providers[lName]; ok {
					log.Infof("A provider for the domain %s already loaded, ignoring the domain present at %s", lName, lDir)
					continue
				}

				prv, err := provider.NewProvider(layout, sc.ServerId)
				if err != nil {
					log.Infof("Could not create a provider for the domain %s [%s]", layout.Name(), err.Error())
				} else {
					prv.Cert = sc.CertChain[0]
					prv.PrivKey = sc.PrivKey
					prv.ServerId = sc.ServerId
					prv.ReplTransport = sc.ReplTransport
					sp.providers[lName] = prv
					sp.dcPrvMap[prv.DomainCode()] = prv
				}
			}
		}
	}

	log.Infof("Loaded providers for %d domains", len(sp.providers))
}

func (sp *Sparrow) createDefaultDomain(domainsDir string) {
	sc := sp.srvConf
	log.Infof("Creating default domain")

	defaultDomain := filepath.Join(domainsDir, "example.com")
	layout, err := provider.NewLayout(defaultDomain, true)
	if err != nil {
		panic(err)
	}

	writeSchemas(layout.SchemaDir)

	writeResourceTypes(layout.ResTypesDir)

	//confDir := wDir + "/conf"
	//copyDir(confDir, layout.ConfDir)

	// default LDAP templates
	ldapUserTmpl := filepath.Join(layout.LdapTmplDir, "ldap-user.json")
	writeFile(ldapUserTmpl, schema.LDAP_User_Entry)

	ldapGroupTmpl := filepath.Join(layout.LdapTmplDir, "ldap-group.json")
	writeFile(ldapGroupTmpl, schema.LDAP_Group_Entry)

	prv, err := provider.NewProvider(layout, sc.ServerId)
	if err != nil {
		panic(err)
	}

	prv.Cert = sc.CertChain[0]
	prv.PrivKey = sc.PrivKey
	sp.providers[layout.Name()] = prv
	sp.dcPrvMap[prv.DomainCode()] = prv
}

func copyDir(src, dest string) {
	dir, err := os.Open(src)
	if err != nil {
		panic(err)
	}

	defer dir.Close()

	files, err := dir.Readdir(-1)

	if err != nil {
		panic(err)
	}

	for _, f := range files {
		sFile := filepath.Join(src, f.Name())
		tFile := filepath.Join(dest, f.Name())
		if f.IsDir() {
			err = os.Mkdir(tFile, utils.DIR_PERM)
			if err != nil {
				panic(err)
			}
			copyDir(sFile, tFile)
			continue
		}

		data, err := ioutil.ReadFile(sFile)
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(tFile, data, utils.FILE_PERM)

		if err != nil {
			panic(err)
		}
	}
}

func parseTemplates(tmplDir string) map[string]*template.Template {
	templates := make(map[string]*template.Template)

	dir, err := os.Open(tmplDir)
	if err == nil {
		files, err := dir.Readdir(0)
		if err != nil {
			log.Warningf("Failed to read template directory %s [%s]", tmplDir, err)
		} else {
			for _, f := range files {
				if f.IsDir() {
					continue
				}

				name := f.Name()
				if strings.HasSuffix(name, ".html") {
					absFilePath := filepath.Join(tmplDir, name)
					tmpl, err := template.ParseFiles(absFilePath)
					if err != nil {
						log.Warningf("Failed to parse the template %s [%s]", name, err)
					} else {
						templates[name] = tmpl
					}
				}
			}
		}
	} else {
		log.Warningf("Failed to open template directory %s [%s]", tmplDir, err)
	}

	return templates
}

func writeDefaultUiStyle(uiDir string) {
	// login-style.css
	loginStyle := filepath.Join(uiDir, "login-style.css")
	writeFile(loginStyle, login_style)
}

func writeDefaultHtmlTemplates(tmplDir string) {
	// login.html
	loginTmpl := filepath.Join(tmplDir, "login.html")
	writeFile(loginTmpl, login_html)

	// consent.html
	consentTmpl := filepath.Join(tmplDir, "consent.html")
	writeFile(consentTmpl, consent_html)

	// saml_response.html
	samlResponseTmpl := filepath.Join(tmplDir, "saml_response.html")
	writeFile(samlResponseTmpl, saml_response_html)

	// totp-register.html
	totpRegisterTmpl := filepath.Join(tmplDir, "totp-register.html")
	writeFile(totpRegisterTmpl, totp_register_html)

	// totp-send.html
	totpSendTmpl := filepath.Join(tmplDir, "totp-send.html")
	writeFile(totpSendTmpl, totp_send_html)

	// changepassword.html
	cpTmpl := filepath.Join(tmplDir, "changepassword.html")
	writeFile(cpTmpl, changepassword_html)
}

func writeFile(name string, content string) {
	ff, _ := os.Stat(name)
	if ff != nil {
		return
	}
	err := ioutil.WriteFile(name, []byte(content), utils.FILE_PERM)
	if err != nil {
		log.Criticalf("Couldn't write the file %s %#v", name, err)
		panic(err)
	}
}

func writeSchemas(schemaDir string) {
	device := filepath.Join(schemaDir, "device.json")
	writeFile(device, device_schema)

	entUser := filepath.Join(schemaDir, "enterprise-user.json")
	writeFile(entUser, enterprise_user_schema)

	group := filepath.Join(schemaDir, "group.json")
	writeFile(group, group_schema)

	posixGroup := filepath.Join(schemaDir, "posix-group.json")
	writeFile(posixGroup, posix_group_schema)

	user := filepath.Join(schemaDir, "user.json")
	writeFile(user, user_schema)

	posixUser := filepath.Join(schemaDir, "posix-user.json")
	writeFile(posixUser, posix_user_schema)

	application := filepath.Join(schemaDir, "application.json")
	writeFile(application, application_schema)

	authentication := filepath.Join(schemaDir, "authentication.json")
	writeFile(authentication, authentication_schema)

	auditevent := filepath.Join(schemaDir, "auditevent.json")
	writeFile(auditevent, auditevent_schema)
}

func writeResourceTypes(rtDir string) {
	device := filepath.Join(rtDir, "device.json")
	writeFile(device, device_type)

	group := filepath.Join(rtDir, "group.json")
	writeFile(group, group_type)

	user := filepath.Join(rtDir, "user.json")
	writeFile(user, user_type)

	application := filepath.Join(rtDir, "application.json")
	writeFile(application, application_type)

	auditevent := filepath.Join(rtDir, "auditevent.json")
	writeFile(auditevent, auditevent_type)
}

// Generates a ranom unsigned integer of two bytes
// The first byte is a ranom value and the second is the first byte from MAC address of any interface
func genRandomServerId() uint16 {
	log.Debugf("generating server ID")
	var id uint16
	randBytes := utils.RandBytes(2)
	id = uint16(randBytes[0])
	id = id<<8 | uint16(randBytes[1])
	return id
}

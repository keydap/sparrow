// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"html/template"
	"io/ioutil"
	"os"
	"path/filepath"
	"sparrow/conf"
	"sparrow/provider"
	"sparrow/schema"
	"sparrow/utils"
	"strings"
)

var DEFAULT_SRV_CONF string = `{
	"serverId": 0,
    "enableHttps" : false,
    "httpPort" : 7090,
    "ldapPort" : 7092,
    "ldapOverTlsOnly" : true,
    "ipAddress" : "0.0.0.0",
    "certificateFile": "default.cer",
    "privatekeyFile": "default.key"
}`

var COOKIE_LOGIN_NAME string = "SPLCN"

var homeDir string

func Start(srvHome string) {
	log.Debugf("Starting server(s)...")

	homeDir = srvHome
	srvConf = initHome(srvHome)
	templates = parseTemplates(srvConf.TmplDir)

	err := startLdap()
	if err != nil {
		panic(err)
	}

	startHttp()
}

func Stop() {
	stopLdap()
	stopHttp()
}

func initHome(srvHome string) *conf.ServerConf {
	log.Debugf("Checking server home directory %s", srvHome)
	utils.CheckAndCreate(srvHome)

	srvConfDir := filepath.Join(srvHome, "srvconf")
	log.Debugf("Checking server's configuration directory %s", srvConfDir)
	utils.CheckAndCreate(srvConfDir)

	tmplDir := filepath.Join(srvHome, "templates")
	log.Debugf("Checking server's templates directory %s", tmplDir)
	utils.CheckAndCreate(tmplDir)
	writeDefaultHtmlTemplates(tmplDir)

	oauthDir := filepath.Join(srvHome, "oauth")
	log.Debugf("Checking server's oauth directory %s", oauthDir)
	utils.CheckAndCreate(oauthDir)

	srvConfPath := filepath.Join(srvConfDir, "server.json")
	_, err := os.Stat(srvConfPath)

	sc := &conf.ServerConf{}
	sc.TmplDir = tmplDir

	if err != nil {
		err = ioutil.WriteFile(srvConfPath, []byte(DEFAULT_SRV_CONF), utils.FILE_PERM)
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

	// parse the certificate and privatekey
	data, absFilePath, err := pemDecode(srvConfDir, sc.CertFile)
	if err == nil {
		sc.CertChain, err = x509.ParseCertificates(data)
		if err != nil {
			log.Warningf("Failed to parse certificate from file %s %#v", absFilePath, err)
		}
		sc.CertFile = absFilePath
	}

	data, absFilePath, err = pemDecode(srvConfDir, sc.PrivKeyFile)
	if err == nil {
		rsaPrivKey, err := x509.ParsePKCS1PrivateKey(data)
		if err != nil {
			log.Warningf("Failed to parse privatekey from file %s %#v", absFilePath, err)
		}
		sc.PrivKey = rsaPrivKey
		sc.PubKey = rsaPrivKey.Public()
		sc.PrivKeyFile = absFilePath
		//TODO support other types of private keys
	}

	domainsDir := filepath.Join(srvHome, "domains")
	log.Debugf("Checking server domains directory %s", domainsDir)
	utils.CheckAndCreate(domainsDir)

	loadProviders(domainsDir, sc)

	cwd, _ := os.Getwd()
	fmt.Println("Current working directory: ", cwd)

	if len(providers) == 0 {
		createDefaultDomain(domainsDir, sc)
	}

	cs = sessions.NewCookieStore(securecookie.GenerateRandomKey(32))

	return sc
}

func pemDecode(srvConfDir string, givenFilePath string) (data []byte, absFilePath string, err error) {
	if !strings.ContainsRune(givenFilePath, os.PathSeparator) {
		givenFilePath = srvConfDir + string(os.PathSeparator) + givenFilePath
	}

	data, err = ioutil.ReadFile(givenFilePath)
	if err != nil {
		log.Debugf("Failed to read the PEM encoded file %s", givenFilePath)
		return nil, "", err
	}

	pb, _ := pem.Decode(data)
	if pb == nil {
		log.Debugf("Failed to decode the PEM file %s", givenFilePath)
		return nil, "", err
	}

	return pb.Bytes, givenFilePath, nil
}

func loadProviders(domainsDir string, sc *conf.ServerConf) {
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
				if _, ok := providers[lName]; ok {
					log.Infof("A provider for the domain %s already loaded, ignoring the domain present at %s", lName, lDir)
					continue
				}

				prv, err := provider.NewProvider(layout)
				if err != nil {
					log.Infof("Could not create a provider for the domain %s [%s]", layout.Name(), err.Error())
				} else {
					prv.Cert = sc.CertChain[0]
					prv.PrivKey = sc.PrivKey
					prv.ServerId = sc.ServerId
					providers[lName] = prv
					dcPrvMap[prv.DomainCode()] = prv
				}
			}
		}
	}

	log.Infof("Loaded providers for %d domains", len(providers))
}

func createDefaultDomain(domainsDir string, sc *conf.ServerConf) {
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

	prv, err := provider.NewProvider(layout)
	if err != nil {
		panic(err)
	}

	prv.Cert = sc.CertChain[0]
	prv.PrivKey = sc.PrivKey
	prv.ServerId = sc.ServerId
	providers[layout.Name()] = prv
	dcPrvMap[prv.DomainCode()] = prv
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

	user := filepath.Join(schemaDir, "user.json")
	writeFile(user, user_schema)

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

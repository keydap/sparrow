package net

import (
	"fmt"
	. "github.com/onsi/gomega"
	"os"
	"sparrow/client"
	"sparrow/utils"
	"time"
)

// the master and slave words are used just for the sake of better understanding
// while following the interaction, in reality they both are peers
const masterHome string = "/tmp/master"
const slaveHome string = "/tmp/slave"
const seconSlaveHome string = "/tmp/secondslave"

const masterConf string = `{
	"serverId": 1,
    "enableHttps" : true,
    "httpPort" : 7090,
    "ldapPort" : 7092,
	"ldapEnabled" : true,
    "ldapOverTlsOnly" : true,
    "ipAddress" : "localhost",
    "certificateFile": "default-cert.pem",
    "privatekeyFile": "default-key.pem",
	"defaultDomain": "example.com",
	"controllerDomain": "example.com",
	"skipPeerCertCheck": true
}`
const slaveConf string = `{
	"serverId": 2,
    "enableHttps" : true,
    "httpPort" : 9090,
    "ldapPort" : 9092,
	"ldapEnabled" : true,
    "ldapOverTlsOnly" : true,
    "ipAddress" : "localhost",
    "certificateFile": "default-cert.pem",
    "privatekeyFile": "default-key.pem",
	"controllerDomain": "example.com",
	"defaultDomain": "example.com",
	"skipPeerCertCheck": true
}`

const secondSlaveConf string = `{
	"serverId": 3,
    "enableHttps" : true,
    "httpPort" : 2090,
    "ldapPort" : 2092,
	"ldapEnabled" : true,
    "ldapOverTlsOnly" : true,
    "ipAddress" : "localhost",
    "certificateFile": "default-cert.pem",
    "privatekeyFile": "default-key.pem",
	"controllerDomain": "example.com",
	"defaultDomain": "example.com",
	"skipPeerCertCheck": true
}`

var master *Sparrow
var slave *Sparrow
var mclient *client.SparrowClient
var sclient *client.SparrowClient
var domainName string

func initPeers() {
	os.RemoveAll(masterHome)
	os.RemoveAll(slaveHome)
	os.RemoveAll(seconSlaveHome)

	master = NewSparrowServer(masterHome, masterConf)
	slave = NewSparrowServer(slaveHome, slaveConf)
	domainName = master.srvConf.DefaultDomain

	go master.Start()
	time.Sleep(2 * time.Second)
	go slave.Start()
	time.Sleep(2 * time.Second)
}

func createClients() {
	mclient = client.NewSparrowClient(master.homeUrl)
	mclient.DirectLogin("admin", "secret", domainName)
	err := mclient.MakeSchemaAware()
	Expect(err).ToNot(HaveOccurred())
	sclient = client.NewSparrowClient(slave.homeUrl)
	sclient.DirectLogin("admin", "secret", domainName)
	err = sclient.MakeSchemaAware()
	Expect(err).ToNot(HaveOccurred())
}

func joinAndApprove() {
	result := sclient.SendJoinReq("localhost", master.srvConf.HttpPort)
	Expect(result.StatusCode).To(Equal(200))
	result = mclient.ApproveJoinReq(slave.srvConf.ServerId)
	Expect(result.StatusCode).To(Equal(200))
}

func createRandomUser() string {
	tmpl := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
                   "userName":"%s",
                   "displayName":"%s",
				   "active": true,
                   "password": "%s",
                   "emails":[
                       {
                         "value":"%s@%s",
                         "type":"work",
                         "primary":true
                       }
                     ]
                   }`

	username := utils.NewRandShaStr()[0:7]
	displayname := username
	password := username
	domain := master.srvConf.DefaultDomain

	return fmt.Sprintf(tmpl, username, displayname, password, username, domain)
}

func createRandomGroup(members ...string) string {
	tmpl := `{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				    "displayName": "%s",
				    "permissions": [{"value": "*", "opsArr" : "[{\"op\":\"read\",\"allowAttrs\": \"*\",\"filter\":\"ANY\"}]"}],
                    "members": [ %s ]

             }`

	mTmpl := `"{
                 "value": "%s"
               },"`

	memberAt := ""

	for _, v := range members {
		memberAt += fmt.Sprintf(mTmpl, v)
	}
	mlen := len(memberAt)

	if mlen > 0 {
		memberAt = memberAt[0 : mlen-1]
	}

	groupname := utils.NewRandShaStr()[0:7]
	return fmt.Sprintf(tmpl, groupname, memberAt)
}

func checkReplicatedResources(srcClient *client.SparrowClient, targetClient *client.SparrowClient) {
	for _, rt := range srcClient.ResTypes {
		// audit events are not replicated
		if rt.Name == "AuditEvent" {
			continue
		}

		sr := srcClient.GetAll(rt)
		Expect(sr.StatusCode).To(Equal(200))
		for _, srcRs := range sr.Resources {
			cr := targetClient.GetResource(srcRs.GetId(), srcRs.GetType())
			Expect(cr.StatusCode).To(Equal(200))
			log.Debugf("%s = %s", srcRs.GetId(), cr.Rs.GetId())
			Expect(srcRs.GetVersion()).To(Equal(cr.Rs.GetVersion()))
		}
	}
}

package net

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"os"
	"sparrow/base"
	"sparrow/client"
	"testing"
	"time"
)

// the master and slave words are used just for the sake of better understanding
// while following the interaction, in reality they both are peers
const masterHome string = "/tmp/master"
const slaveHome string = "/tmp/slave"
const masterConf string = `{
	"serverId": 1,
    "enableHttps" : true,
    "httpPort" : 7090,
    "ldapPort" : 7092,
	"ldapEnabled" : true,
    "ldapOverTlsOnly" : true,
    "ipAddress" : "0.0.0.0",
    "certificateFile": "default.cer",
    "privatekeyFile": "default.key",
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
    "ipAddress" : "0.0.0.0",
    "certificateFile": "default.cer",
    "privatekeyFile": "default.key",
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

	master = NewSparrowServer(masterHome, masterConf)
	slave = NewSparrowServer(slaveHome, slaveConf)
	domainName = master.srvConf.DefaultDomain

	go master.Start()
	time.Sleep(2 * time.Second)
	go slave.Start()
	time.Sleep(2 * time.Second)
}

func TestRepl(t *testing.T) {
	RegisterFailHandler(Fail)
	initPeers()
	RunSpecs(t, "Replication silo test suite")
}

var _ = Describe("testing replication", func() {
	BeforeSuite(func() {
		mclient = client.NewSparrowClient(master.homeUrl)
		mclient.DirectLogin("admin", "secret", domainName)
		err := mclient.MakeSchemaAware()
		Expect(err).ToNot(HaveOccurred())
		sclient = client.NewSparrowClient(slave.homeUrl)
		sclient.DirectLogin("admin", "secret", domainName)
		err = sclient.MakeSchemaAware()
		Expect(err).ToNot(HaveOccurred())
	})
	AfterSuite(func() {
		go master.Stop()
		slave.Stop()
	})
	Context("replicate create resource", func() {
		It("join and approve", func() {
			result := sclient.SendJoinReq("localhost", master.srvConf.HttpPort)
			Expect(result.StatusCode).To(Equal(200))
			result = mclient.ApproveJoinReq(slave.srvConf.ServerId)
			Expect(result.StatusCode).To(Equal(200))
		})
		It("create resource on both master and slave and check", func() {
			// create on master and check on slave
			userJson := createRandomUser()
			result := mclient.AddUser(userJson)
			Expect(result.StatusCode).To(Equal(201))
			time.Sleep(1 * time.Second)
			id := result.Rs.GetId()
			replResult := sclient.GetUser(id)
			Expect(replResult.StatusCode).To(Equal(200))

			// create on slave and check on master
			userJson = createRandomUser()
			result = sclient.AddUser(userJson)
			Expect(result.StatusCode).To(Equal(201))
			time.Sleep(1 * time.Second)
			id = result.Rs.GetId()
			replResult = mclient.GetUser(id)
			Expect(replResult.StatusCode).To(Equal(200))
		})
		It("create resource on master and login on slave", func() {
			// create on master and check on slave
			userJson := createRandomUser()
			rs, _ := mclient.ParseResource([]byte(userJson))
			username := rs.GetAttr("username").GetSimpleAt().GetStringVal()
			password := rs.GetAttr("password").GetSimpleAt().GetStringVal()

			result := mclient.AddUser(userJson)
			Expect(result.StatusCode).To(Equal(201))
			time.Sleep(1 * time.Second)
			tclient := client.NewSparrowClient(slave.homeUrl)
			err := tclient.DirectLogin(username, password, domainName)
			Expect(err).ToNot(HaveOccurred())
			err = tclient.MakeSchemaAware()
			Expect(err).ToNot(HaveOccurred())
			// then fetch using this new client
			//TODO this requires fixing permission issue
			//id := result.Rs.GetId()
			//replResult := tclient.GetUser(id)
			//Expect(replResult.StatusCode).To(Equal(200))
		})
	})
})

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

	username := base.RandStr()
	displayname := username
	password := username
	domain := master.srvConf.DefaultDomain

	return fmt.Sprintf(tmpl, username, displayname, password, username, domain)
}

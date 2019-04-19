package net

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"os"
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

func initPeers() {
	os.RemoveAll(masterHome)
	os.RemoveAll(slaveHome)

	master = NewSparrowServer(masterHome, "")
	slave = NewSparrowServer(slaveHome, slaveConf)

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
		mclient.DirectLogin("admin", "secret", "example.com")

		sclient = client.NewSparrowClient(slave.homeUrl)
		sclient.DirectLogin("admin", "secret", "example.com")
	})
	AfterSuite(func() {
		//master.Stop()
		//slave.Stop()
	})
	Context("pending replication join", func() {
		It("join", func() {
			result := sclient.SendJoinReq("localhost", master.srvConf.HttpPort)
			fmt.Println(result.ErrorMsg)
			Expect(result.StatusCode).To(Equal(200))
		})
	})
})

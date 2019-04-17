package net

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"os"
	"sparrow/client"
	"testing"
)

// the master and slave words are used just for the sake of better understanding
// while following the interaction, in reality they both are peers
const masterHome string = "/tmp/master"
const slaveHome string = "/tmp/slave"
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
	go slave.Start()
}

func TestRepl(t *testing.T) {
	RegisterFailHandler(Fail)
	initPeers()
	RunSpecs(t, "Replication silo test suite")
}

var _ = Describe("testing replication", func() {
	BeforeSuite(func() {
		mclient = client.NewSparrowClient(master.homeUrl + API_BASE)
		mclient.DirectLogin("admin", "secret", "example.com")

		sclient = client.NewSparrowClient(slave.homeUrl + API_BASE)
		sclient.DirectLogin("admin", "secret", "example.com")
	})
	AfterSuite(func() {
		master.Stop()
		slave.Stop()
	})
	Context("pending replication join", func() {
		It("join", func() {
			result := sclient.SendJoinReq("localhost", master.srvConf.HttpPort)
			Expect(result.StatusCode).To(Equal(200))
		})
	})
})

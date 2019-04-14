package net

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"os"
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

func initPeers() {
	os.RemoveAll(masterHome)
	os.RemoveAll(slaveHome)

	master = NewSparrowServer(masterHome, "")
	slave = NewSparrowServer(slaveHome, slaveConf)

	go master.Start()
	//go slave.Start()
}

func TestRepl(t *testing.T) {
	RegisterFailHandler(Fail)
	initPeers()
	RunSpecs(t, "Replication silo test suite")
}

var _ = Describe("testing replication", func() {
	AfterSuite(func() {
		master.Stop()
		//slave.Stop()
	})
	Context("pending replication join", func() {
		It("join", func() {
			i := 0
			Expect(i).To(Equal(0))
		})
	})
})

package repl

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/url"
	"os"
	"sparrow/utils"
	"testing"
)

var dbFilePath = "/tmp/silo_test.db"
var sl *ReplSilo

func initSilo() {
	if sl != nil {
		sl.Close()
		os.Remove(dbFilePath)
	}

	var err error
	sl, err = OpenReplSilo(dbFilePath)

	if err != nil {
		fmt.Println("Failed to open replication silo\n", err)
		os.Exit(1)
	}

	os.Remove(dbFilePath)
}

func TestReplSilo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Replication silo test suite")
}

var _ = Describe("testing replication silo", func() {
	BeforeEach(func() {
		initSilo()
	})

	Context("pending replication join peers", func() {
		It("insert, get and delete", func() {
			peer := JoinRequest{}
			peer.WebHookToken = "abcd"
			peer.ServerId = 1
			peer.Host = "localhost"
			peer.Port = 8080
			peer.CreatedTime = utils.DateTimeMillis()

			err := sl.AddSentJoinReq(peer)
			Expect(err).ToNot(HaveOccurred())

			peers := sl.GetSentJoinRequests()
			Expect(len(peers)).To(Equal(1))
			Expect(peers[0]).To(Equal(peer))

			// insert another request with the same ID again and the count should be same
			peer.Host = "127.0.0.1"
			err = sl.AddSentJoinReq(peer)
			Expect(err).ToNot(HaveOccurred())
			peers = sl.GetSentJoinRequests()
			Expect(len(peers)).To(Equal(1))
			Expect(peers[0]).To(Equal(peer))

			err = sl.DeleteSentJoinRequest(peer.ServerId)
			Expect(err).ToNot(HaveOccurred())
			peers = sl.GetSentJoinRequests()
			Expect(len(peers)).To(Equal(0))
		})
	})

	Context("replication peers", func() {
		It("insert, get and delete", func() {
			peer := &ReplicationPeer{}
			peer.WebHookToken = "abcd"
			peer.ServerId = 1
			peer.EventsUrl, _ = url.Parse("https://localhost:8080")
			peer.CreatedTime = utils.DateTimeMillis()
			peer.LastReqSentTime = utils.DateTimeMillis()

			err := sl.AddReplicationPeer(peer)
			Expect(err).ToNot(HaveOccurred())

			fetchedPeer := sl.GetReplicationPeer(peer.ServerId)
			Expect(fetchedPeer).To(Equal(peer))

			err = sl.DeleteReplicationPeer(peer.ServerId)
			Expect(err).ToNot(HaveOccurred())

			fetchedPeer = sl.GetReplicationPeer(peer.ServerId)
			var nilPeer *ReplicationPeer
			Expect(fetchedPeer).To(Equal(nilPeer))
		})
	})
})

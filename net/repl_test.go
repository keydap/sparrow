package net

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"os"
	"sparrow/base"
	"sparrow/client"
	"sparrow/utils"
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
		It("patch resource on master and check on slave", func() {
			// create on master and check on slave
			userJson := createRandomUser()
			result := mclient.AddUser(userJson)
			Expect(result.StatusCode).To(Equal(201))
			time.Sleep(1 * time.Second)
			id := result.Rs.GetId()
			replResult := sclient.GetUser(id)
			Expect(replResult.StatusCode).To(Equal(200))

			// patch the resource on master
			rsVersion := result.Rs.GetVersion()
			nickName := "patchedNick"
			displayName := "patchedDisplay"
			pr := fmt.Sprintf(`{"Operations":[{"op":"add", "path": "nickName", "value":"%s"}, {"op":"replace", "path": "displayName", "value":"%s"}]}`, nickName, displayName)
			patchResult := mclient.Patch(pr, id, result.Rs.GetType(), rsVersion, "*")
			Expect(patchResult.StatusCode).To(Equal(200))
			// create on slave and check on master
			time.Sleep(1 * time.Second)
			replResult = sclient.GetUser(id)
			rs := replResult.Rs
			Expect(replResult.StatusCode).To(Equal(200))
			Expect(rs.GetAttr("nickname").GetSimpleAt().GetStringVal()).To(Equal(nickName))
			Expect(rs.GetAttr("displayName").GetSimpleAt().GetStringVal()).To(Equal(displayName))
			Expect(rs.GetVersion()).To(Equal(patchResult.Rs.GetVersion()))
		})
		It("patch a group on master and check its members on slave", func() {
			// create on master and check on slave
			userJson := createRandomUser()
			mUserResult := mclient.AddUser(userJson)
			Expect(mUserResult.StatusCode).To(Equal(201))

			uid := mUserResult.Rs.GetId()
			mGroupResult := mclient.AddGroup(createRandomGroup())
			Expect(mGroupResult.StatusCode).To(Equal(201))
			gid := mGroupResult.Rs.GetId()
			groupVersion := mGroupResult.Rs.GetVersion()
			// now patch the group to add the new user
			pr := fmt.Sprintf(`{"Operations":[{"op":"add", "path": "members", "value":[{"value": "%s"}]}]}`, uid)
			patchResult := mclient.Patch(pr, gid, mGroupResult.Rs.GetType(), groupVersion, "*")
			Expect(patchResult.StatusCode).To(Equal(200))

			time.Sleep(1 * time.Second)

			// check on slave that the patched group was replicated and the user has the correct group membership
			replUserResult := sclient.GetUser(uid)
			replGroupResult := sclient.GetGroup(gid)
			Expect(replUserResult.StatusCode).To(Equal(200))
			Expect(replGroupResult.StatusCode).To(Equal(200))
			Expect(replGroupResult.Rs.GetAttr("members").GetComplexAt().HasValue(uid)).To(BeTrue())
			Expect(replUserResult.Rs.GetAttr("groups").GetComplexAt().HasValue(gid)).To(BeTrue())
			// the version of user MUST not get updated when the group membership changes
			Expect(replUserResult.Rs.GetVersion()).To(Equal(mUserResult.Rs.GetVersion()))
			// and the group's version remains same
			Expect(replGroupResult.Rs.GetVersion()).To(Equal(patchResult.Rs.GetVersion()))
		})
		It("delete resource on master and check on slave", func() {
			// create on master
			userJson := createRandomUser()
			createResult := mclient.AddUser(userJson)
			Expect(createResult.StatusCode).To(Equal(201))
			uid := createResult.Rs.GetId()
			delResult := mclient.Delete(uid, createResult.Rs.GetType())
			Expect(delResult.StatusCode).To(Equal(204))
			time.Sleep(1 * time.Second)
			getResult := sclient.GetUser(uid)
			Expect(getResult.StatusCode).To(Equal(404))
		})
		It("replace resource on master and check on slave", func() {
			// create on master
			userJson := createRandomUser()
			createResult := mclient.AddUser(userJson)
			Expect(createResult.StatusCode).To(Equal(201))
			uid := createResult.Rs.GetId()
			replaceUserJson := createRandomUser()
			// the username is also getting replaced, which may not work if the new name is already taken
			replaceResult := mclient.Replace(uid, replaceUserJson, createResult.Rs.GetType(), createResult.Rs.GetVersion())
			Expect(replaceResult.StatusCode).To(Equal(200))
			time.Sleep(1 * time.Second)

			getResult := sclient.GetUser(uid)
			Expect(getResult.StatusCode).To(Equal(200))
			Expect(true).To(Equal(replaceResult.Rs.Equals(getResult.Rs)))
		})
		It("change password on master and check on slave", func() {
			// this scenario can't be tested using client, http layer needs
			// to be bypassed to invoke changepassword directly
			userJson := createRandomUser()
			result := mclient.AddUser(userJson)
			username := result.Rs.GetAttr("username").GetSimpleAt().GetStringVal()
			newPassword := "abcdefghijk"
			mPr := master.providers[domainName]
			cpCtx := &base.ChangePasswordContext{}
			cpCtx.OpContext = &base.OpContext{ClientIP: "localhost"}
			cpCtx.Rid = result.Rs.GetId()
			cpCtx.NewPassword = newPassword
			err := mPr.ChangePassword(cpCtx)
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(1 * time.Second)
			// login on the client with the new password to verify that changed password was replicated
			tclient := client.NewSparrowClient(slave.homeUrl)
			err = tclient.DirectLogin(username, newPassword, domainName)
			Expect(err).ToNot(HaveOccurred())
		})
		It("create a new SSO session on master and check on slave", func() {
			mPr := master.providers[domainName]
			userJson := createRandomUser()
			result := mclient.AddUser(userJson)
			ssoSession, err := mPr.GenSessionForUserId(result.Rs.GetId())
			Expect(err).ToNot(HaveOccurred())
			Expect(ssoSession).ToNot(Equal(nil))
			mPr.StoreSsoSession(ssoSession)
			oauthSession, err := mPr.GenSessionForUserId(result.Rs.GetId())
			Expect(err).ToNot(HaveOccurred())
			Expect(oauthSession).ToNot(Equal(nil))
			mPr.StoreOauthSession(oauthSession)
			time.Sleep(1 * time.Second)
			sPr := slave.providers[domainName]
			slaveSsoSession := sPr.GetSsoSession(ssoSession.Jti)
			Expect(ssoSession.Jti).To(Equal(slaveSsoSession.Jti))
			slaveOauthSession := sPr.GetOauthSession(oauthSession.Jti)
			Expect(oauthSession.Jti).To(Equal(slaveOauthSession.Jti))

			// revoke the oauth session and check on slave
			mPr.RevokeOauthSession(&base.OpContext{}, oauthSession.Jti)
			deletedSsoSessionResult := mPr.DeleteSsoSession(&base.OpContext{Session: ssoSession})
			Expect(deletedSsoSessionResult).To(Equal(true))
			time.Sleep(1 * time.Second)
			revokedSessionStatus := sPr.IsRevokedSession(&base.OpContext{}, oauthSession.Jti)
			Expect(revokedSessionStatus).To(Equal(true))
			slaveSsoSession = sPr.GetSsoSession(ssoSession.Jti)
			Expect(slaveSsoSession).To(BeNil())
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

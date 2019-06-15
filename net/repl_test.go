package net

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"sparrow/base"
	"sparrow/client"
	"sparrow/schema"
	"testing"
	"time"
)

func TestRepl(t *testing.T) {
	RegisterFailHandler(Fail)
	initPeers()
	RunSpecs(t, "Replication silo test suite")
}

func injectUsers(cl *client.SparrowClient, count int) []string {
	ids := make([]string, 0)
	for i := 0; i < count; i++ {
		userJson := createRandomUser()
		result := cl.AddUser(userJson)
		Expect(result.StatusCode).To(Equal(201))
		ids = append(ids, result.Rs.GetId())
	}

	Expect(len(ids)).To(Equal(count))
	return ids
}

func patchResources(ids []string, pr string, rt *schema.ResourceType, cl *client.SparrowClient) {
	for _, v := range ids {
		result := cl.GetResource(v, rt)
		patchResult := cl.Patch(pr, v, rt, result.Rs.GetVersion(), "*")
		Expect(patchResult.StatusCode).To(Equal(200))
	}
}

func checkExistence(cl *client.SparrowClient, ids []string, rt *schema.ResourceType) {
	for _, v := range ids {
		result := cl.GetResource(v, rt)
		Expect(result.StatusCode).To(Equal(200))
	}
}

func checkPatchedValues(cl *client.SparrowClient, ids []string, rt *schema.ResourceType, matcherFunc func(rs *base.Resource)) {
	for _, v := range ids {
		result := cl.GetResource(v, rt)
		Expect(result.StatusCode).To(Equal(200))
		matcherFunc(result.Rs)
	}
}

func restartServer(sp *Sparrow) {
	if sp == master {
		master = NewSparrowServer(masterHome, masterConf)
		go master.Start()
	} else if sp == slave {
		slave = NewSparrowServer(slaveHome, slaveConf)
		go slave.Start()
	}
}

func create_resource_on_both_master_and_slave_and_check() {
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
}

func create_resource_on_master_and_login_on_slave() {
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
}

func patch_resource_on_master_and_check_on_slave() {
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
}

func patch_a_group_on_master_and_check_its_members_on_slave() {
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
}

func delete_resource_on_master_and_check_on_slave() {
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
}

func replace_resource_on_master_and_check_on_slave() {
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
}

func change_password_on_master_and_check_on_slave() {
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
}

func create_a_new_SSO_session_on_master_and_check_on_slave() {
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
}

func stop_slave_inject_on_master_start_slave_then_check() {
	// create on master and check on slave
	userJson := createRandomUser()
	result := mclient.AddUser(userJson)
	Expect(result.StatusCode).To(Equal(201))
	time.Sleep(1 * time.Second)
	id := result.Rs.GetId()
	replResult := sclient.GetUser(id)
	Expect(replResult.StatusCode).To(Equal(200))

	// stop the slave and inject 10 users on master
	slave.Stop()
	ids := injectUsers(mclient, 10)
	restartServer(slave)
	time.Sleep(5 * time.Second)
	checkExistence(sclient, ids, sclient.ResTypes["User"])
}

func stop_slave_inject_and_modify_on_master_and_start_slave_then_check() {
	// stop the slave and inject 10 users on master
	slave.Stop()
	ids := injectUsers(mclient, 10)
	nickName := "testNickName"
	displayName := "testDisplayName"
	pr := fmt.Sprintf(`{"Operations":[{"op":"add", "path": "nickName", "value":"%s"}, {"op":"replace", "path": "displayName", "value":"%s"}]}`, nickName, displayName)
	patchResources(ids, pr, mclient.ResTypes["User"], mclient)
	restartServer(slave)
	time.Sleep(5 * time.Second)
	checkPatchedValues(sclient, ids, sclient.ResTypes["User"], func(rs *base.Resource) {
		nick := rs.GetAttr("nickName").GetSimpleAt().GetStringVal()
		display := rs.GetAttr("displayName").GetSimpleAt().GetStringVal()
		Expect(nick).To(Equal(nickName))
		Expect(display).To(Equal(displayName))
	})
}

func start_second_slave_and_clone() {
	secondSlave := NewSparrowServer(seconSlaveHome, secondSlaveConf)
	go secondSlave.Start()
	time.Sleep(2 * time.Second)

	secondSclient := client.NewSparrowClient(secondSlave.homeUrl)
	secondSclient.DirectLogin("admin", "secret", domainName)
	err := secondSclient.MakeSchemaAware()
	Expect(err).ToNot(HaveOccurred())

	injectUsers(mclient, 10) // inject 10 more entries in master server

	result := secondSclient.SendJoinReq("localhost", master.srvConf.HttpPort)
	Expect(result.StatusCode).To(Equal(200))
	result = mclient.ApproveJoinReq(secondSlave.srvConf.ServerId)
	Expect(result.StatusCode).To(Equal(200))

	time.Sleep(2 * time.Second)
	checkReplicatedResources(mclient, secondSclient)
}

var _ = Describe("testing replication", func() {
	BeforeSuite(createClients)
	AfterSuite(func() {
		go master.Stop()
		slave.Stop()
	})
	Context("replicate create resource", func() {
		It("join and approve", joinAndApprove)
		It("create resource on both master and slave and check", create_resource_on_both_master_and_slave_and_check)
		It("create resource on master and login on slave", create_resource_on_master_and_login_on_slave)
		It("patch resource on master and check on slave", patch_resource_on_master_and_check_on_slave)
		It("patch a group on master and check its members on slave", patch_a_group_on_master_and_check_its_members_on_slave)
		It("delete resource on master and check on slave", delete_resource_on_master_and_check_on_slave)
		It("replace resource on master and check on slave", replace_resource_on_master_and_check_on_slave)
		It("change password on master and check on slave", change_password_on_master_and_check_on_slave)
		It("create a new SSO session on master and check on slave", create_a_new_SSO_session_on_master_and_check_on_slave)
	})
	Context("testing replication backlog", func() {
		It("join and approve", joinAndApprove)
		It("stop slave inject on master start slave then check", stop_slave_inject_on_master_start_slave_then_check)
		It("stop slave inject and modify on master and start slave then check", stop_slave_inject_and_modify_on_master_and_start_slave_then_check)
	})
	Context("testing server cloning", func() {
		It("start second slave and clone", start_second_slave_and_clone)
	})
})

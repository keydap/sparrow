package provider

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/http"
	"sparrow/base"
	"sparrow/repl"
	"sparrow/utils"
)

type ReplInterceptor struct {
	replSilo     *repl.ReplProviderSilo
	domainCode   string
	peers        map[uint16]*repl.ReplicationPeer
	transport    *http.Transport
	serverId     uint16
	webhookToken string
	// do not reuse the encoder
	//buf          *bytes.Buffer
	//enc          *gob.Encoder
}

func (ri *ReplInterceptor) PreCreate(crCtx *base.CreateContext) error {
	return nil
}

func (ri *ReplInterceptor) PostCreate(crCtx *base.CreateContext) {
	event := repl.ReplicationEvent{}
	event.Version = crCtx.InRes.GetVersion()
	event.CreatedRes = crCtx.InRes
	event.DomainCode = ri.domainCode
	event.Type = repl.RESOURCE_CREATE
	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the generated create replication event [%#v]", err)
	}
}

func (ri *ReplInterceptor) PrePatch(patchCtx *base.PatchContext) error {
	return nil
}

func (ri *ReplInterceptor) PostPatch(patchCtx *base.PatchContext) {
	event := repl.ReplicationEvent{}
	event.Version = patchCtx.Res.GetVersion()
	event.DomainCode = ri.domainCode
	event.Type = repl.RESOURCE_PATCH
	event.Data = patchCtx.Pr.RawReq
	event.PatchRid = patchCtx.Rid
	event.RtName = patchCtx.Rt.Name
	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the generated patch replication event [%#v]", err)
	}
}

func (ri *ReplInterceptor) PreDelete(delCtx *base.DeleteContext) error {
	return nil
}

func (ri *ReplInterceptor) PostDelete(delCtx *base.DeleteContext) {
	event := repl.ReplicationEvent{}
	event.Version = delCtx.DeleteCsn
	event.Rid = delCtx.Rid
	event.DomainCode = ri.domainCode
	event.Type = repl.RESOURCE_DELETE
	event.RtName = delCtx.Rt.Name
	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the generated delete replication event [%#v]", err)
	}
}

func (ri *ReplInterceptor) PreReplace(replaceCtx *base.ReplaceContext) error {
	return nil
}

func (ri *ReplInterceptor) PostReplace(replaceCtx *base.ReplaceContext) {
	event := repl.ReplicationEvent{}
	event.Version = replaceCtx.Res.GetVersion()
	event.ResToReplace = replaceCtx.InRes
	event.DomainCode = ri.domainCode
	event.Type = repl.RESOURCE_REPLACE
	event.RtName = replaceCtx.Rt.Name
	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the generated create replication event [%#v]", err)
	}
}

func (ri *ReplInterceptor) PostStoreSession(session *base.RbacSession, ssoSession bool, version string) {
	event := repl.ReplicationEvent{}
	event.Version = version
	event.DomainCode = ri.domainCode
	event.Type = repl.NEW_SESSION
	event.NewSession = session
	event.SsoSession = ssoSession

	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the generated new session replication event [%#v]", err)
	}
}

func (ri *ReplInterceptor) PostRevokeSession(jti string, version string) {
	event := repl.ReplicationEvent{}
	event.Version = version
	event.DomainCode = ri.domainCode
	event.Type = repl.REVOKE_SESSION
	event.RevokedSessionId = jti

	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the generated new session replication event [%#v]", err)
	}
}

func (ri *ReplInterceptor) PostChangePassword(cpContext *base.ChangePasswordContext) {
	// send the changed password hash as patch to avoid storing and transmitting the plaintext value
	event := repl.ReplicationEvent{}
	event.Version = cpContext.Res.GetVersion()
	event.DomainCode = ri.domainCode
	event.Type = repl.RESOURCE_PATCH
	pr := fmt.Sprintf(`{"Operations":[{"op":"replace", "path": "password", "value":"%s"}]}`, cpContext.Res.GetAttr("password").GetSimpleAt().GetStringVal())
	event.Data = []byte(pr)
	event.PatchRid = cpContext.Rid
	event.RtName = cpContext.Res.GetType().Name
	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the generated changepassword replication event [%#v]", err)
	}
}

func (ri *ReplInterceptor) PostDeleteSession(jti string, ssoSession bool, version string) {
	event := repl.ReplicationEvent{}
	event.Version = version
	event.DomainCode = ri.domainCode
	event.Type = repl.DELETE_SESSION
	event.DeletedSessionId = jti
	event.SsoSession = ssoSession

	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the generated new session replication event [%#v]", err)
	}
}

func (ri *ReplInterceptor) PostAuthDataUpdate(user *base.Resource) {
	event := repl.ReplicationEvent{}
	event.Version = user.GetVersion()
	event.DomainCode = ri.domainCode
	event.Type = repl.REPLACE_AUTHDATA
	var buf bytes.Buffer
	// a new decoder must be created, without which the Skeys field is not properly getting
	// encoded, even tried registering the type map[int]interface{} but didn't work
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(user.AuthData)
	event.Data = buf.Bytes()
	fmt.Println(utils.B64Encode(event.Data))
	event.RtName = user.GetType().Name
	event.Rid = user.GetId()
	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the authdata event [%#v]", err)
	}
}

func (ri *ReplInterceptor) sendToPeers(dataBuf *bytes.Buffer, event repl.ReplicationEvent, peers map[uint16]*repl.ReplicationPeer) {
	for _, v := range peers {
		go v.SendEvent(dataBuf.Bytes(), ri.transport, ri.serverId, ri.webhookToken, event.DomainCode, event.Version, ri.replSilo)
	}
}

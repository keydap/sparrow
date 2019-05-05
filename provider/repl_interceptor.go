package provider

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/repl"
	"sparrow/utils"
	"strconv"
	"time"
)

type ReplInterceptor struct {
	replSilo     *repl.ReplProviderSilo
	domainCode   string
	peers        map[uint16]*base.ReplicationPeer
	transport    *http.Transport
	serverId     uint16
	webhookToken string
}

func (ri *ReplInterceptor) PreCreate(crCtx *base.CreateContext) error {
	return nil
}

func (ri *ReplInterceptor) PostCreate(crCtx *base.CreateContext) {
	event := base.ReplicationEvent{}
	event.Version = crCtx.InRes.GetVersion()
	event.CreatedRes = crCtx.InRes
	event.DomainCode = ri.domainCode
	event.Type = base.RESOURCE_CREATE
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
	event := base.ReplicationEvent{}
	event.Version = patchCtx.Res.GetVersion()
	event.DomainCode = ri.domainCode
	event.Type = base.RESOURCE_PATCH
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
	event := base.ReplicationEvent{}
	event.Version = delCtx.DeleteCsn
	event.Rid = delCtx.Rid
	event.DomainCode = ri.domainCode
	event.Type = base.RESOURCE_DELETE
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
	event := base.ReplicationEvent{}
	event.Version = replaceCtx.Res.GetVersion()
	event.ResToReplace = replaceCtx.InRes
	event.DomainCode = ri.domainCode
	event.Type = base.RESOURCE_REPLACE
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
	event := base.ReplicationEvent{}
	event.Version = version
	event.DomainCode = ri.domainCode
	event.Type = base.NEW_SESSION
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
	event := base.ReplicationEvent{}
	event.Version = version
	event.DomainCode = ri.domainCode
	event.Type = base.REVOKE_SESSION
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
	event := base.ReplicationEvent{}
	event.Version = cpContext.Res.GetVersion()
	event.DomainCode = ri.domainCode
	event.Type = base.RESOURCE_PATCH
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
	event := base.ReplicationEvent{}
	event.Version = version
	event.DomainCode = ri.domainCode
	event.Type = base.DELETE_SESSION
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

func (ri *ReplInterceptor) sendToPeers(dataBuf *bytes.Buffer, event base.ReplicationEvent, peers map[uint16]*base.ReplicationPeer) {
	req := &http.Request{}
	req.Method = http.MethodPost
	req.Header = http.Header{}
	req.Header.Add("Content-Type", "application/octet-stream")
	req.Header.Add(base.HEADER_X_FROM_PEER_ID, strconv.Itoa(int(ri.serverId)))
	req.Header.Add(base.HEADER_X_WEBHOOK_TOKEN, ri.webhookToken)

	for _, v := range peers {
		req.Body = ioutil.NopCloser(dataBuf)
		req.URL = v.Url
		client := &http.Client{Transport: ri.transport, Timeout: 60 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Debugf("%#v", err)
			continue
		}

		if resp.StatusCode == 200 {
			log.Debugf("successfully sent event with version %s to peer %d %s", event.Version, v.ServerId, v.Url)
			v.LastVersion = event.Version
			v.LastReqSentTime = utils.DateTimeMillis()
		}
	}
}

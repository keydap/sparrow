package provider

import (
	"bytes"
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
	event.Version = crCtx.InRes.GetMeta().GetValue("version").(string)
	event.Res = crCtx.InRes
	event.DomainCode = ri.domainCode
	event.Type = base.RESOURCE_CREATE
	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	} else {
		log.Debugf("failed to store the generated replication event [%#v]", err)
	}
}

func (ri *ReplInterceptor) PrePatch(patchCtx *base.PatchContext) error {
	return nil
}

func (ri *ReplInterceptor) PostPatch(patchedRs *base.Resource, patchCtx *base.PatchContext) {
}

func (ri *ReplInterceptor) PreDelete(delCtx *base.DeleteContext) error {
	return nil
}

func (ri *ReplInterceptor) PostDelete(delCtx *base.DeleteContext) {
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

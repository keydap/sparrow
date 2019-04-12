package provider

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/repl"
	"sparrow/utils"
	"time"
)

type ReplInterceptor struct {
	replSilo   *repl.ReplProviderSilo
	domainCode string
	peers      []*base.ReplicationPeer
	transport  *http.Transport
}

func (ri *ReplInterceptor) PreCreate(crCtx *base.CreateContext) error {
	return nil
}

func (ri *ReplInterceptor) PostCreate(crCtx *base.CreateContext) {
	event := base.ReplicationEvent{}
	event.Csn = crCtx.InRes.GetMeta().GetValue("csn").(string)
	event.Res = crCtx.InRes
	event.DomainCode = ri.domainCode
	event.Type = base.RESOURCE_CREATE
	dataBuf, err := ri.replSilo.StoreEvent(event)
	// send to the peers
	if err == nil {
		go ri.sendToPeers(dataBuf, event, ri.peers)
	}
}

func (ri *ReplInterceptor) PrePatch(patchCtx *base.PatchContext) error {
	return nil
}

func (ri *ReplInterceptor) PostPatch(patchedRs *base.Resource, patchCtx *base.PatchContext) {
	panic("implement me")
}

func (ri *ReplInterceptor) PreDelete(delCtx *base.DeleteContext) error {
	return nil
}

func (ri *ReplInterceptor) PostDelete(delCtx *base.DeleteContext) {
	panic("implement me")
}

func (ri *ReplInterceptor) sendToPeers(dataBuf *bytes.Buffer, event base.ReplicationEvent, peers []*base.ReplicationPeer) {
	req := &http.Request{}
	req.Method = http.MethodPost
	req.Header.Add("Content-Type", "application/octet-stream")
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
			log.Debugf("successfully sent event with csn %s to peer %d %s", event.Csn, v.ServerId, v.Url)
			v.LastCsn = event.Csn
			v.LastReqSentTime = utils.DateTimeMillis()
		}
	}
}

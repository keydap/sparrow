package provider

import (
	"sparrow/base"
	"sparrow/repl"
)

type ReplInterceptor struct {
	replSilo   *repl.ReplProviderSilo
	domainCode string
	peers      []*base.ReplicationPeer
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
	ri.replSilo.StoreEvent(event)
	// send to the peers
	go sendToPeers(event, ri.peers)
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

func sendToPeers(event base.ReplicationEvent, peers []*base.ReplicationPeer) {
	for _, v := range peers {
		//v.
	}
}

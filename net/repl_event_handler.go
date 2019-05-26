package net

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/repl"
	"strconv"
	"strings"
)

func handleEvents(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	serverId, _, err := parseServerIdPeer(w, r, sp)
	if err != nil {
		return // error was already handled
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		msg := fmt.Sprintf("failed to read all the data sent from server ID %d [%#v]", serverId, err)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	var event repl.ReplicationEvent
	err = dec.Decode(&event)
	if err != nil {
		msg := fmt.Sprintf("failed to decode the data sent from server ID %d [%#v]", serverId, err)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	pr := sp.dcPrvMap[event.DomainCode]
	// the provider might have been de-activated on this server
	if pr == nil && event.Type != repl.NEW_DOMAIN {
		msg := fmt.Sprintf("provider with domain code %s is not active", event.DomainCode)
		log.Debugf(msg)
		writeError(w, base.NewNotFoundError(msg))
		return
	}

	switch event.Type {
	case repl.RESOURCE_CREATE:
		rs := event.CreatedRes
		rs.SetSchema(pr.RsTypes[rs.TypeName])
		crCtx := &base.CreateContext{Repl: true}
		crCtx.InRes = rs
		err = pr.CreateResource(crCtx)

	case repl.RESOURCE_PATCH:
		rt := pr.RsTypes[event.RtName]
		patchReqJson := string(event.Data)
		patchReq, err := base.ParsePatchReq(strings.NewReader(patchReqJson), rt)
		if err == nil {
			patchCtx := &base.PatchContext{Pr: patchReq, Rid: event.PatchRid, Rt: rt, Repl: true, ReplVersion: event.Version}
			err = pr.Patch(patchCtx)
		}

	case repl.RESOURCE_REPLACE:
		rt := pr.RsTypes[event.RtName]
		rs := event.ResToReplace
		rs.SetSchema(rt)
		replaceCtx := &base.ReplaceContext{InRes: rs, Rt: rt, Repl: true, ReplVersion: event.Version}
		err = pr.Replace(replaceCtx)

	case repl.RESOURCE_DELETE:
		rt := pr.RsTypes[event.RtName]
		delCtx := &base.DeleteContext{Rid: event.Rid, Rt: rt, Repl: true}
		err = pr.DeleteResource(delCtx)

	case repl.NEW_SESSION:
		pr.StoreReplSession(event.NewSession, event.SsoSession)

	case repl.REVOKE_SESSION:
		pr.RevokeReplSession(event.RevokedSessionId, event.SsoSession)

	case repl.DELETE_SESSION:
		// nil context is interpreted as replication context, a special case unlike all other events
		pr.DeleteReplSsoSessionById(event.DeletedSessionId, event.SsoSession, true)

	case repl.NEW_DOMAIN:
		sp.createDomain(event.NewDomainName)

	case repl.DELETE_DOMAIN:
		// TODO add safety checks for a clean removal
		delete(sp.providers, event.DomainCode)
		pr.Close()
		// delete or move the files to a stash dir

	default:
		msg := fmt.Sprintf("unknown event type %d (server ID %d)", event.Type, serverId)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
	}

	if err == nil {
		log.Debugf("saved the replication event of type %d with ID %s", event.Type, event.Version)
	} else {
		log.Debugf("failed to save the replication event with ID %s", event.Version)
	}

}

func parseServerIdPeer(w http.ResponseWriter, r *http.Request, sp *Sparrow) (uint16, *repl.ReplicationPeer, error) {
	serverId, err := strconv.Atoi(r.Header.Get(repl.HEADER_X_FROM_PEER_ID))
	if err != nil {
		msg := "missing server ID header, ignoring the events"
		log.Debugf(msg)
		err = base.NewBadRequestError(msg)
		writeError(w, err)
		return 0, nil, err
	}

	srvIdUint16 := uint16(serverId)
	peer := sp.peers[srvIdUint16]
	if peer == nil {
		msg := fmt.Sprintf("no registered peer exists with the server ID %d, ignoring the events", serverId)
		log.Debugf(msg)
		err = base.NewBadRequestError(msg)
		writeError(w, err)
		return 0, nil, err
	}

	webhookToken := r.Header.Get(repl.HEADER_X_WEBHOOK_TOKEN)
	if peer.WebHookToken != webhookToken {
		msg := fmt.Sprintf("missing or invalid webhook token (request sent from server with ID %d), ignoring the events", serverId)
		log.Debugf(msg)
		err = base.NewUnAuthorizedError(msg)
		writeError(w, err)
		return 0, nil, err
	}

	return srvIdUint16, peer, nil
}

func sendBacklogEvents(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	_, peer, err := parseServerIdPeer(w, r, sp)
	if err != nil {
		return // error was already handled
	}

	for _, pr := range sp.providers {
		lv, ok := peer.LastVersions[pr.DomainCode()]
		if !ok {
			// likely a new domain was created but not replicated, send all the events from the provider
		} else {
			go pr.SendBacklogEvents(lv, peer)
		}
	}
}

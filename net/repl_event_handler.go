package net

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"strconv"
	"strings"
)

func handleEvents(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	serverId, err := strconv.Atoi(r.Header.Get(base.HEADER_X_FROM_PEER_ID))
	if err != nil {
		msg := "missing server ID header, ignoring the events"
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	peer := sp.peers[uint16(serverId)]
	if peer == nil {
		msg := fmt.Sprintf("no registered peer exists with the server ID %d, ignoring the events", serverId)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	webhookToken := r.Header.Get(base.HEADER_X_WEBHOOK_TOKEN)
	if peer.WebHookToken != webhookToken {
		msg := fmt.Sprintf("missing or invalid webhook token (request sent from server with ID %d), ignoring the events", serverId)
		log.Debugf(msg)
		writeError(w, base.NewUnAuthorizedError(msg))
		return
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
	var event base.ReplicationEvent
	err = dec.Decode(&event)
	if err != nil {
		msg := fmt.Sprintf("failed to decode the data sent from server ID %d [%#v]", serverId, err)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	pr := sp.dcPrvMap[event.DomainCode]
	// the provider might have been de-activated on this server
	if pr == nil {
		msg := fmt.Sprintf("provider with domain code %s is not active", event.DomainCode)
		log.Debugf(msg)
		writeError(w, base.NewNotFoundError(msg))
		return
	}

	switch event.Type {
	case base.RESOURCE_CREATE:
		rs := event.Res
		rs.SetSchema(pr.RsTypes[rs.TypeName])
		crCtx := &base.CreateContext{Repl: true}
		crCtx.InRes = rs
		err = pr.CreateResource(crCtx)

	case base.RESOURCE_PATCH:
		rt := pr.RsTypes[event.PatchRtName]
		patchReq, err := base.ParsePatchReq(strings.NewReader(string(event.Data)), rt)
		if err == nil {
			patchCtx := &base.PatchContext{Pr: patchReq, Rid: event.PatchRid, Rt: rt, Repl: true, ResplVersion: event.Version}
			err = pr.Patch(patchCtx)
		}
	default:
		msg := fmt.Sprintf("unknown event type %d (server ID %d)", event.Type, serverId)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
	}

	if err == nil {
		log.Debugf("saved the replication event with ID %s", event.Version)
	} else {
		log.Debugf("failed to save the replication event with ID %s", event.Version)
	}

}

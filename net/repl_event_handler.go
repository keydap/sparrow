package net

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"strconv"
)

func handleEvents(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	serverId, err := strconv.Atoi(r.Header.Get("X-From-Peer-Id"))
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

	webhookToken := r.Header.Get("X-Webhook-Token")
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

	switch event.Type {
	case base.RESOURCE_CREATE:
		pr := sp.dcPrvMap[event.DomainCode]
		// the provider might have been de-activated on this server
		if pr == nil {
			msg := fmt.Sprintf("provider with domain code %s is not active", event.DomainCode)
			log.Debugf(msg)
			writeError(w, base.NewNotFoundError(msg))
			return
		}
		// reuse the buffer
		buf.Reset()
		buf.Write(event.Data)
		var rs *base.Resource
		err = dec.Decode(rs)
		if err == nil {
			// apply the schema
			rs.SetSchema(pr.RsTypes[rs.TypeName])
			crCtx := &base.CreateContext{}
			crCtx.OpContext = &base.OpContext{Repl: true}
			crCtx.InRes = rs
			pr.CreateResource(crCtx)
		} else {
			msg := fmt.Sprintf("failed to decode the resource from the data sent from server ID %d [%#v]", serverId, err)
			log.Debugf(msg)
			writeError(w, base.NewBadRequestError(msg))
			return
		}

	default:
		msg := fmt.Sprintf("unknown event type %d (server ID %d)", event.Type, serverId)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
	}
}

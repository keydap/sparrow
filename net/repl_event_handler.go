package net

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/provider"
	"sparrow/repl"
	"sparrow/schema"
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

	err = processEvent(event, serverId, sp)
	if err != nil {
		writeError(w, err)
	}
}

func processEvent(event repl.ReplicationEvent, serverId uint16, sp *Sparrow) error {
	var err error
	pr := sp.dcPrvMap[event.DomainCode]
	// the provider might have been de-activated on this server
	if pr == nil && event.Type != repl.NEW_DOMAIN {
		msg := fmt.Sprintf("provider with domain code %s is not active", event.DomainCode)
		log.Debugf(msg)
		return base.NewNotFoundError(msg)
	}

	switch event.Type {
	case repl.RESOURCE_CREATE:
		rs := event.CreatedRes
		rt := pr.RsTypes[rs.TypeName]
		rs.SetSchema(rt)
		crCtx := &base.CreateContext{Repl: true}
		crCtx.InRes = rs
		err = pr.CreateResource(crCtx)
		if err != nil && event.Cloning {
			replaceCtx := &base.ReplaceContext{InRes: rs, Rt: rt, Repl: true, Cloning: event.Cloning, ReplVersion: event.Version}
			err = pr.Replace(replaceCtx)
		}

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
		err = base.NewBadRequestError(msg)
	}

	if err == nil {
		log.Debugf("saved the replication event of type %d with ID %s", event.Type, event.Version)
	} else {
		log.Debugf("failed to save the replication event with ID %s", event.Version)
	}

	return nil // no error must be returned from here, either consume the event or discard it
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

	// write to w directly instead of sending async events, the caller's HTTP server won't be available yet
	// during this call
	for _, pr := range sp.providers {
		lv, ok := peer.LastVersions[pr.DomainCode()]
		if !ok {
			// likely a new domain was created but not replicated, send all the events from the provider
		} else {
			pr.WriteBacklogEvents(lv, peer, w)
		}
	}
}

func sendResourceAsEvent(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	_, _, err := parseServerIdPeer(w, r, sp)
	if err != nil {
		return // error was already handled
	}

	domainCode := r.Form.Get("dc")
	pr := sp.dcPrvMap[domainCode]
	if pr == nil {
		msg := fmt.Sprintf("no provider found with the domain code %s", domainCode)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	rtName := r.Form.Get("rt")
	rt := pr.RsTypes[rtName]
	if rt == nil {
		msg := fmt.Sprintf("no resourcetype found with the name %s", rtName)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	rid := r.Form.Get("rid")
	res, err := pr.GetResourceInternal(rid, rt)
	if err != nil {
		writeError(w, err)
		return
	}

	event := repl.ReplicationEvent{}
	event.Version = res.GetVersion()
	event.CreatedRes = res
	event.DomainCode = domainCode
	event.Type = repl.RESOURCE_CREATE
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(event)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Write(buf.Bytes())
}

func sendCloneDataToPeer(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	_, peer, err := parseServerIdPeer(w, r, sp)
	if err != nil {
		return // error was already handled
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		err = fmt.Errorf("writer interface is not a Flusher")
		writeError(w, err)
		return
	}

	if peer.IsBusy() {
		w.WriteHeader(http.StatusTooManyRequests)
		log.Debugf("peer %d is already receiving events, try again later", peer.ServerId)
		return
	}

	peer.BeginRebase()
	defer peer.EndRebase()

	for _, pr := range sp.providers {
		event := repl.ReplicationEvent{}
		event.DomainCode = pr.DomainCode()
		event.Type = repl.RESOURCE_CREATE
		event.Cloning = true

		// users and groups must be sent in sequence
		// so that the data need not be sorted based on the creation time
		// and also the groups' can perfectly link their members
		rt := pr.RsTypes["User"]
		sendCloneData(pr, w, flusher, event, rt)
		rt = pr.RsTypes["Group"]
		sendCloneData(pr, w, flusher, event, rt)

		for _, rt := range pr.RsTypes {
			// do not replicate audit events
			if rt.Name == "AuditEvent" || rt.Name == "User" || rt.Name == "Group" {
				continue
			}
			sendCloneData(pr, w, flusher, event, rt)
		}
	}

	log.Debugf("******* final flush after sending cloned data")
	flusher.Flush()
}

func sendCloneData(pr *provider.Provider, w http.ResponseWriter, flusher http.Flusher, partialEvent repl.ReplicationEvent, rt *schema.ResourceType) {
	outPipe := make(chan *base.Resource)
	go pr.ReadAllInternal(rt, outPipe)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	for res := range outPipe {
		buf.Reset()
		partialEvent.Version = res.GetVersion()
		partialEvent.CreatedRes = res
		err := enc.Encode(&partialEvent)
		if err != nil {
			log.Debugf("sending error >> %#v", err)
			writeError(w, err)
			close(outPipe)
			break
		}

		log.Debugf("sending >> %s", res.GetId())
		data := buf.Bytes()
		i, err := w.Write(data)
		if err != nil {
			log.Debugf("%d, %#v", i, err)
		}
		flusher.Flush()
	}
}

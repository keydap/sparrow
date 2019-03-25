// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/asaskevich/govalidator"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/provider"
	"sparrow/repl"
	"sparrow/utils"
	"strconv"
	"strings"
)

type replHandler struct {
	rl           *repl.ReplSilo
	transport    *http.Transport
	webhookToken string // webook token of this server
}

func HandleReplEvent() {

}

func (rh *replHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uri := r.RequestURI
	if strings.HasSuffix(uri, "/") {
		uri = uri[:len(uri)-1]
	}

	pos := strings.LastIndex(uri, "/")
	action := uri[pos+1:]
	r.ParseForm() //ignore any errors
	switch action {
	case "join":
		rh.addJoinRequest(w, r)

	case "approve":
		rh.approveJoinRequest(w, r)

	case "reject":
		rh.rejectJoinRequest(w, r)

		// internal methods
	case "sendJoinRequest":
		rh.sendJoinRequest(w, r)
	}
	w.Write([]byte("received path " + uri + " action " + action))
}

func (rh *replHandler) approveJoinRequest(w http.ResponseWriter, r *http.Request) {
	opCtx := getOpCtxOfAdminSessionOrAbort(w, r)
	if opCtx == nil {
		return
	}
	serverId, err := parseServerId(w, r)
	if err != nil {
		return // error was already handled so just return
	}

	var joinReq *base.JoinRequest
	requests := rh.rl.GetReceivedJoinRequests()
	for _, v := range requests {
		if serverId == v.ServerId {
			joinReq = &v
			break
		}
	}

	if joinReq == nil {
		msg := fmt.Sprintf("no pending join request exists for the server ID %d", serverId)
		log.Debugf(msg)
		writeError(w, base.NewNotFoundError(msg))
		return
	}

	joinResp := base.JoinResponse{}
	joinResp.ApprovedBy = opCtx.Session.Username
	joinResp.PeerWebHookToken = rh.webhookToken

	approveReq := &http.Request{}
	rp := base.ReplicationPeer{}
	rp.ServerId = joinReq.ServerId
	rp.SentBy = joinReq.SentBy
	rp.Domain = joinReq.Domain
	rp.Url = fmt.Sprintf("https://%s:%d/repl/events", joinReq.Host, joinReq.Port)
	rp.CreatedTime = utils.DateTimeMillis()

}

func (rh *replHandler) rejectJoinRequest(w http.ResponseWriter, r *http.Request) {
	opCtx := getOpCtxOfAdminSessionOrAbort(w, r)
	if opCtx == nil {
		return
	}
	serverId, err := parseServerId(w, r)
	if err != nil {
		return // erro was already handled so just return
	}

	err = rh.rl.DeleteSentJoinRequest(uint16(serverId))
	log.Warningf("%#v", err)
}

func (rh *replHandler) addJoinRequest(w http.ResponseWriter, r *http.Request) {
	conStatus := r.TLS
	if conStatus == nil {
		msg := "invalid transport, replication requests are only allowed over HTTPS"
		log.Warningf(msg)
		w.Write([]byte(msg))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var joinReq base.JoinRequest
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewBadRequestError(err.Error()))
		return
	}
	err = json.Unmarshal(data, &joinReq)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewBadRequestError(err.Error()))
		return
	}

	_, err = govalidator.ValidateStruct(joinReq)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewBadRequestError(err.Error()))
		return
	}

	if joinReq.ServerId != srvConf.ServerId {
		msg := fmt.Sprintf("Mismatched server ID %s", joinReq.ServerId)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	joinReq.CreatedTime = utils.DateTimeMillis()

	err = rh.rl.AddReceivedJoinReq(joinReq)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewInternalserverError(err.Error()))
		return
	}
}

func (rh *replHandler) sendJoinRequest(w http.ResponseWriter, r *http.Request) {
	opCtx := getOpCtxOfAdminSessionOrAbort(w, r)
	if opCtx == nil {
		return
	}

	serverId := r.Form.Get("serverId")
	host := r.Form.Get("host")
	port := r.Form.Get("port")
	joinReq := base.JoinRequest{}
	id, err := strconv.Atoi(serverId)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewInternalserverError(err.Error()))
		return
	}

	joinReq.ServerId = uint16(id)
	joinReq.Host = host
	joinReq.Port, _ = strconv.Atoi(port)
	joinReq.Domain = opCtx.Session.Domain
	joinReq.WebHookToken = utils.NewRandShaStr()
	joinReq.CreatedTime = utils.DateTimeMillis()
	joinReq.SentBy = opCtx.Session.Username

	var buf *bytes.Buffer
	enc := json.NewEncoder(buf)
	enc.Encode(joinReq)
	httpReq := &http.Request{}
	httpReq.Body = ioutil.NopCloser(buf)
	httpReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{Transport: rh.transport}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewPeerConnectionFailed(err.Error()))
		return
	}

	if resp.StatusCode != 200 {
		err = base.NewFromHttpResp(resp)
		log.Debugf("%#v", err)
		writeError(w, err)
		return
	}

	rh.rl.AddSentJoinReq(joinReq)
}

func getOpCtxOfAdminSessionOrAbort(w http.ResponseWriter, r *http.Request) *base.OpContext {
	opCtx, err := createOpCtx(r)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, err) //this will be a SCIM error so no need to create again
		return nil
	}

	if _, ok := opCtx.Session.Roles[provider.SystemGroupId]; !ok {
		err := base.NewForbiddenError("Insufficient access privileges, only users belonging to System group can configure replication")
		log.Debugf("%#v", err)
		writeError(w, err)
		return nil
	}

	if opCtx.Session.Domain != srvConf.ControllerDomain {
		err := base.NewForbiddenError("Insufficient access privileges, only users of the control domain are allowed to configure replication")
		log.Debugf("%#v", err)
		writeError(w, err)
		return nil
	}

	return opCtx
}

func parseServerId(w http.ResponseWriter, r *http.Request) (uint16, error) {
	serverIdParam := r.Form.Get("serverId")
	serverId, err := strconv.Atoi(serverIdParam)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewBadRequestError(err.Error()))
		return 0, err
	}

	if serverId < 0 || serverId > 65535 {
		msg := fmt.Sprintf("invalid server ID %d", serverId)
		err = base.NewBadRequestError(msg)
		writeError(w, err)
		return 0, err
	}

	return uint16(serverId), nil
}

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
	"net/url"
	"sparrow/base"
	"sparrow/provider"
	"sparrow/utils"
	"strconv"
	"strings"
)

func HandleReplEvent() {

}

func (sp *Sparrow) replHandler(w http.ResponseWriter, r *http.Request) {
	conStatus := r.TLS
	if conStatus == nil {
		msg := "invalid transport, replication requests are only allowed over HTTPS"
		log.Warningf(msg)
		w.Write([]byte(msg))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	uri := r.RequestURI
	log.Debugf(">>>>>>>>>>>>>>>>>>> received replication request %s", uri)
	if strings.HasSuffix(uri, "/") {
		uri = uri[:len(uri)-1]
	}

	pos := strings.LastIndex(uri, "/")
	action := uri[pos+1:]
	r.ParseForm() //ignore any errors
	switch action {
	case "join":
		addJoinRequest(w, r, sp)

	case "approve":
		receivedApproval(w, r, sp)

	case "leave":
		//deletePeer(sp, w, r)

		// internal methods
	case "sendJoinReq":
		sendJoinRequest(w, r, sp)

	case "approveJoinReq":
		sendApprovalForJoinRequest(w, r, sp)

	case "rejectJoinReq":
		rejectJoinRequest(w, r, sp)

	case "sendLeaveReq":
		//sendLeaveReq(w, r, sp)

	case "events":
		handleEvents(w, r, sp)

	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("received path " + uri + " action " + action))
	}
}

func receivedApproval(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	var joinResp base.JoinResponse
	err := parseJsonBody(w, r, &joinResp)
	if err != nil {
		return // error was already handled
	}

	sentReq := sp.rl.GetSentJoinRequest(joinResp.PeerServerId)
	if sentReq == nil {
		msg := fmt.Sprintf("no join request was sent to server with ID %d", joinResp.PeerServerId)
		log.Debugf(msg)
		writeError(w, base.NewNotFoundError(msg))
		return
	}

	_storePeer(sentReq, w, sp)
}

func sendApprovalForJoinRequest(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	opCtx := getOpCtxOfAdminSessionOrAbort(w, r, sp)
	if opCtx == nil {
		return
	}
	serverId, err := parseServerId(w, r)
	if err != nil {
		return // error was already handled so just return
	}

	joinReq := sp.rl.GetReceivedJoinRequest(serverId)

	if joinReq == nil {
		msg := fmt.Sprintf("no pending join request exists for the server ID %d", serverId)
		log.Debugf(msg)
		writeError(w, base.NewNotFoundError(msg))
		return
	}

	joinResp := base.JoinResponse{}
	joinResp.ApprovedBy = opCtx.Session.Username
	joinResp.PeerWebHookToken = sp.rl.WebHookToken
	joinResp.PeerView = make([]base.ReplicationPeer, 0)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.Encode(joinResp)

	baseUrl := fmt.Sprintf("https://%s:%d/repl", joinReq.Host, joinReq.Port)

	approveReq, _ := http.NewRequest(http.MethodPost, baseUrl+"/approve", ioutil.NopCloser(&buf))
	approveReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{Transport: sp.srvConf.ReplTransport}
	resp, err := client.Do(approveReq)
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

	_storePeer(joinReq, w, sp)
	log.Debugf("approved the server at %s to join the replication club", baseUrl)
}

func _storePeer(joinReq *base.JoinRequest, w http.ResponseWriter, sp *Sparrow) error {
	baseUrl := fmt.Sprintf("https://%s:%d/repl", joinReq.Host, joinReq.Port)
	log.Debugf("storing replication peer %s", baseUrl)
	rp := &base.ReplicationPeer{}
	rp.ServerId = joinReq.ServerId
	rp.SentBy = joinReq.SentBy
	rp.Domain = joinReq.Domain
	rp.Url, _ = url.Parse(baseUrl + "/events")
	rp.CreatedTime = utils.DateTimeMillis()
	err := sp.rl.AddReplicationPeer(rp)
	if err != nil {
		log.Warningf("%#v", err)
		writeError(w, base.NewInternalserverError(err.Error()))
		return err
	}

	sp.peers[rp.ServerId] = rp

	return nil
}

func rejectJoinRequest(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	opCtx := getOpCtxOfAdminSessionOrAbort(w, r, sp)
	if opCtx == nil {
		return
	}
	serverId, err := parseServerId(w, r)
	if err != nil {
		return // erro was already handled so just return
	}

	err = sp.rl.DeleteReceivedJoinRequest(uint16(serverId))
	log.Warningf("%#v", err)
	// TODO send rejected response, but not sure if this is necessary
	log.Debugf("rejected replication join request from server with ID %d", serverId)
}

func addJoinRequest(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	var joinReq base.JoinRequest

	err := parseJsonBody(w, r, &joinReq)
	if err != nil {
		return // error was already handled
	}

	if joinReq.ServerId == sp.srvConf.ServerId {
		msg := fmt.Sprintf("cannot join self, received server ID %d", joinReq.ServerId)
		log.Debugf(msg)
		writeError(w, base.NewBadRequestError(msg))
		return
	}

	joinReq.CreatedTime = utils.DateTimeMillis()

	err = sp.rl.AddReceivedJoinReq(joinReq)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewInternalserverError(err.Error()))
		return
	}

	log.Debugf("received a join request from the server %s:%d with ID %d by %s", joinReq.Host, joinReq.Port, joinReq.ServerId, joinReq.SentBy)
}

func sendJoinRequest(w http.ResponseWriter, r *http.Request, sp *Sparrow) {
	opCtx := getOpCtxOfAdminSessionOrAbort(w, r, sp)
	if opCtx == nil {
		return
	}

	host := strings.TrimSpace(r.Form.Get("host"))
	portVal := r.Form.Get("port")
	joinReq := base.JoinRequest{}
	port, err := strconv.Atoi(portVal)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewBadRequestError("invalid port number"))
		return
	}

	joinReq.ServerId = sp.srvConf.ServerId
	joinReq.Host = sp.srvConf.IpAddress
	joinReq.Port = sp.srvConf.HttpPort
	joinReq.Domain = opCtx.Session.Domain
	joinReq.WebHookToken = utils.NewRandShaStr()
	joinReq.CreatedTime = utils.DateTimeMillis()
	joinReq.SentBy = opCtx.Session.Username

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.Encode(joinReq)
	location := fmt.Sprintf("https://%s:%d/repl/join", host, port)
	httpReq, _ := http.NewRequest(http.MethodPost, location, ioutil.NopCloser(&buf))
	httpReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{Transport: sp.srvConf.ReplTransport}
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

	sp.rl.AddSentJoinReq(joinReq)
	log.Debugf("sent a join request from %s:%d to the server at %s:%d", sp.srvConf.IpAddress, sp.srvConf.HttpPort, host, port)
}

func getOpCtxOfAdminSessionOrAbort(w http.ResponseWriter, r *http.Request, sp *Sparrow) *base.OpContext {
	opCtx, err := createOpCtx(r, sp)
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

	if opCtx.Session.Domain != sp.srvConf.ControllerDomain {
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

func parseJsonBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewBadRequestError(err.Error()))
		return err
	}
	err = json.Unmarshal(data, v)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewBadRequestError(err.Error()))
		return err
	}

	_, err = govalidator.ValidateStruct(v)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewBadRequestError(err.Error()))
		return err
	}

	return nil
}

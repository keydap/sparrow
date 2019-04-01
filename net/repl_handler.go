// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/asaskevich/govalidator"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"sparrow/base"
	"sparrow/provider"
	"sparrow/repl"
	"sparrow/utils"
	"strconv"
	"strings"
)

type replHandler struct {
	rl        *repl.ReplSilo
	transport *http.Transport
	peers     map[uint16]*base.ReplicationPeer
}

func registerReplHandler(router *mux.Router) {
	var err error
	replHandler := &replHandler{}
	replHandler.rl, err = repl.OpenReplSilo(path.Join(replDir, "repl-data.db"))
	if err != nil {
		panic(err)
	}

	skipCertCheck := false
	if srvConf.SkipPeerCertCheck {
		skipCertCheck = true
	} else {
		// configure the trust store
	}
	tlsConf := &tls.Config{InsecureSkipVerify: skipCertCheck}
	replHandler.transport = &http.Transport{TLSClientConfig: tlsConf}

	// load the existing peers
	replHandler.peers = replHandler.rl.GetReplicationPeers()
	// replication requests
	router.PathPrefix("/repl/").Handler(replHandler)
}

func HandleReplEvent() {

}

func (rh *replHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conStatus := r.TLS
	if conStatus == nil {
		msg := "invalid transport, replication requests are only allowed over HTTPS"
		log.Warningf(msg)
		w.Write([]byte(msg))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

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
		rh.receivedApproval(w, r)

	case "leave":
		//rh.deletePeer(w, r)

		// internal methods
	case "sendJoinReq":
		rh.sendJoinRequest(w, r)

	case "approveJoinReq":
		rh.sendApprovalForJoinRequest(w, r)

	case "rejectJoinReq":
		rh.rejectJoinRequest(w, r)

	case "sendLeaveReq":
	//rh.sendLeaveReq(w, r)

	default:
		w.Write([]byte("received path " + uri + " action " + action))
	}
}

func (rh *replHandler) receivedApproval(w http.ResponseWriter, r *http.Request) {
	var joinResp base.JoinResponse
	err := parseJsonBody(w, r, &joinResp)
	if err != nil {
		return // error was already handled
	}

	sentReq := rh.rl.GetSentJoinRequest(joinResp.PeerServerId)
	if sentReq == nil {
		msg := fmt.Sprintf("no join request was sent to server with ID %d", joinResp.PeerServerId)
		log.Debugf(msg)
		writeError(w, base.NewNotFoundError(msg))
		return
	}

	rh._storePeer(sentReq, w)
}

func (rh *replHandler) sendApprovalForJoinRequest(w http.ResponseWriter, r *http.Request) {
	opCtx := getOpCtxOfAdminSessionOrAbort(w, r)
	if opCtx == nil {
		return
	}
	serverId, err := parseServerId(w, r)
	if err != nil {
		return // error was already handled so just return
	}

	joinReq := rh.rl.GetReceivedJoinRequest(serverId)

	if joinReq == nil {
		msg := fmt.Sprintf("no pending join request exists for the server ID %d", serverId)
		log.Debugf(msg)
		writeError(w, base.NewNotFoundError(msg))
		return
	}

	joinResp := base.JoinResponse{}
	joinResp.ApprovedBy = opCtx.Session.Username
	joinResp.PeerWebHookToken = rh.rl.WebHookToken
	joinResp.PeerView = make([]base.ReplicationPeer, 0)

	var buf *bytes.Buffer
	enc := json.NewEncoder(buf)
	enc.Encode(joinResp)

	baseUrl := fmt.Sprintf("https://%s:%d/repl", joinReq.Host, joinReq.Port)

	approveReq := &http.Request{}
	approveReq.Method = http.MethodPost
	approveReq.URL, _ = url.Parse(baseUrl + "/approve")
	approveReq.Body = ioutil.NopCloser(buf)
	approveReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{Transport: rh.transport}
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

	rh._storePeer(joinReq, w)
}

func (rh *replHandler) _storePeer(joinReq *base.JoinRequest, w http.ResponseWriter) error {
	baseUrl := fmt.Sprintf("https://%s:%d/repl", joinReq.Host, joinReq.Port)
	log.Debugf("storing replication peer %s", baseUrl)
	rp := &base.ReplicationPeer{}
	rp.ServerId = joinReq.ServerId
	rp.SentBy = joinReq.SentBy
	rp.Domain = joinReq.Domain
	rp.Url, _ = url.Parse(baseUrl + "/events")
	rp.CreatedTime = utils.DateTimeMillis()
	err := rh.rl.AddReplicationPeer(rp)
	if err != nil {
		log.Warningf("%#v", err)
		writeError(w, base.NewInternalserverError(err.Error()))
		return err
	}

	rh.peers[rp.ServerId] = rp

	return nil
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

	err = rh.rl.DeleteReceivedJoinRequest(uint16(serverId))
	log.Warningf("%#v", err)
	// TODO send rejected response, but not sure if this is necessary
}

func (rh *replHandler) addJoinRequest(w http.ResponseWriter, r *http.Request) {
	var joinReq base.JoinRequest

	err := parseJsonBody(w, r, &joinReq)
	if err != nil {
		return // error was already handled
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

	host := strings.TrimSpace(r.Form.Get("host"))
	portVal := r.Form.Get("port")
	joinReq := base.JoinRequest{}
	port, err := strconv.Atoi(portVal)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, base.NewBadRequestError("invalid port number"))
		return
	}

	joinReq.ServerId = srvConf.ServerId
	joinReq.Host = srvConf.IpAddress
	joinReq.Port = srvConf.HttpPort
	joinReq.Domain = opCtx.Session.Domain
	joinReq.WebHookToken = utils.NewRandShaStr()
	joinReq.CreatedTime = utils.DateTimeMillis()
	joinReq.SentBy = opCtx.Session.Username

	var buf *bytes.Buffer
	enc := json.NewEncoder(buf)
	enc.Encode(joinReq)
	httpReq := &http.Request{}
	httpReq.URL, _ = url.Parse(fmt.Sprintf("https://%s:%d/repl/join", host, port))
	httpReq.Method = http.MethodPost
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

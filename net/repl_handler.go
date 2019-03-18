// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"encoding/json"
	"github.com/asaskevich/govalidator"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"strings"
)

type replHandler struct {
}

func HandleReplEvent() {

}

func (rh replHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uri := r.RequestURI
	if strings.HasSuffix(uri, "/") {
		uri = uri[:len(uri)-1]
	}

	pos := strings.LastIndex(uri, "/")
	action := uri[pos+1:]
	r.ParseForm() //ignore any errors
	switch action {
	case "join":
		handleJoinRequest(w, r)

	}
	w.Write([]byte("received path " + uri + " action " + action))
}

func handleJoinRequest(w http.ResponseWriter, r *http.Request) {
	conStatus := r.TLS
	if conStatus == nil {
		msg := "invalid transport, replication requests are only allowed over HTTPS"
		log.Warningf(msg)
		w.Write([]byte(msg))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var joinEvent base.JoinEvent
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, err)
		return
	}
	err = json.Unmarshal(data, &joinEvent)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, err)
		return
	}

	_, err = govalidator.ValidateStruct(joinEvent)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, err)
		return
	}

	pendingReq := base.PendingJoinRequest{}
	pendingReq.Host = joinEvent.Host
	pendingReq.Port = joinEvent.Port
	pendingReq.ServerId = joinEvent.ServerId
	pendingReq.CertChain = conStatus.PeerCertificates
}

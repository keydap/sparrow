// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"net/http"
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
	//conStatus := r.TLS
	//conStatus.PeerCertificates
}

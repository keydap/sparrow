// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sparrow/base"
	"strconv"
)

const scimContentType = "application/scim+json; charset=UTF-8"
const authzHeader = "Authorization"

type SparrowClient struct {
	transport *http.Transport
	baseUrl   string
	token     string
}

type authRequest struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

type Result struct {
	StatusCode int
	ErrorMsg   string
	Data       []byte
}

func NewSparrowClient(baseUrl string) *SparrowClient {
	client := &SparrowClient{}
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	client.transport = &http.Transport{TLSClientConfig: tlsConf}
	client.baseUrl = baseUrl

	return client
}

func (scl *SparrowClient) Add(rs *base.Resource) Result {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.Encode(rs)

	req := &http.Request{Method: http.MethodPost}
	usersUrl, _ := url.Parse(scl.baseUrl + rs.GetType().Endpoint)
	req.URL = usersUrl
	scl.addRequiredHeaders(req)
	req.Body = ioutil.NopCloser(&buf)

	return scl.sendReq(req)
}

func (scl *SparrowClient) SendJoinReq(host string, port int) Result {
	req := &http.Request{Method: http.MethodPost}
	joinUrl, _ := url.Parse(scl.baseUrl + "/repl/sendJoinReq")
	req.URL = joinUrl
	req.Form.Add("host", host)
	req.Form.Add("port", strconv.Itoa(port))
	scl.addRequiredHeaders(req)

	return scl.sendReq(req)
}

func (scl *SparrowClient) ApproveJoinReq(serverId uint16) Result {
	req := &http.Request{Method: http.MethodPost}
	joinUrl, _ := url.Parse(scl.baseUrl + "/repl/approveJoinReq")
	req.URL = joinUrl
	req.Form.Add("serverId", strconv.Itoa(int(serverId)))
	scl.addRequiredHeaders(req)

	return scl.sendReq(req)
}

func (scl *SparrowClient) DirectLogin(username string, password string, domain string) error {
	// authenticate first
	ar := authRequest{}
	ar.Username = username
	ar.Password = password
	ar.Domain = domain

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.Encode(&ar)

	req := &http.Request{Method: http.MethodPost}
	loginUrl, _ := url.Parse(scl.baseUrl + "/directLogin")
	req.URL = loginUrl
	req.Header = make(map[string][]string)
	req.Header.Add("Content-Type", "application/json")
	req.Body = ioutil.NopCloser(&buf)

	result := scl.sendReq(req)

	if result.StatusCode != 200 {
		return fmt.Errorf("%d - %s", result.StatusCode, result.ErrorMsg)
	}

	scl.token = string(result.Data)
	return nil
}

func (scl *SparrowClient) sendReq(req *http.Request) Result {
	client := &http.Client{Transport: scl.transport}
	r := Result{}
	resp, err := client.Do(req)
	if err != nil {
		r.ErrorMsg = err.Error()
		r.StatusCode = 500
	} else {
		r.Data, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			r.ErrorMsg = err.Error()
			r.Data = nil
		}
		r.StatusCode = resp.StatusCode
		resp.Body.Close()
	}

	return r
}

func (scl *SparrowClient) addRequiredHeaders(r *http.Request) {
	r.Header = make(map[string][]string)
	r.Header.Add("Content-Type", scimContentType)
	r.Header.Add(authzHeader, "Bearer "+scl.token)
}

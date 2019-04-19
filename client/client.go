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
	"strings"
)

const scimContentType = "application/scim+json; charset=UTF-8"
const formUrlEncodedContentType = "application/x-www-form-urlencoded"
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

	req, _ := http.NewRequest(http.MethodPost, scl.baseUrl+"/v2"+rs.GetType().Endpoint, ioutil.NopCloser(&buf))
	scl.addRequiredHeaders(req)

	return scl.sendReq(req)
}

func (scl *SparrowClient) SendJoinReq(host string, port int) Result {
	form := url.Values{}
	form.Add("host", host)
	form.Add("port", strconv.Itoa(port))
	req, _ := http.NewRequest(http.MethodPost, scl.baseUrl+"/repl/sendJoinReq", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", formUrlEncodedContentType)
	req.Header.Add(authzHeader, "Bearer "+scl.token)

	return scl.sendReq(req)
}

func (scl *SparrowClient) ApproveJoinReq(serverId uint16) Result {
	form := url.Values{}
	form.Add("serverId", strconv.Itoa(int(serverId)))
	req, _ := http.NewRequest(http.MethodPost, scl.baseUrl+"/repl/approveJoinReq", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", formUrlEncodedContentType)
	req.Header.Add(authzHeader, "Bearer "+scl.token)

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

	req, _ := http.NewRequest(http.MethodPost, scl.baseUrl+"/v2/directLogin", ioutil.NopCloser(&buf))
	req.Header.Add("Content-Type", "application/json")

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
	if r.Header == nil {
		r.Header = make(map[string][]string)
	}
	r.Header.Add("Content-Type", scimContentType)
	r.Header.Add(authzHeader, "Bearer "+scl.token)
}

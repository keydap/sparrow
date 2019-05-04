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
	"sparrow/schema"
	"strconv"
	"strings"
)

const scimContentType = "application/scim+json; charset=UTF-8"
const formUrlEncodedContentType = "application/x-www-form-urlencoded"
const authzHeader = "Authorization"

type SparrowClient struct {
	transport   *http.Transport
	baseUrl     string
	token       string
	schemaAware bool
	Schemas     map[string]*schema.Schema
	ResTypes    map[string]*schema.ResourceType
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
	Rs         *base.Resource
}

func NewSparrowClient(baseUrl string) *SparrowClient {
	client := &SparrowClient{}
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	client.transport = &http.Transport{TLSClientConfig: tlsConf}
	client.baseUrl = baseUrl

	return client
}

func (scl *SparrowClient) AddUser(userJson string) Result {
	return scl._addResource([]byte(userJson), scl.ResTypes["User"])
}

func (scl *SparrowClient) GetUser(id string) Result {
	return scl.GetResource(id, scl.ResTypes["User"])
}

func (scl *SparrowClient) AddGroup(groupJson string) Result {
	return scl._addResource([]byte(groupJson), scl.ResTypes["Group"])
}

func (scl *SparrowClient) GetGroup(id string) Result {
	return scl.GetResource(id, scl.ResTypes["Group"])
}

func (scl *SparrowClient) Delete(rid string, rt *schema.ResourceType) Result {
	req, _ := http.NewRequest(http.MethodDelete, scl.baseUrl+"/v2"+rt.Endpoint+"/"+rid, nil)
	scl.addRequiredHeaders(req)

	result := scl.sendReq(req)
	return result
}

func (scl *SparrowClient) Replace(rid string, replaceJson string, rt *schema.ResourceType, rsVersion string) Result {
	req, _ := http.NewRequest(http.MethodPut, scl.baseUrl+"/v2"+rt.Endpoint+"/"+rid, strings.NewReader(replaceJson))
	scl.addRequiredHeaders(req)
	req.Header.Add("If-Match", rsVersion)

	result := scl.sendReq(req)
	if result.StatusCode == http.StatusOK {
		result.Rs, _ = scl.ParseResource(result.Data)
	}
	return result
}

func (scl *SparrowClient) Patch(patchReq string, rid string, rt *schema.ResourceType, rsVersion string, returnAttrs string) Result {
	location := scl.baseUrl + "/v2" + rt.Endpoint + "/" + rid
	returnAttrs = strings.TrimSpace(returnAttrs)
	if len(returnAttrs) > 0 {
		location = location + "?attributes=" + returnAttrs
	}
	req, _ := http.NewRequest(http.MethodPatch, location, strings.NewReader(patchReq))
	scl.addRequiredHeaders(req)
	req.Header.Add("If-Match", rsVersion)
	result := scl.sendReq(req)
	if result.StatusCode == http.StatusOK {
		result.Rs, _ = scl.ParseResource(result.Data)
	}

	return result
}

func (scl *SparrowClient) GetResource(id string, rt *schema.ResourceType) Result {
	req, _ := http.NewRequest(http.MethodGet, scl.baseUrl+"/v2"+rt.Endpoint+"/"+id, nil)
	scl.addRequiredHeaders(req)

	result := scl.sendReq(req)
	if result.StatusCode == http.StatusOK {
		result.Rs, _ = scl.ParseResource(result.Data)
	}

	return result
}

func (scl *SparrowClient) Add(rs *base.Resource) Result {
	data := rs.Serialize()
	return scl._addResource(data, rs.GetType())
}

func (scl *SparrowClient) _addResource(data []byte, rt *schema.ResourceType) Result {
	req, _ := http.NewRequest(http.MethodPost, scl.baseUrl+"/v2"+rt.Endpoint, ioutil.NopCloser(bytes.NewBuffer(data)))
	scl.addRequiredHeaders(req)

	result := scl.sendReq(req)
	if result.StatusCode == http.StatusCreated {
		result.Rs, _ = scl.ParseResource(result.Data)
	}

	return result
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

func (scl *SparrowClient) MakeSchemaAware() error {
	err := scl.loadSchemas()
	if err == nil {
		err = scl.loadResTypes()
	}

	scl.schemaAware = (err == nil)
	return err
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

func (scl *SparrowClient) loadSchemas() error {
	req, _ := http.NewRequest(http.MethodGet, scl.baseUrl+"/v2/Schemas", nil)
	req.Header.Add(authzHeader, "Bearer "+scl.token)

	result := scl.sendReq(req)

	if result.StatusCode != 200 {
		return fmt.Errorf("%d - %s", result.StatusCode, result.ErrorMsg)
	}

	var arr []interface{}
	err := json.Unmarshal(result.Data, &arr)
	if err != nil {
		return err
	}

	sm := make(map[string]*schema.Schema)

	for _, v := range arr {
		singleSchemaData, err := json.Marshal(v)
		if err != nil {
			return err
		}

		sc, err := schema.NewSchema(singleSchemaData)
		if err != nil {
			return err
		}
		sm[sc.Id] = sc
	}

	scl.Schemas = sm
	return nil
}

func (scl *SparrowClient) loadResTypes() error {
	req, _ := http.NewRequest(http.MethodGet, scl.baseUrl+"/v2/ResourceTypes", nil)
	req.Header.Add(authzHeader, "Bearer "+scl.token)

	result := scl.sendReq(req)

	if result.StatusCode != 200 {
		return fmt.Errorf("%d - %s", result.StatusCode, result.ErrorMsg)
	}

	var arr []interface{}
	err := json.Unmarshal(result.Data, &arr)
	if err != nil {
		return err
	}

	rts := make(map[string]*schema.ResourceType)

	for _, v := range arr {
		singleRtData, err := json.Marshal(v)
		if err != nil {
			return err
		}

		rt, err := schema.NewResourceType(singleRtData, scl.Schemas)
		if err != nil {
			return err
		}
		rts[rt.Name] = rt
	}

	scl.ResTypes = rts
	return nil
}

func (scl *SparrowClient) ParseResource(data []byte) (*base.Resource, error) {
	if !scl.schemaAware {
		return nil, fmt.Errorf("client is not aware of schema")
	}

	return base.ParseResource(scl.ResTypes, scl.Schemas, ioutil.NopCloser(bytes.NewBuffer(data)))
}

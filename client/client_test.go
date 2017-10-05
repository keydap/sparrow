// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sparrow/base"
	"strings"
	"testing"
	"time"
)

const baseUrl = "http://localhost:7090/v2"
const scimContentType = "application/scim+json; charset=UTF-8"

type authRequest struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

func TestCreateResourcesPerf(t *testing.T) {
	if true {
		fmt.Println("Not running insert perf test")
		return
	}

	token, err := login()
	if err != nil {
		t.Logf("%s", err)
		t.FailNow()
	}

	t.Log(token)

	bufReader, err := os.Open("/Users/dbugger/ldif-templates/100k-users.json")
	if err != nil {
		t.Error(err)
		return
	}

	lineReader := bufio.NewReader(bufReader)
	count := 0

	reqUrl, _ := url.Parse(baseUrl + "/Users")
	client := &http.Client{}
	req := &http.Request{Method: "POST", URL: reqUrl}
	req.Header = make(map[string][]string)
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", scimContentType)

	start := time.Now()

	for {
		l, err := lineReader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			panic(err)
		}

		record := string(l)
		strings.TrimSpace(record)
		if len(l) == 0 {
			continue
		}

		req.Body = ioutil.NopCloser(strings.NewReader(record))
		resp, se := client.Do(req)
		if se != nil {
			fmt.Printf("Error while creating resource %#v\n", se)
			break
		}

		msg, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusCreated {
			count++
		} else {
			panic(fmt.Errorf("Unable to insert %d resource status is %s\n %s\n\n%s", count+1, resp.Status, msg, l))
		}

		if (count > 0) && ((count % 5000) == 0) {
			durSec := time.Now().Sub(start).Seconds()
			fmt.Printf("Time took to insert %d entries %fsec\n", count, durSec)
		}

		break
	}

	fmt.Printf("Created %d resources in %fsec\n", count, time.Now().Sub(start).Seconds())
}

func TestSearchResourcesPerf(t *testing.T) {
	if false {
		fmt.Println("Not running search perf test")
		return
	}

	scimReq := base.NewSearchRequest("username pr", "password", false)
	data, err := json.Marshal(scimReq)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	token, err := login()
	if err != nil {
		t.Logf("%s", err)
		t.FailNow()
	}

	reqUrl, _ := url.Parse(baseUrl + "/Users/.search")
	client := &http.Client{}
	req := &http.Request{Method: "POST", URL: reqUrl}
	req.Header = make(map[string][]string)
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", scimContentType)
	req.Body = ioutil.NopCloser(strings.NewReader(string(data)))

	start := time.Now()

	resp, se := client.Do(req)
	if se != nil {
		fmt.Printf("Error while searching User resource %#v\n", se)
		return
	}

	var lr base.ListResponse
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&lr)

	resp.Body.Close()

	fmt.Println(resp.Status)

	if resp.StatusCode == http.StatusOK {
		durSec := time.Now().Sub(start).Seconds()
		fmt.Printf("%d resources fetched in %fsec\n", lr.TotalResults, durSec)
	}
}

func login() (token string, err error) {
	// authenticate first
	ar := authRequest{}
	ar.Username = "admin"
	ar.Password = "secret"
	ar.Domain = "example.com"

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.Encode(&ar)

	fmt.Println(string(buf.Bytes()))
	resp, err := http.Post(baseUrl+"/directLogin", "application/json", &buf)
	if err != nil {
		return "", err
	}

	tokenBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(tokenBytes), nil
}

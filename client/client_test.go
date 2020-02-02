// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package client

import (
	"bufio"
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

const baseUrl string = "https://localhost:7090"

var scl *SparrowClient

func TestMain(m *testing.M) {
	scl = NewSparrowClient(baseUrl)
	err := scl.DirectLogin("admin", "secret", "example.com")
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	// now run the tests
	m.Run()
}

func TestCreateResourcesPerf(t *testing.T) {
	//if true {
	//	fmt.Println("Not running insert perf test")
	//	return
	//}

	bufReader, err := os.Open("/Users/dbugger/ldif-templates/100k-users.json")
	if err != nil {
		t.Error(err)
		return
	}

	lineReader := bufio.NewReader(bufReader)
	count := 0


	reqUrl := baseUrl + "/v2/Users"
	req, _ := http.NewRequest(http.MethodPost, reqUrl, nil)
	req.Header.Add("Authorization", "Bearer "+scl.token)
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
		result := scl.sendReq(req)
		if result.StatusCode == http.StatusCreated {
			count++
		} else {
			panic(fmt.Errorf("Unable to insert %d resource StatusCode is %d\n %s\n\n%s", count+1, result.StatusCode, result.ErrorMsg, l))
		}

		if (count > 0) && ((count % 10000) == 0) {
			durSec := time.Now().Sub(start).Seconds()
			fmt.Printf("Time took to insert %d resources %fsec\n", count, durSec)
			//break
		}
	}

	totalSec := time.Now().Sub(start).Seconds()
	fmt.Printf("Created %d resources in %fsec at the rate of %f resources per sec\n", count, totalSec, (float64(count) / totalSec))
}

func BenchmarkTestSearchResourcesPerf(t *testing.B) {
	if true {
		fmt.Println("Not running search perf test")
		return
	}

	scimReq := base.NewSearchRequest("username pr", "id", true)
	data, err := json.Marshal(scimReq)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	reqUrl, _ := url.Parse(baseUrl + "/Users/.search")

	//start := time.Now()
	//fmt.Println(t.N)
	for i := 0; i < t.N; i++ {
		req := &http.Request{Method: "POST", URL: reqUrl}
		req.Header = make(map[string][]string)
		req.Header.Add("Authorization", "Bearer "+scl.token)
		req.Header.Add("Content-Type", scimContentType)
		req.Body = ioutil.NopCloser(strings.NewReader(string(data)))

		result := scl.sendReq(req)

		if result.StatusCode == http.StatusOK {
			//durSec := time.Now().Sub(start).Seconds()
			//fmt.Printf("%d resources fetched in %fsec\n", lr.TotalResults, durSec)
		} else {
			fmt.Println(result.StatusCode)
			fmt.Printf("%s", result.ErrorMsg)
		}
	}

	//dur := time.Now().Sub(start).String()
	//fmt.Printf("total number of seconds for %d search iterations %s\n", t.N, dur)
}

func BenchmarkTestSearchAllOfSingleResourceType(t *testing.B) {
	if true {
		fmt.Println("Not running BenchmarkTestSearchAllOfSingleResourceType")
		return
	}

	reqUrl, _ := url.Parse(baseUrl + "/Users")

	start := time.Now()
	//fmt.Println(t.N)
	for i := 0; i < t.N; i++ {
		req := &http.Request{Method: "GET", URL: reqUrl}
		req.Header = make(map[string][]string)

		result := scl.sendReq(req)

		if result.StatusCode == http.StatusOK {
			//durSec := time.Now().Sub(start).Seconds()
			//fmt.Printf("%d resources fetched in %fsec\n", lr.TotalResults, durSec)
		} else {
			fmt.Println(result.StatusCode)
			fmt.Printf("%s", result.ErrorMsg)
		}
	}

	dur := time.Now().Sub(start).String()
	fmt.Printf("total number of seconds for %d search iterations %s\n", t.N, dur)
}

func BenchmarkTestSingleUser(t *testing.B) {
	if true {
		fmt.Println("Not running BenchmarkTestSingleUser")
		return
	}

	reqUrl, _ := url.Parse(baseUrl + "/Users/00000000-0000-4000-4000-000000000000") // admin user

	start := time.Now()
	//fmt.Println(t.N)
	for i := 0; i < t.N; i++ {
		req := &http.Request{Method: "GET", URL: reqUrl}

		result := scl.sendReq(req)
		if result.StatusCode == http.StatusOK {
			//durSec := time.Now().Sub(start).Seconds()
			//fmt.Printf("%d resources fetched in %fsec\n", lr.TotalResults, durSec)
		} else {
			fmt.Println(result.StatusCode)
			fmt.Printf("%s", result.ErrorMsg)
		}
	}

	dur := time.Now().Sub(start).String()
	fmt.Printf("total number of seconds for %d search iterations %s\n", t.N, dur)
}

func BenchmarkTestSingleUserUsingFilter(t *testing.B) {
	if true {
		fmt.Println("Not running BenchmarkTestSearchAllOfSingleResourceType")
		return
	}

	reqUrl, _ := url.Parse(baseUrl + "/Users?filter=" + url.QueryEscape("id EQ \"00000000-0000-4000-4000-000000000000\"")) // admin user

	start := time.Now()
	//fmt.Println(t.N)
	for i := 0; i < t.N; i++ {
		req := &http.Request{Method: "GET", URL: reqUrl}
		result := scl.sendReq(req)

		if result.StatusCode == http.StatusOK {
			//durSec := time.Now().Sub(start).Seconds()
			//fmt.Printf("%d resources fetched in %fsec\n", lr.TotalResults, durSec)
		} else {
			fmt.Println(result.StatusCode)
			fmt.Printf("%s", result.ErrorMsg)
		}
	}

	dur := time.Now().Sub(start).String()
	fmt.Printf("BenchmarkTestSingleUserUsingFilter: total number of seconds for %d search iterations %s\n", t.N, dur)
}

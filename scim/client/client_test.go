package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sparrow/scim/base"
	"testing"
)

func TestCreateResourcesPerf(t *testing.T) {
	if true {
		return
	}
	bufReader, err := os.Open("/Volumes/EVOSSD/sparrow-bench/100k-users.json")
	if err != nil {
		t.Error(err)
		return
	}

	lineReader := bufio.NewReader(bufReader)
	count := 0

	for {
		l, err := lineReader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			panic(err)
		}

		buf := bytes.NewReader(l)
		resp, se := http.Post("http://localhost:9090/v2/Users", "application/scim+json", buf)
		if se != nil {
			fmt.Printf("Error while creating resource %#v\n", se)
			break
		}

		resp.Body.Close()

		if resp.StatusCode == http.StatusCreated {
			count++
		}

		if count == 20000 {
			break
		}
	}

	fmt.Printf("Created %d resources\n", count)
}

func TestSearchResourcesPerf(t *testing.T) {
	req := base.NewSearchRequest("username pr", "password", false)
	data, err := json.Marshal(req)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	resp, se := http.Post("http://localhost:9090/v2/Users/.search", "application/scim+json", bytes.NewReader(data))
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
		fmt.Printf("Number of resources fetched %d", lr.TotalResults)
	}
}

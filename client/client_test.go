package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sparrow/base"
	"testing"
	"time"
)

func TestCreateResourcesPerf(t *testing.T) {
	if true {
		fmt.Println("Not running insert perf test")
		return
	}

	bufReader, err := os.Open("/Volumes/EVOSSD/sparrow-bench/100k-users.json")
	if err != nil {
		t.Error(err)
		return
	}

	lineReader := bufio.NewReader(bufReader)
	count := 0

	durSlice := make([]float64, 0)

	start := time.Now()

outer:
	for {
		l, err := lineReader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			panic(err)
		}

		buf := bytes.NewReader(l)
		for {
			ch, _, err := buf.ReadRune()

			if ch == 0 || err != nil {
				continue outer
			}

			if ch == ' ' || ch == '\n' || ch == '\t' || ch == '\r' {
				continue
			} else {
				buf.UnreadRune()
				break
			}
		}

		resp, se := http.Post("http://localhost:9090/v2/Users", "application/scim+json", buf)
		if se != nil {
			fmt.Printf("Error while creating resource %#v\n", se)
			break
		}

		resp.Body.Close()

		if resp.StatusCode == http.StatusCreated {
			count++
		} else {
			panic(fmt.Errorf("Unable to insert %d resource status is %s\n %s", count+1, resp.Status, buf))
		}

		if (count > 0) && ((count % 5000) == 0) {
			durSec := time.Now().Sub(start).Seconds()
			durSlice = append(durSlice, durSec)
			fmt.Printf("Time took to insert %d entries %fsec\n", count, durSec)
		}
	}

	fmt.Printf("Created %d resources in %fsec\n", count, time.Now().Sub(start).Seconds())
	fmt.Println(durSlice)
}

func TestSearchResourcesPerf(t *testing.T) {
	req := base.NewSearchRequest("username pr", "password", false)
	data, err := json.Marshal(req)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	start := time.Now()

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
		durSec := time.Now().Sub(start).Seconds()
		fmt.Printf("%d resources fetched in %fsec\n", lr.TotalResults, durSec)
	}
}

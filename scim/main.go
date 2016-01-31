package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"os"
	"sparrow/scim/provider"
	"sparrow/scim/schema"
	"time"
)

var (
	resDir, _ = os.Getwd()
)

func main() {
	logger.ConfigureLoggers("<root>=debug;scim.main=debug")
	log := logger.GetLogger("scim.main")
	resDir = resDir + "/resources/"
	sc, err := schema.LoadSchema(resDir + "/schemas/user.json")
	if err != nil {
		log.Debugf("%s", err)
		return
	}

	log.Debugf("loggo %#v", sc.AttrMap["addresses"].SubAttrMap)

	sm := make(map[string]*schema.Schema)
	sm[sc.Id] = sc
	fmt.Printf("%#v\n", sc.AttrMap)

	sc, err = schema.LoadSchema(resDir + "/schemas/enterprise-user.json")
	if err != nil {
		fmt.Println(err)
		return
	}
	sm[sc.Id] = sc
	fmt.Printf("%#v\n", sc.AttrMap)

	rtMap := make(map[string]*schema.ResourceType)
	rt, err := schema.LoadResourceType(resDir+"/types/user.json", sm)
	if err != nil {
		fmt.Println(err)
		return
	}
	rtMap[rt.Id] = rt

	data, err := ioutil.ReadFile(resDir + "/samples/ent-user.json")

	if err != nil {
		fmt.Println(err)
		return
	}

	rs, err := provider.ParseResource(rtMap, sm, string(data))
	if err != nil {
		fmt.Print("error \n")
		fmt.Println(err)
	}

	fmt.Printf("%#v\n", rs)
	v, err := rs.ToJSON()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s\n", v)
	log.Debugf("length of the JSON data %d", len(v))

	var rdata bytes.Buffer
	enc := gob.NewEncoder(&rdata)
	dec := gob.NewDecoder(&rdata)

	start := time.Now()

	err = enc.Encode(rs)
	if err != nil {
		fmt.Printf("Error while encoding the resource %s\n", rs.TypeName)
	}

	log.Debugf("size of the encoded buffer %d", rdata.Len())
	var r provider.Resource
	err = dec.Decode(&r)
	if err != nil {
		fmt.Printf("Error while decoding the resource %s\n", rs.TypeName)
	}

	fmt.Printf("\nTime took to encode a resource %#v sec\n", time.Since(start).Seconds())
	fmt.Printf("decoded value %#v\n", r)
	r.SetSchema(rt)
	v, err = rs.ToJSON()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("decoded JSON\n %s", v)
}

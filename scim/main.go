package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"sparrow/scim/provider"
	"sparrow/scim/schema"
	"encoding/gob"
	"bytes"
	"time"
)

var (
	resDir, _ = os.Getwd()
)

func main() {
	resDir = resDir + "/resources/"
	sc, err := schema.LoadSchema(resDir + "/schemas/user.json")
	if err != nil {
		fmt.Println(err)
		return
	}
	
	fmt.Printf("%#v", sc.AttrMap["addresses"].SubAttrMap)
	//return
	
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

	rt, err := schema.LoadResourceType(resDir+"/types/user.json", sm)
	if err != nil {
		fmt.Println(err)
		return
	}

	data, err := ioutil.ReadFile(resDir + "/samples/ent-user.json")

	if err != nil {
		fmt.Println(err)
		return
	}

	rs, err := provider.ParseResource(rt, sm, string(data))
	if err != nil {
		fmt.Print("error \n")
		fmt.Println(err)
	}

	fmt.Printf("%#v\n", rs)
	fmt.Printf("%s\n", rs.ToJSON())
	
	var rdata bytes.Buffer
	enc := gob.NewEncoder(&rdata)
	dec := gob.NewDecoder(&rdata)
	
	start := time.Now()
	
	err = enc.Encode(rs)
	if err != nil {
		fmt.Printf("Error while encoding the resource %s\n", rs.TypeName)
	}
	
	var r provider.Resource
	err = dec.Decode(&r)
	if err != nil {
		fmt.Printf("Error while decoding the resource %s\n", rs.TypeName)
	}
	
	fmt.Printf("\nTime took to encode a resource %#v sec\n", time.Since(start).Seconds())
	fmt.Printf("decoded value %#v\n", r)
	r.SetSchema(rt)
	fmt.Printf("decoded JSON\n %s", r.ToJSON())
}

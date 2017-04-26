package schema

import (
	//	"bytes"
	"fmt"
	//"io/ioutil"
	"testing"
	//	"time"
	"encoding/json"
)

var (
	resDir = "../resources/schemas/"
)

func TestGenerateSchema(t *testing.T) {
	sc, err := LoadSchema(resDir + "group.json")
	if err != nil {
		t.Errorf(err.Error())
	}

	fmt.Println(sc.Id)
	fmt.Println(sc.Attributes[0].Returned)
	fmt.Println(sc.Attributes[1].Returned)
	fmt.Println(sc.Attributes[1].SubAttributes[0].Mutability)

	//var at Attribute

	data, _ := json.Marshal(sc.Attributes[1].SubAttributes[0])
	fmt.Println(string(data))

	data = []byte(`{"id": "abc"}`)
	sc, err = NewSchema(data)

	ve := err.(*ValidationErrors)
	if ve.Count != 1 {
		t.Errorf("There must be one error in schema")
	}
}

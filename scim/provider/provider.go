package provider

import (
//	"encoding/json"
	"sparrow/scim/schema"
)

var schemas = make(map[string]*schema.Schema)

type AuthContext struct {
}


/*
func CreateResource(sc *schema.Schema, jsonData string) error {
	obj, err := validateData(sc, jsonData)
	
	if obj != nil {
		
	}
	if err != nil {
		return err
	}
	
	return nil
}
*/
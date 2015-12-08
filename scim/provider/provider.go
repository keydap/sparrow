package provider

import (
//	"encoding/json"
	"sparrow/scim/schema"
	logger "github.com/juju/loggo"	
)

var schemas = make(map[string]*schema.Schema)

type AuthContext struct {
}

var log logger.Logger

func init() {
	log = logger.GetLogger("scim.provider")
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
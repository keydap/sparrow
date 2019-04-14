package net

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/provider"
	"strconv"
	"strings"
)

// a struct for deserializing incoming config JSON patchset
type confPatch struct {
	Op    string
	Path  string
	Value interface{}
}

func (sp *Sparrow) handleDomainConf(w http.ResponseWriter, r *http.Request) {
	opCtx, err := createOpCtx(r, sp)
	if err != nil {
		writeError(w, err)
		return
	}

	if _, ok := opCtx.Session.Roles[provider.SystemGroupId]; !ok {
		err := base.NewForbiddenError("Insufficient access privileges, only users belonging to System group can modify the config")
		writeError(w, err)
		return
	}

	pr := sp.providers[opCtx.Session.Domain]
	log.Debugf("serving configuration of the domain %s", pr.Name)

	hc := httpContext{w, r, pr, opCtx}

	if r.Method == http.MethodGet {
		sendDomainConf(pr, hc)
	} else if r.Method == http.MethodPatch {
		updateDomainConf(pr, hc, sp)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func sendDomainConf(pr *provider.Provider, hc httpContext) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.Encode(pr.Config)

	headers := hc.w.Header()
	headers.Add("Content-Type", "application/json")
	hc.w.Write(buf.Bytes())
}

func updateDomainConf(pr *provider.Provider, hc httpContext, sp *Sparrow) {
	var cpatches []confPatch
	dec := json.NewDecoder(hc.r.Body)
	err := dec.Decode(&cpatches)
	if err != nil {
		err = base.NewBadRequestError(err.Error())
		writeError(hc.w, err)
		return
	}

	sp.dconfUpdateMutex.Lock()
	log.Infof("%v", cpatches)

	defer func() {
		e := recover()
		if _, ok := e.(error); ok {
			log.Errorf("failed to updated domain config %v", e)
			writeError(hc.w, e.(error))
		}
		sp.dconfUpdateMutex.Unlock()
	}()

	ifMatch := hc.r.Header.Get("If-Match")
	if ifMatch != pr.Config.Scim.Meta.Version {
		err := base.NewConflictError("configuration was modified since last accessed")
		writeError(hc.w, err)
		return
	}

	updated := false

outer:
	for _, v := range cpatches {
		dc := reflect.ValueOf(pr.Config).Elem()

		pathParts := strings.Split(v.Path, "/")
		pathParts = pathParts[1:]
		plen := len(pathParts)
		log.Debugf("%v %d", pathParts, plen)
		if plen < 2 {
			log.Warningf("Unsupported config path %s, can only change primitive fields", v.Path)
			continue
		}

		firstFieldName := pathParts[0]
		sf, found := findFieldWithTag(firstFieldName, dc.Type())
		if !found {
			log.Warningf("invalid path, no field with the name %s found", firstFieldName)
			continue
		}

		// resources is an array type
		if firstFieldName == "resources" {
			err := updateResources(pr.Config, v, pathParts[1:])
			if err != nil {
				panic(err)
			}

			updated = true
			log.Debugf("%v", err)
			continue
		}

		// replacing values of existing fields allowed
		// except in the case of resources where add and remove are permitted
		if v.Op != "replace" {
			continue
		}

		// remaining are fields in internal structs
		dc = dc.FieldByName(sf.Name).Elem()
		for _, fieldName := range pathParts[1:] {
			log.Debugf("finding field %s", fieldName)
			sf, found = findFieldWithTag(fieldName, dc.Type())
			if !found {
				log.Warningf("invalid child-path, no field with the name %s found", pathParts[1])
				continue outer
			}
		}

		if found {
			val := reflect.ValueOf(v.Value)
			f := dc.FieldByName(sf.Name)
			switch sf.Type.Kind() {
			case reflect.Int:
				intVal := int64(val.Float())
				if intVal > 0 {
					f.SetInt(intVal)
					updated = true
				} else {
					// TODO use the validator framework to validate
					log.Warningf("Invalid value %d for the field %s, ignoring", intVal, sf.Name)
				}
			case reflect.String:
				f.SetString(val.String())
				updated = true
			case reflect.Bool:
				f.SetBool(val.Bool())
				updated = true
			}
			log.Infof("successfully updated field %v", sf)
		}
	}

	if updated {
		err := pr.SaveConf()
		if err != nil {
			writeError(hc.w, err)
			return
		}
		log.Debugf("successfully saved %s domain's config", pr.Name)
		sendDomainConf(pr, hc)
	} else {
		hc.w.WriteHeader(http.StatusNotModified)
	}
}

func findFieldWithTag(tag string, t reflect.Type) (sf reflect.StructField, found bool) {
	count := t.NumField()
	for i := 0; i < count; i++ {
		sf = t.Field(i)
		fTag := sf.Tag.Get("json")
		if strings.HasPrefix(fTag, tag) {
			found = true
			break
		}
	}

	return sf, found
}

/* some scenarios
{"op":"replace","path":"/resources/0/indexFields/3","value":"active"}
{"op":"replace","path":"/resources/0/indexFields/4","value":"addresses.country"}
{"op":"remove","path":"/resources/0/indexFields/5"}
{"op":"add","path":"/resources/0/indexFields/-","value":"addresses.country"}
{"op":"add","path":"/resources/-","value":{"name":"Application","indexFields":[]}}
{"op":"remove","path":"/resources/2"}
{"op":"replace","path":"/resources/2/name","value":"Application"}
{"op":"replace","path":"/resources/2/indexFields/0","value":"assertionvalidity"}
*/
func updateResources(cf *conf.DomainConfig, v confPatch, pathParts []string) error {
	plen := len(pathParts)

	switch v.Op {
	case "remove":
		rIndex, err := strconv.Atoi(pathParts[0])
		if err != nil {
			return err
		}
		rlen := len(cf.Resources)
		if rIndex >= rlen {
			return fmt.Errorf("invalid index %d in the remove operation on resources array", rIndex)
		}
		rlen--

		if plen == 1 { // remove it from resources array
			if rIndex == 0 {
				cf.Resources = cf.Resources[1:]
			} else if rIndex == rlen {
				cf.Resources = cf.Resources[:rIndex]
			} else {
				cf.Resources = append(cf.Resources[:rIndex], cf.Resources[rIndex+1:]...)
			}
		} else { // remove from indexFields alone
			if pathParts[1] != "indexFields" {
				return fmt.Errorf("cannot remove anything other than from indexFields")
			}

			fIndex, err := strconv.Atoi(pathParts[2])
			if err != nil {
				return err
			}

			indexFields := cf.Resources[rIndex].IndexFields
			flen := len(indexFields)
			if fIndex >= flen {
				return fmt.Errorf("invalid index %d in the operation to remove from indexFields", fIndex)
			}
			flen--

			if fIndex == 0 {
				indexFields = indexFields[1:]
			} else if fIndex == flen {
				indexFields = indexFields[:fIndex]
			} else {
				indexFields = append(indexFields[:fIndex], indexFields[fIndex+1:]...)
			}
			cf.Resources[rIndex].IndexFields = indexFields
			log.Debugf("%v", cf.Resources[rIndex].IndexFields)
		}

	case "replace":
		rIndex, err := strconv.Atoi(pathParts[0])
		if err != nil {
			return err
		}
		rlen := len(cf.Resources)
		if rIndex >= rlen {
			return fmt.Errorf("invalid index %d in the replace operation on resources array", rIndex)
		}
		rlen--

		if plen == 1 { // replace a value in resources array
			rc, err := parseResourceConf(v.Value)
			if err != nil {
				return err
			}
			cf.Resources[rIndex] = rc
		} else {
			rc := cf.Resources[rIndex]
			name := pathParts[1]
			switch name {
			case "name":
				rc.Name = strings.TrimSpace(fmt.Sprint(v.Value))
				if rc.Name == "" {
					return fmt.Errorf("invalid operation, resource name cannot be blank")
				}
			case "notes":
				rc.Notes = strings.TrimSpace(fmt.Sprint(v.Value))
			case "indexFields":
				fIndex, err := strconv.Atoi(pathParts[2])
				if err != nil {
					return err
				}

				indexFields := cf.Resources[rIndex].IndexFields
				flen := len(indexFields)
				if fIndex >= flen {
					return fmt.Errorf("invalid index %d in the operation to replace from indexFields", fIndex)
				}
				atName := strings.TrimSpace(fmt.Sprint(v.Value))
				if atName == "" {
					return fmt.Errorf("index attribute name cannot be empty")
				}
				indexFields[fIndex] = atName
				cf.Resources[rIndex].IndexFields = indexFields
			}
		}
	case "add":
		if pathParts[0] == "-" { // add resource
			rc, err := parseResourceConf(v.Value)
			if err != nil {
				return err
			}

			cf.Resources = append(cf.Resources, rc)
		} else {
			rIndex, err := strconv.Atoi(pathParts[0])
			if err != nil {
				return err
			}

			name := pathParts[1]
			if name != "indexFields" {
				return fmt.Errorf("cannot allow adding %s under resources, only adding indexFields of a resource is allowed", name)
			}

			if atNameArr, ok := v.Value.([]interface{}); ok {
				cf.Resources[rIndex].IndexFields = toStringArray(atNameArr)
			} else if atName, ok := v.Value.(interface{}); ok {
				idxFields := cf.Resources[rIndex].IndexFields
				idxFields = append(idxFields, fmt.Sprint(atName))
				cf.Resources[rIndex].IndexFields = idxFields
			}
		}
	}

	return nil
}

func parseResourceConf(val interface{}) (*conf.ResourceConf, error) {
	rc := &conf.ResourceConf{}
	m, ok := val.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid ResourceConf data")
	}
	name := m["name"]
	if name == nil {
		return nil, fmt.Errorf("invalid ResourceConf data, resource name is required")
	}
	rc.Name = strings.TrimSpace(fmt.Sprint(name))
	if rc.Name == "" {
		return nil, fmt.Errorf("invalid ResourceConf data, resource name cannot be blank")
	}
	notes := m["notes"]
	if notes != nil {
		rc.Notes = strings.TrimSpace(fmt.Sprint(notes))
	}

	ixFields := m["indexFields"]
	if ixFields == nil {
		rc.IndexFields = make([]string, 0)
	} else {
		iArr := ixFields.([]interface{})
		rc.IndexFields = toStringArray(iArr)
	}

	return rc, nil
}

func toStringArray(iArr []interface{}) []string {
	tmp := make([]string, len(iArr))
	for i, atName := range iArr {
		tmp[i] = fmt.Sprint(atName)
	}

	return tmp
}

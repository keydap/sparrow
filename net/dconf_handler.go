package net

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"sparrow/base"
	"sparrow/provider"
	"strings"
)

// a struct for deserializing incoming config JSON patchset
type confPatch struct {
	Op    string
	Path  string
	Value interface{}
}

func handleDomainConf(w http.ResponseWriter, r *http.Request) {
	opCtx, err := createOpCtx(r)
	if err != nil {
		writeError(w, err)
		return
	}

	if _, ok := opCtx.Session.Roles[provider.SystemGroupId]; !ok {
		err := base.NewForbiddenError("Insufficient access privileges, only users belonging to System group can modify the config")
		writeError(w, err)
		return
	}

	pr := providers[opCtx.Session.Domain]
	log.Debugf("serving configuration of the domain %s", pr.Name)

	hc := httpContext{w, r, pr, opCtx}

	if r.Method == http.MethodGet {
		sendDomainConf(pr, hc)
	} else if r.Method == http.MethodPatch {
		updateDomainConf(pr, hc)
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

func updateDomainConf(pr *provider.Provider, hc httpContext) {
	var cpatches []confPatch
	dec := json.NewDecoder(hc.r.Body)
	err := dec.Decode(&cpatches)
	if err != nil {
		err = base.NewBadRequestError(err.Error())
		writeError(hc.w, err)
		return
	}

	log.Infof("%v", cpatches)

	updated := false

outer:
	for _, v := range cpatches {
		if v.Op != "replace" {
			continue
		}

		dc := reflect.ValueOf(pr.Config).Elem()

		pathParts := strings.Split(v.Path, "/")
		pathParts = pathParts[1:]
		plen := len(pathParts)
		log.Debugf("%v %d", pathParts, plen)
		if plen < 2 {
			log.Warningf("Unsupported config path %s, can only change primitive fields", v.Path)
			continue
		}

		sf, found := findFieldWithTag(pathParts[0], dc.Type())
		if !found {
			log.Warningf("invalid path, no field with the name %s found", pathParts[0])
			continue
		}

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

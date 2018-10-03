// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package net

import (
	"io/ioutil"
	"net/http"
	"runtime/debug"
	"sparrow/base"
	"sparrow/provider"
	"strings"
)

func handleTemplateConf(w http.ResponseWriter, r *http.Request) {
	opCtx, err := createOpCtx(r)
	if err != nil {
		writeError(w, err)
		return
	}

	if _, ok := opCtx.Session.Roles[provider.SystemGroupId]; !ok {
		err := base.NewForbiddenError("Insufficient access privileges, only users belonging to System group can modify the templates")
		writeError(w, err)
		return
	}

	pr := providers[opCtx.Session.Domain]
	log.Debugf("serving templates of the domain %s", pr.Name)

	hc := httpContext{w, r, pr, opCtx}

	if r.Method == http.MethodGet {
		sendTemplate(pr, hc)
	} else if r.Method == http.MethodPut {
		updateTemplate(pr, hc)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func sendTemplate(pr *provider.Provider, hc httpContext) {
	hc.r.ParseForm()
	name := hc.r.Form.Get("name")
	name = strings.TrimSpace(name)
	if name == "" {
		writeError(hc.w, base.NewBadRequestError("parameter 'name' is missing"))
		return
	}

	data, err := pr.ReadTemplate(name)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	headers := hc.w.Header()
	headers.Add("Content-Type", "text/plain")
	hc.w.Write(data)
}

func updateTemplate(pr *provider.Provider, hc httpContext) {
	hc.r.ParseForm()
	name := hc.r.Form.Get("name")
	name = strings.TrimSpace(name)
	if name == "" {
		writeError(hc.w, base.NewBadRequestError("parameter 'name' is missing"))
		return
	}

	dconfUpdateMutex.Lock()
	log.Debugf("replacing the template %s", name)

	defer func() {
		e := recover()
		if _, ok := e.(error); ok {
			debug.PrintStack()
			log.Errorf("failed to updated template %s %v", name, e)
			writeError(hc.w, e.(error))
		}
		dconfUpdateMutex.Unlock()
	}()

	data, err := ioutil.ReadAll(hc.r.Body)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	t, err := pr.UpdateTemplate(name, data)
	if err != nil {
		writeError(hc.w, err)
	} else {
		if t != nil {
			// unlike LDAP templates html templates are global at the moment
			templates[t.Name()] = t
		}
		headers := hc.w.Header()
		headers.Add("Content-Type", "text/plain")
		hc.w.Write(data)
	}
}

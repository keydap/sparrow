package net

import (
	"net/http"
	"sparrow/base"
	"strings"
)

func (sp *Sparrow) handleDomainLifecycle(w http.ResponseWriter, r *http.Request) {
	opCtx := getOpCtxOfAdminSessionOrAbort(w, r, sp)
	if opCtx == nil {
		return
	}

	r.ParseForm()
	operation := strings.TrimSpace(r.Form.Get("op"))
	operation = strings.ToLower(operation)

	name := strings.TrimSpace(r.Form.Get("name"))
	name = strings.ToLower(name)

	switch operation {
	case "create":
		err := sp.createDomain(name)
		if err != nil {
			writeError(w, base.NewBadRequestError(err.Error()))
		} else {
			pr := sp.providers[sp.srvConf.ControllerDomain]
			pr.SendCreateDomainEvent(name)
		}
	}
}

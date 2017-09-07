// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	logger "github.com/juju/loggo"
	"html/template"
	"net/http"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/provider"
	"sparrow/schema"
	"sparrow/utils"
	"strconv"
	"strings"
)

var log logger.Logger

var providers = make(map[string]*provider.Provider)

// a map of providers keyed using the hashcode of the domain name
// this exists to keep the length of Oauth code fixed to N bytes
var dcPrvMap = make(map[uint32]*provider.Provider)

var TENANT_HEADER = "X-Sparrow-Domain"
var TENANT_COOKIE = "SD"
var SCIM_JSON_TYPE = "application/scim+json; charset=UTF-8"
var JSON_TYPE = "application/json; charset=UTF-8"
var FORM_URL_ENCODED_TYPE = "application/x-www-form-urlencoded"
const SSO_COOKIE = "KSPAX" // Keydap Sparrow Auth X (X -> all the authenticated users)

var API_BASE = "/v2"       // NO slash at the end
var OAUTH_BASE = "/oauth2" // NO slash at the end
var commaByte = []byte{','}

var defaultDomain = "example.com"
var srvConf *conf.ServerConf
var templates map[string]*template.Template
var cs *sessions.CookieStore
var server *http.Server

var cookieKey []byte

var issuerUrl = ""

func init() {
	log = logger.GetLogger("sparrow.net")
	cookieKey = utils.RandBytes(16)
}

type httpContext struct {
	w  http.ResponseWriter
	r  *http.Request
	pr *provider.Provider
	*base.OpContext
}

func startHttp() {
	hostAddr := srvConf.IpAddress + ":" + strconv.Itoa(srvConf.HttpPort)
	log.Infof("Starting http server %s", hostAddr)

	router := mux.NewRouter()
	router.StrictSlash(true)
	router.HandleFunc("/", serveVersionInfo).Methods("GET")

	// scim requests
	scimRouter := router.PathPrefix(API_BASE).Subrouter()

	scimRouter.HandleFunc("/directLogin", directLogin).Methods("POST")
	//scimRouter.HandleFunc("/revoke", handleRevoke).Methods("DELETE")
	scimRouter.HandleFunc("/Me", selfServe).Methods("GET", "POST", "PUT", "PATCH", "DELETE")

	// generic service provider methods
	scimRouter.HandleFunc("/ServiceProviderConfig", getSrvProvConf).Methods("GET")
	scimRouter.HandleFunc("/ResourceTypes", getResTypes).Methods("GET")
	scimRouter.HandleFunc("/Schemas", getSchemas).Methods("GET")
	scimRouter.HandleFunc("/Bulk", bulkUpdate).Methods("POST")

	// root level search
	scimRouter.HandleFunc("/.search", handleResRequest).Methods("POST")

	// register routes for each resourcetype endpoint
	for _, p := range providers {
		for _, rt := range p.RsTypes {
			scimRouter.HandleFunc("/ResourceTypes/"+rt.Name, getResTypes).Methods("GET")

			scimRouter.HandleFunc(rt.Endpoint, handleResRequest).Methods("POST")
			scimRouter.HandleFunc(rt.Endpoint, handleResRequest).Methods("GET")
			scimRouter.HandleFunc(rt.Endpoint, handleResRequest).Methods("GET").Queries("filter", "")
			scimRouter.HandleFunc(rt.Endpoint, handleResRequest).Methods("GET").Queries("attributes", "")
			scimRouter.HandleFunc(rt.Endpoint, handleResRequest).Methods("GET").Queries("excludedAttributes", "")
			scimRouter.HandleFunc(rt.Endpoint+"/.search", handleResRequest).Methods("POST")
			scimRouter.HandleFunc(rt.Endpoint+"/{id}", handleResRequest).Methods("PUT", "PATCH", "DELETE")
			scimRouter.HandleFunc(rt.Endpoint+"/{id}", handleResRequest).Methods("GET")
			scimRouter.HandleFunc(rt.Endpoint+"/{id}", handleResRequest).Methods("GET").Queries("attributes", "")
			scimRouter.HandleFunc(rt.Endpoint+"/{id}", handleResRequest).Methods("GET").Queries("excludedAttributes", "")
		}

		for _, sc := range p.Schemas {
			scimRouter.HandleFunc("/Schemas/"+sc.Id, getSchemas).Methods("GET")
		}
	}

	// OAuth2 requests
	oauthRouter := router.PathPrefix(OAUTH_BASE).Subrouter()
	// match /authorize with any number of query parameters
	oauthRouter.HandleFunc("/authorize", authorize).Methods("GET", "POST").MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		return true
	})

	oauthRouter.HandleFunc("/register", registerClient).Methods("POST")
	oauthRouter.HandleFunc("/token", sendToken).Methods("POST")
	oauthRouter.HandleFunc("/consent", verifyConsent).Methods("POST")

	router.HandleFunc("/login", showLogin).Methods("GET")
	router.HandleFunc("/verifyPassword", verifyPassword).Methods("POST")

	if srvConf.Https {
		issuerUrl = "https://" + hostAddr
		server = &http.Server{Addr: issuerUrl, Handler: router}
		server.ListenAndServeTLS(srvConf.CertFile, srvConf.PrivKeyFile)
	} else {
		issuerUrl = "http://" + hostAddr
		server = &http.Server{Addr: issuerUrl, Handler: router}
		server.ListenAndServe()
	}
}

func stopHttp() {
	log.Debugf("Stopping HTTP server")
	server.Close()
	for _, pr := range providers {
		pr.Close()
	}
}

func bulkUpdate(w http.ResponseWriter, r *http.Request) {
}

func searchResource(hc *httpContext) {
	log.Debugf("endpoint %s", hc.Endpoint)
	pos := strings.LastIndex(hc.Endpoint, "/")

	if pos > 0 {
		rid := hc.Endpoint[pos+1:]
		log.Debugf("Searching for the resource with ID %s", rid)
		rtByPath := hc.pr.RtPathMap[hc.Endpoint[0:pos]]

		getCtx := base.GetContext{Rid: rid, Rt: rtByPath, OpContext: hc.OpContext}
		rs, err := hc.pr.GetResource(&getCtx)
		if err != nil {
			writeError(hc.w, err)
			return
		}

		ifNoneMatch := hc.r.Header.Get("If-None-Match")
		if len(ifNoneMatch) != 0 {
			version := rs.GetVersion()
			if strings.Compare(ifNoneMatch, version) == 0 {
				hc.w.Header().Add("Etag", version)
				hc.w.WriteHeader(http.StatusNotModified)
				return
			}
		}

		err = hc.r.ParseForm()
		if err != nil {
			writeError(hc.w, err)
			return
		}

		attributes := hc.r.Form.Get("attributes")
		exclAttributes := hc.r.Form.Get("excludedAttributes")

		var jsonData []byte

		if len(attributes) != 0 && len(exclAttributes) != 0 {
			err := base.NewBadRequestError("The parameters 'attributes' and 'excludedAttributes' cannot be set for fetching a resource")
			writeError(hc.w, err)
			return
		}

		attrLst, exclAttrLst := parseAttrParams(attributes, exclAttributes, rtByPath)
		if attrLst != nil {
			jsonData = rs.FilterAndSerialize(attrLst, true)
		} else {
			jsonData = rs.FilterAndSerialize(exclAttrLst, false)
		}

		writeCommonHeaders(hc.w)
		header := hc.w.Header()
		header.Add("Location", hc.r.RequestURI+"/"+rid)
		header.Add("Etag", rs.GetVersion())
		hc.w.WriteHeader(http.StatusOK)
		hc.w.Write(jsonData)
		log.Debugf("Found the resource with ID %s", rid)
		return
	}

	rtByPath := hc.pr.RtPathMap[hc.Endpoint]

	err := hc.r.ParseForm()
	if err != nil {
		writeError(hc.w, err)
		return
	}

	sr := &base.SearchRequest{}
	sr.Filter = hc.r.Form.Get("filter")
	sr.Attributes = hc.r.Form.Get("attributes")
	sr.ExcludedAttributes = hc.r.Form.Get("excludedAttributes")

	search(hc, sr, rtByPath)
}

func searchWithSearchRequest(hc *httpContext) {
	pos := strings.LastIndex(hc.Endpoint, "/.search")
	if pos < 0 {
		err := base.NewBadRequestError("Invalid request")
		writeError(hc.w, err)
		return
	}

	sr := &base.SearchRequest{}

	defer hc.r.Body.Close()
	err := json.NewDecoder(hc.r.Body).Decode(sr)
	if err != nil {
		e := base.NewBadRequestError("Invalid search request " + err.Error())
		writeError(hc.w, e)
		return
	}

	if pos > 0 { // endpoint is NOT server root
		rtByPath := hc.pr.RtPathMap[hc.Endpoint[0:pos]]
		search(hc, sr, rtByPath)
	} else {
		rTypes := make([]*schema.ResourceType, len(hc.pr.RsTypes))
		count := 0
		for _, rt := range hc.pr.RsTypes {
			rTypes[count] = rt
			count++
		}

		search(hc, sr, rTypes...)
	}
}

func search(hc *httpContext, sr *base.SearchRequest, rTypes ...*schema.ResourceType) {

	sx := &base.SearchContext{}

	sx.ResTypes = make([]*schema.ResourceType, len(rTypes))
	copy(sx.ResTypes, rTypes)

	paramFilter := strings.TrimSpace(sr.Filter)
	// case where the search should be on entire set of resources of a single type, e.g /Users
	if len(paramFilter) == 0 {
		if len(rTypes) == 1 {
			paramFilter = "meta.resourceType eq " + rTypes[0].Name
		} else if len(rTypes) > 1 {
			err := base.NewBadRequestError("Missing 'filter' parameter")
			writeError(hc.w, err)
			return
		}
	}

	if len(sr.Attributes) != 0 && len(sr.ExcludedAttributes) != 0 {
		err := base.NewBadRequestError("The parameters 'attributes' and 'excludedAttributes' cannot be set in a signle request")
		writeError(hc.w, err)
		return
	}

	filter, err := base.ParseFilter(paramFilter)
	if err != nil {
		se := base.NewBadRequestError(err.Error())
		se.ScimType = base.ST_INVALIDFILTER
		writeError(hc.w, se)
		return
	}

	err = base.FixSchemaUris(filter, rTypes)
	if err != nil {
		se := base.NewBadRequestError(err.Error())
		se.ScimType = base.ST_INVALIDFILTER
		writeError(hc.w, se)
		return
	}

	attrLst, exclAttrLst := parseAttrParams(sr.Attributes, sr.ExcludedAttributes, rTypes...)

	sc := &base.SearchContext{}
	sc.Filter = filter
	sc.OpContext = hc.OpContext
	sc.ResTypes = rTypes

	outPipe := make(chan *base.Resource, 0)

	// search starts a go routine and returns nil error immediately
	// or returns an error before starting the go routine
	err = hc.pr.Search(sc, outPipe)
	if err != nil {
		close(outPipe)
		writeError(hc.w, err)
		return
	}

	writeCommonHeaders(hc.w)
	hc.w.Write([]byte(`{"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "Resources":[`)) // yes, the 'R' in resources must be upper case

	count := 0
	for rs := range outPipe {
		var jsonData []byte

		// write the separator ,
		if count > 0 {
			_, err := hc.w.Write(commaByte)
			if err != nil {
				break
			}
		}

		// attribute filtering
		if attrLst != nil {
			jsonData = rs.FilterAndSerialize(attrLst, true)
		} else {
			jsonData = rs.FilterAndSerialize(exclAttrLst, false)
		}

		_, err := hc.w.Write(jsonData)
		if err != nil {
			break
		}
		count++
	}

	hc.w.Write([]byte(`], "totalResults":` + strconv.Itoa(count) + `}`))
}

func createResource(hc *httpContext) {
	defer hc.r.Body.Close()
	rs, err := base.ParseResource(hc.pr.RsTypes, hc.pr.Schemas, hc.r.Body)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	rtByPath := hc.pr.RtPathMap[hc.Endpoint]
	rsType := rs.GetType()
	if rsType != rtByPath {
		// return bad request error
		err = base.NewBadRequestError(fmt.Sprintf("Resource data of type %s is sent to the wrong endpoint %s", rsType.Name, hc.r.RequestURI))
		writeError(hc.w, err)
		return
	}

	createCtx := base.CreateContext{InRes: rs, OpContext: hc.OpContext}
	insertedRs, err := hc.pr.CreateResource(&createCtx)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	rid := insertedRs.GetId()
	writeCommonHeaders(hc.w)
	header := hc.w.Header()
	header.Add("Location", hc.r.RequestURI+"/"+rid)
	header.Add("Etag", insertedRs.GetVersion())
	hc.w.WriteHeader(http.StatusCreated)
	d := insertedRs.Serialize()
	log.Debugf("-------------------\n%s", string(d))
	hc.w.Write(d)
	log.Debugf("Successfully inserted the resource with ID %s", rid)
}

func replaceResource(hc *httpContext) {
	pos := strings.LastIndex(hc.Endpoint, "/")
	pos++
	if pos >= len(hc.Endpoint) {
		writeCommonHeaders(hc.w)
		hc.w.WriteHeader(http.StatusBadRequest)
		detail := "Invalid replace request, missing resource ID"
		log.Debugf(detail)
		err := base.NewBadRequestError(detail)
		hc.w.Write(err.Serialize())
		return
	}

	defer hc.r.Body.Close()
	rs, err := base.ParseResource(hc.pr.RsTypes, hc.pr.Schemas, hc.r.Body)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	rid := hc.Endpoint[pos:]
	rtByPath := hc.pr.RtPathMap[hc.Endpoint[0:pos-1]]
	rsType := rs.GetType()
	if rsType != rtByPath {
		// return bad request error
		err = base.NewBadRequestError(fmt.Sprintf("Resource data of type %s is sent to the wrong endpoint %s", rsType.Name, hc.r.RequestURI))
		writeError(hc.w, err)
		return
	}

	// set the ID on the resource first (even if the resource contains an ID it is safe to overwrite it)
	rs.SetId(rid)
	replaceCtx := base.ReplaceContext{InRes: rs, OpContext: hc.OpContext}
	replaceCtx.Rid = rid
	replaceCtx.IfNoneMatch = hc.r.Header.Get("If-None-Match")
	replacedRs, err := hc.pr.Replace(&replaceCtx)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	writeCommonHeaders(hc.w)
	header := hc.w.Header()
	header.Add("Location", hc.r.RequestURI+"/"+rid)
	header.Add("Etag", replacedRs.GetVersion())
	hc.w.WriteHeader(http.StatusOK)
	hc.w.Write(replacedRs.Serialize())
	log.Debugf("Successfully replaced the resource with ID %s", rid)
}

func patchResource(hc *httpContext) {
	pos := strings.LastIndex(hc.Endpoint, "/")
	pos++
	if pos >= len(hc.Endpoint) {
		writeCommonHeaders(hc.w)
		hc.w.WriteHeader(http.StatusBadRequest)
		detail := "Invalid patch request, missing resource ID"
		log.Debugf(detail)
		err := base.NewBadRequestError(detail)
		hc.w.Write(err.Serialize())
		return
	}

	err := hc.r.ParseForm()
	if err != nil {
		writeError(hc.w, err)
		return
	}

	reqAttr := hc.r.Form.Get("attributes")

	rid := hc.Endpoint[pos:]
	rtByPath := hc.pr.RtPathMap[hc.Endpoint[0:pos-1]]
	if rtByPath == nil {
		// return bad request error
		err := base.NewBadRequestError(fmt.Sprintf("There is no resource type associated with the endpoint %s", hc.r.RequestURI))
		writeError(hc.w, err)
		return
	}

	defer hc.r.Body.Close()
	patchReq, err := base.ParsePatchReq(hc.r.Body, rtByPath)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	patchReq.IfNoneMatch = hc.r.Header.Get("If-None-Match")
	patchCtx := base.PatchContext{Rid: rid, Rt: rtByPath, Pr: patchReq, OpContext: hc.OpContext}
	patchedRes, err := hc.pr.Patch(&patchCtx)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	writeCommonHeaders(hc.w)
	header := hc.w.Header()
	header.Add("Location", hc.r.RequestURI+"/"+rid)
	header.Add("Etag", patchedRes.GetVersion())

	if reqAttr == "" {
		hc.w.WriteHeader(http.StatusNoContent)
	} else {
		attrLst := parseAttrParam(reqAttr, []*schema.ResourceType{rtByPath})
		if attrLst != nil {
			data := patchedRes.FilterAndSerialize(attrLst, true)
			hc.w.WriteHeader(http.StatusOK)
			hc.w.Write(data)
		}
	}
}

func deleteResource(hc *httpContext) {
	log.Debugf(hc.Endpoint)
	pos := strings.LastIndex(hc.Endpoint, "/")
	pos++
	if pos >= len(hc.Endpoint) {
		writeCommonHeaders(hc.w)
		hc.w.WriteHeader(http.StatusBadRequest)
		detail := "Invalid delete request, missing resource ID"
		log.Debugf(detail)
		err := base.NewBadRequestError(detail)
		hc.w.Write(err.Serialize())
		return
	}

	rid := hc.Endpoint[pos:]
	rtByPath := hc.pr.RtPathMap[hc.Endpoint[0:pos-1]]
	delCtx := base.DeleteContext{Rid: rid, Rt: rtByPath, OpContext: hc.OpContext}
	err := hc.pr.DeleteResource(&delCtx)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	hc.w.WriteHeader(http.StatusNoContent)
	log.Debugf("Successfully deleted the resource with ID %s", rid)
}

func getSrvProvConf(w http.ResponseWriter, r *http.Request) {
	pr, err := getPrFromParam(r)
	if err != nil {
		writeError(w, err)
		return
	}

	log.Debugf("Sending service provider configuration of domain %s", pr.Name)

	data, err := pr.GetConfigJson()
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
	} else {
		//log.Debugf("service provider config %s", string(data))
		writeCommonHeaders(w)
		w.Write(data)
	}
}

func getPrFromParam(r *http.Request) (pr *provider.Provider, err error) {
	// NO NEED TO parse Form cause the domain ID will be either in the
	// Header or in a Cookie
	//r.ParseForm()
	domain := r.Header.Get(TENANT_COOKIE)

	if len(domain) == 0 {
		domain = r.Header.Get(TENANT_HEADER)
	}

	/* no longer supported
	if len(domain) == 0 {
		domain = r.Form.Get("d")
	}*/

	domain = strings.ToLower(domain)

	if len(domain) == 0 {
		domain = defaultDomain
	}

	pr = providers[domain]
	if pr == nil {
		se := base.NewNotFoundError(fmt.Sprintf("No domain '%s' found", domain))
		return nil, se
	}
	return pr, nil
}

func getResTypes(w http.ResponseWriter, r *http.Request) {
	pr, err := getPrFromParam(r)
	if err != nil {
		writeError(w, err)
		return
	}

	var data string
	ep := getEndpoint(r)
	tokens := strings.SplitAfter(ep, "ResourceTypes/")
	if len(tokens) == 2 {
		log.Debugf("Sending resource type %s of the domain %s", tokens[1], pr.Name)
		rt := pr.RsTypes[tokens[1]]
		if rt == nil {
			se := base.NewNotFoundError("ResourceType " + tokens[1] + " does not exist")
			writeCommonHeaders(w)
			w.WriteHeader(se.Code())
			w.Write(se.Serialize())
			return
		}

		data = rt.Text
	} else {
		log.Debugf("Sending resource types of the domain %s", pr.Name)
		data = pr.GetResTypeJsonArray()
	}

	writeCommonHeaders(w)
	w.Write([]byte(data))
}

func getSchemas(w http.ResponseWriter, r *http.Request) {
	pr, err := getPrFromParam(r)
	if err != nil {
		writeError(w, err)
		return
	}

	var data string
	ep := getEndpoint(r)
	tokens := strings.SplitAfter(ep, "Schemas/")
	if len(tokens) == 2 {
		log.Debugf("Sending schema %s of the domain %s", tokens[1], pr.Name)
		sc := pr.Schemas[tokens[1]]
		if sc == nil {
			se := base.NewNotFoundError("Schema " + tokens[1] + " does not exist")
			writeCommonHeaders(w)
			w.WriteHeader(se.Code())
			w.Write(se.Serialize())
			return
		}

		data = sc.Text
	} else {
		log.Debugf("Sending schemas of the domain %s", pr.Name)
		data = pr.GetSchemaJsonArray()
	}

	writeCommonHeaders(w)
	w.Write([]byte(data))
}

func selfServe(w http.ResponseWriter, r *http.Request) {
	log.Debugf("-------------------- Headers received on /Me -----------\n%#v\n--------------------------------", r.Header)

	opCtx, err := createOpCtx(r)
	if err != nil {
		writeError(w, err)
		return
	}

	pr := providers[opCtx.Session.Domain]
	log.Debugf("handling %s request on %s for the domain %s", r.Method, r.RequestURI, pr.Name)

	//hc := &httpContext{w, r, pr, opCtx}

	switch r.Method {
	case http.MethodGet:
		getCtx := &base.GetContext{}
		getCtx.OpContext = opCtx
		getCtx.Rid = opCtx.Session.Sub
		getCtx.Rt = pr.RsTypes["User"]
		user, err := pr.GetResource(getCtx)
		if err != nil {
			writeError(w, err)
			return
		}

		//user.FilterAndSerialize(getCtx.Rt., include)

		writeCommonHeaders(w)
		w.Write(user.Serialize())
	}
}

func serveVersionInfo(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(version))
}

func directLogin(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	ar := &base.AuthRequest{}
	err := json.NewDecoder(r.Body).Decode(ar)
	if err != nil {
		e := base.NewBadRequestError("Invalid authentication request " + err.Error())
		writeError(w, e)
		return
	}

	ar.ClientIP = r.RemoteAddr
	normDomain := strings.ToLower(ar.Domain)
	if len(normDomain) == 0 {
		normDomain = defaultDomain
	}
	pr := providers[normDomain]

	if pr == nil {
		e := base.NewBadRequestError("Invalid domain name " + ar.Domain)
		writeError(w, e)
		return
	}

	ar.Domain = normDomain
	user := pr.Authenticate(ar.Username, ar.Password)
	if user == nil {
		writeError(w, base.NewBadRequestError("Invalid credentials"))
		return
	}

	token := pr.GenSessionForUser(user)
	pr.StoreOauthSession(token)

	log.Debugf("Issued token %s by %s", token.Jti, ar.Domain)
	// write the token
	headers := w.Header()
	headers.Add("Content-Type", "text/plain")
	w.Write([]byte(token.Jti))
}

func handleResRequest(w http.ResponseWriter, r *http.Request) {
	log.Debugf("-------------------- Headers received-----------\n%#v\n--------------------------------", r.Header)

	opCtx, err := createOpCtx(r)
	if err != nil {
		writeError(w, err)
		return
	}

	pr := providers[opCtx.Session.Domain]
	log.Debugf("handling %s request on %s for the domain %s", r.Method, r.RequestURI, pr.Name)

	hc := &httpContext{w, r, pr, opCtx}

	switch r.Method {
	case http.MethodGet:
		searchResource(hc)

	case http.MethodPost:
		if badContentType(w, r) {
			return
		}

		if strings.HasSuffix(hc.Endpoint, "/.search") {
			searchWithSearchRequest(hc)
		} else {
			createResource(hc)
		}

	case http.MethodDelete:
		deleteResource(hc)

	case http.MethodPatch:
		if badContentType(w, r) {
			return
		}
		patchResource(hc)

	case http.MethodPut:
		if badContentType(w, r) {
			return
		}
		replaceResource(hc)
	}
}

func badContentType(w http.ResponseWriter, r *http.Request) bool {
	contType := r.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contType), "charset=utf-8") {
		msg := fmt.Sprintf("Rejecting request with bad Content-Type header value %s", contType)
		log.Debugf(msg)
		err := base.NewBadRequestError(msg)
		writeError(w, err)
		return true
	}

	return false
}

func createOpCtx(r *http.Request) (opCtx *base.OpContext, err error) {
	opCtx = &base.OpContext{}

	authzHeader := r.Header.Get("Authorization")
	if len(authzHeader) == 0 {
		// check for SSO cookie
		cookie, _ := r.Cookie(SSO_COOKIE)
		if cookie != nil {
			authzHeader = cookie.Value
			opCtx.Sso = true
		} else {
			// return Unauthorized error
			return nil, base.NewUnAuthorizedError("Missing Authorization header")
		}
	}

	session, err := parseToken(authzHeader, opCtx, r)
	if err != nil {
		return nil, err
	}

	opCtx.Session = session
	opCtx.ClientIP = r.RemoteAddr
	opCtx.Endpoint = getEndpoint(r)

	return opCtx, nil
}

func getEndpoint(r *http.Request) string {
	parts := strings.Split(r.URL.Path, API_BASE)
	ep := ""
	if len(parts) == 2 { // extract the part after API_BASE
		ep = parts[1]
	} else {
		ep = r.RequestURI
	}

	// trim '/' if it is the last char
	epLen := len(ep)
	if (epLen > 1) && (ep[epLen-1] == '/') {
		ep = ep[:epLen-1]
	}

	return ep
}

func writeCommonHeaders(w http.ResponseWriter) {
	headers := w.Header()
	headers.Add("Content-Type", SCIM_JSON_TYPE)
}

func writeError(w http.ResponseWriter, err error) {
	se, ok := err.(*base.ScimError)
	writeCommonHeaders(w)
	if ok {
		w.WriteHeader(se.Code())
		w.Write(se.Serialize())
	} else {
		w.WriteHeader(http.StatusInternalServerError) // unknown error
		unknown := base.NewInternalserverError(err.Error())
		w.Write(unknown.Serialize())
	}
}

func parseAttrParam(attrParam string, rTypes []*schema.ResourceType) []*base.AttributeParam {
	attrSet, subAtPresent := base.SplitAttrCsv(attrParam, rTypes)
	if attrSet != nil {
		// the mandatory attributes that will always be returned
		for _, rt := range rTypes {
			for k, _ := range rt.AtsAlwaysRtn {
				attrSet[k] = 1
			}

			for k, _ := range rt.AtsNeverRtn {
				if _, ok := attrSet[k]; ok {
					delete(attrSet, k)
				}
			}
		}

		// sort the names and eliminate redundant values, for example "name, name.familyName" will be reduced to name
		return base.ConvertToParamAttributes(attrSet, subAtPresent)
	}

	return nil
}

func parseToken(token string, opCtx *base.OpContext, r *http.Request) (session *base.RbacSession, err error) {
	pr, err := getPrFromParam(r)

	if err != nil {
		return nil, err
	}

	if opCtx.Sso {
		session = pr.GetSsoSession(token)
	} else {
		// strip the prefix "Bearer " from token
		spacePos := strings.IndexRune(token, ' ')
		if spacePos > 0 {
			spacePos++
			if spacePos < len(token)-1 {
				token = token[spacePos:]
			}
		}

		session = pr.GetOauthSession(token)
	}

	if session == nil {
		log.Debugf("Failed to fetch the session associated with token %s", token)
		return nil, base.NewForbiddenError("Failed to fetch the session associated with token")
	}

	if session.IsExpired() {
		log.Debugf("Expired session %s", token)
		return nil, base.NewForbiddenError("Expired session token")
	}

	//TODO update the last accesstime if it is a SSO session
	return session, nil
}

func keyFunc(jt *jwt.Token) (key interface{}, err error) {
	domain := jt.Header["d"]
	if domain == nil {
		return nil, jwt.NewValidationError("Missing domain attribute 'd' in the header", jwt.ValidationErrorMalformed)
	}

	prv := providers[domain.(string)]
	return prv.PubKey, nil
}

func parseAttrParams(attributes string, excludedAttributes string, rTypes ...*schema.ResourceType) (attrLst []*base.AttributeParam, exclAttrLst []*base.AttributeParam) {
	if len(attributes) != 0 {
		attrLst = parseAttrParam(attributes, rTypes)
	} else {
		exclAttrLst = parseExcludedAttrs(excludedAttributes, rTypes...)
	}

	return attrLst, exclAttrLst
}

func parseExcludedAttrs(excludedAttributes string, rTypes ...*schema.ResourceType) (exclAttrLst []*base.AttributeParam) {
	exclAttrSet, subAtPresent := base.SplitAttrCsv(excludedAttributes, rTypes)

	if exclAttrSet == nil {
		// in this case compute the never return attribute list
		exclAttrSet = make(map[string]int)
		subAtPresent = true
	}

	// the mandatory attributes cannot be excluded
	for _, rt := range rTypes {
		for k, _ := range rt.AtsAlwaysRtn {
			if _, ok := exclAttrSet[k]; ok {
				delete(exclAttrSet, k)
			}
		}

		for k, _ := range rt.AtsNeverRtn {
			exclAttrSet[k] = 1
		}

		for k, _ := range rt.AtsRequestRtn {
			if _, ok := exclAttrSet[k]; !ok {
				exclAttrSet[k] = 1
			}
		}
	}

	exclAttrLst = base.ConvertToParamAttributes(exclAttrSet, subAtPresent)

	return exclAttrLst
}

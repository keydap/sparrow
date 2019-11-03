// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	logger "github.com/juju/loggo"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddy/caddymain"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/provider"
	"sparrow/schema"
	"sparrow/utils"
	"strconv"
	"strings"
	"time"
)

var log logger.Logger

var TENANT_HEADER = "X-Sparrow-Domain"
var TENANT_COOKIE = "SD"
var SCIM_JSON_TYPE = "application/scim+json; charset=UTF-8"
var JSON_TYPE = "application/json; charset=UTF-8"
var FORM_URL_ENCODED_TYPE = "application/x-www-form-urlencoded"

const SSO_COOKIE = "KSPAX" // Keydap Sparrow Auth X (X -> all the authenticated users)
const PARAM_REDIRECT_TO = "redirectTo"

var API_BASE = "/v2"       // NO slash at the end
var OAUTH_BASE = "/oauth2" // NO slash at the end
var SAML_BASE = "/saml"    // NO slash at the end
var commaByte = []byte{','}
var fiveMin = int64(5 * 60)

func init() {
	log = logger.GetLogger("sparrow.net")
}

type httpContext struct {
	w  http.ResponseWriter
	r  *http.Request
	pr *provider.Provider
	*base.OpContext
}

type muxHandler struct {
	router *mux.Router
	next   httpserver.Handler
}

func (mh muxHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	mh.router.ServeHTTP(w, r)
	return 0, nil
}

func (sp *Sparrow) startHttp() {
	srvConf := sp.srvConf
	hostAddr := "0.0.0.0:" + strconv.Itoa(srvConf.HttpPort)
	log.Infof("Starting http server(%d) %s", srvConf.ServerId, hostAddr)
	caddy.AppName = "Sparrow Identity Server"
	caddy.AppVersion = SparrowVersion

	tlsDirective := ""
	if srvConf.Https {
		tlsDirective = "tls " + srvConf.CertFile + " " + srvConf.PrivKeyFile
		sp.homeUrl = "https://" + srvConf.IpAddress
	} else {
		sp.homeUrl = "http://" + srvConf.IpAddress
	}

	if srvConf.HttpPort != 80 && srvConf.HttpPort != 443 {
		sp.homeUrl += ":" + strconv.Itoa(srvConf.HttpPort)
	}

	//fmt.Println("registering sparrow plugin")
	directiveName := "sparrow-" + strings.ToLower(utils.NewRandShaStr()[0:7]) // generating a random name so that two caddy instances can be started from replication tests
	httpserver.RegisterDevDirective(directiveName, "startup")
	caddy.RegisterPlugin(directiveName, caddy.Plugin{
		ServerType: "http",
		Action:     sp.setup,
	})

	caddyFile := fmt.Sprintf("%s\n%s\n%s", hostAddr, directiveName, tlsDirective)
	input := caddy.CaddyfileInput{
		Contents:       []byte(caddyFile),
		Filepath:       "sparrow",
		ServerTypeName: "http",
	}

	caddymain.EnableTelemetry = false // disables Caddy's telemetry
	i, err := caddy.Start(input)
	if err != nil {
		panic(err)
	}

	logUrls(sp.homeUrl)

	sp.instance = i
	sp.instance.Wait()
}

func (sp *Sparrow) stopHttp() {
	sp.instance.Stop() // first stop the HTTP server to prevent incoming request processing
	for _, pr := range sp.providers {
		pr.Close()
	}

	for _, p := range sp.peers {
		err := sp.rl.AddReplicationPeer(p)
		if err != nil {
			log.Warningf("%#v", err)
		}
	}

	sp.rl.Close()
	log.Debugf("Stopped HTTP server with id %d", sp.srvConf.ServerId)
}

func (sp *Sparrow) setup(c *caddy.Controller) error {
	router := mux.NewRouter()
	router.StrictSlash(true)
	router.HandleFunc("/about", serveVersionInfo).Methods("GET")
	router.HandleFunc("/", serveVersionInfo).Methods("GET")

	// for serving the admin dashboard UI assets
	fs := http.FileServer(http.Dir(sp.homeDir + "/ui"))
	sp.uiHandler = http.StripPrefix("/ui", fs)
	router.PathPrefix("/ui").Methods("GET").HandlerFunc(sp.serveUI)

	// scim requests
	scimRouter := router.PathPrefix(API_BASE).Subrouter()

	scimRouter.HandleFunc("/directLogin", sp.directLogin).Methods("POST")
	//scimRouter.HandleFunc("/revoke", handleRevoke).Methods("DELETE")
	scimRouter.HandleFunc("/Me", sp.selfServe).Methods("GET")
	scimRouter.HandleFunc("/pubkeyOptions", sp.pubKeyOptions).Methods("GET")
	scimRouter.HandleFunc("/registerPubkey", sp.registerPubKey).Methods("POST")
	scimRouter.HandleFunc("/deletePubkey/{id}", sp.deletePubKey).Methods("DELETE")
	scimRouter.HandleFunc("/logout", sp.handleLogout).Methods("POST")

	// generic service provider methods
	scimRouter.HandleFunc("/ServiceProviderConfigs", sp.getSrvProvConf).Methods("GET")
	scimRouter.HandleFunc("/DomainConfig", sp.handleDomainConf).Methods("GET", "PATCH") // Sparrow specific endpoint
	scimRouter.HandleFunc("/Templates", sp.handleTemplateConf).Methods("GET", "PUT")    // Sparrow specific endpoint
	scimRouter.HandleFunc("/ResourceTypes", sp.getResTypes).Methods("GET")
	scimRouter.HandleFunc("/Schemas", sp.getSchemas).Methods("GET")
	scimRouter.HandleFunc("/Bulk", bulkUpdate).Methods("POST")

	// root level search
	scimRouter.HandleFunc("/.search", sp.handleResRequest).Methods("POST")
	// for group management, Sparrow specific method, not a SCIM standard
	scimRouter.HandleFunc("/ModifyGroupsOfUser", sp.handleResRequest).Methods("POST")

	// register routes for each resourcetype endpoint
	// FIXME fix the routes with regex to ignore trailing / chars
	for _, p := range sp.providers {
		for _, rt := range p.RsTypes {
			scimRouter.HandleFunc("/ResourceTypes/"+rt.Name, sp.getResTypes).Methods("GET")

			scimRouter.HandleFunc(rt.Endpoint, sp.handleResRequest).Methods("POST")
			scimRouter.HandleFunc(rt.Endpoint, sp.handleResRequest).Methods("GET")
			scimRouter.HandleFunc(rt.Endpoint, sp.handleResRequest).Methods("GET").Queries("filter", "")
			scimRouter.HandleFunc(rt.Endpoint, sp.handleResRequest).Methods("GET").Queries("attributes", "")
			scimRouter.HandleFunc(rt.Endpoint, sp.handleResRequest).Methods("GET").Queries("excludedAttributes", "")
			scimRouter.HandleFunc(rt.Endpoint+"/.search", sp.handleResRequest).Methods("POST")
			scimRouter.HandleFunc(rt.Endpoint+"/{id}", sp.handleResRequest).Methods("PUT", "PATCH", "DELETE")
			scimRouter.HandleFunc(rt.Endpoint+"/{id}", sp.handleResRequest).Methods("GET")
			scimRouter.HandleFunc(rt.Endpoint+"/{id}", sp.handleResRequest).Methods("GET").Queries("attributes", "")
			scimRouter.HandleFunc(rt.Endpoint+"/{id}", sp.handleResRequest).Methods("GET").Queries("excludedAttributes", "")
		}

		for _, sc := range p.Schemas {
			scimRouter.HandleFunc("/Schemas/"+sc.Id, sp.getSchemas).Methods("GET")
		}
	}

	// OAuth2 requests
	oauthRouter := router.PathPrefix(OAUTH_BASE).Subrouter()
	// match /authorize with any number of query parameters
	oauthRouter.HandleFunc("/authorize", sp.authorize).Methods("GET", "POST").MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		return true
	})

	oauthRouter.HandleFunc("/token", sp.sendToken).Methods("POST")
	oauthRouter.HandleFunc("/consent", sp.verifyConsent).Methods("POST")

	// SAMLv2 requests
	samlRouter := router.PathPrefix(SAML_BASE).Subrouter()
	samlRouter.HandleFunc("/idp/meta/{domain}", sp.serveIdpMetadata).Methods("GET")
	samlRouter.HandleFunc("/idp/logout", sp.handleSamlLogout).Methods("GET", "POST")
	// match /saml with any number of query parameters
	samlRouter.HandleFunc("/idp", sp.handleSamlReq).Methods("GET", "POST").MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		return true
	})

	router.HandleFunc("/login", sp.showLogin).Methods("GET")
	router.HandleFunc("/verifyPassword", sp.verifyPassword).Methods("POST")
	router.HandleFunc("/changePassword", sp.handleChangePasswordReq).Methods("GET")
	router.HandleFunc("/registerTotp", sp.registerTotp).Methods("POST")
	router.HandleFunc("/webauthn", sp.sendWebauthnAuthReq).Methods("POST")
	router.HandleFunc("/webauthnVerifyCred", sp.webauthnVerifyCred).Methods("POST")
	router.HandleFunc("/redirect", sp.redirectAfterAuth).Methods("GET", "POST")

	router.PathPrefix("/repl/").HandlerFunc(sp.replHandler)

	domainsRouter := router.PathPrefix("/domains").Subrouter()
	domainsRouter.HandleFunc("/dlc", sp.handleDomainLifecycle).Methods("POST")

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return muxHandler{router: router, next: next}
	})

	//if srvConf.Https {
	//	homeUrl = "https://" + hostAddr
	//	logUrls()
	//	server = &http.Server{Addr: hostAddr, Handler: router}
	//	server.ListenAndServeTLS(srvConf.CertFile, srvConf.PrivKeyFile)
	//} else {
	//	homeUrl = "http://" + hostAddr
	//	logUrls()
	//	server = &http.Server{Addr: hostAddr, Handler: router}
	//	server.ListenAndServe()
	//}

	return nil
}

func logUrls(homeUrl string) {
	log.Infof("SCIM API is accessible at %s", homeUrl+API_BASE)
	log.Infof("OAuth2 and OpenIDConnect API is accessible at %s", homeUrl+OAUTH_BASE)
	log.Infof("SAML2 API is accessible at %s", homeUrl+SAML_BASE)
}

func bulkUpdate(w http.ResponseWriter, r *http.Request) {
}

func searchResource(hc *httpContext) {
	log.Debugf("endpoint %s", hc.Endpoint)
	pos := strings.LastIndex(hc.Endpoint, "/")

	err := hc.r.ParseForm()
	if err != nil {
		writeError(hc.w, err)
		return
	}

	attributes := hc.r.Form.Get("attributes")
	exclAttributes := hc.r.Form.Get("excludedAttributes")

	if pos > 0 {
		rid := hc.Endpoint[pos+1:]
		log.Debugf("Searching for the resource with ID %s", rid)
		rtByPath := hc.pr.RtPathMap[hc.Endpoint[0:pos]]

		getCtx := base.GetContext{Rid: rid, Rt: rtByPath, OpContext: hc.OpContext}
		getCtx.ParamAttrs = attributes
		getCtx.ParamExclAttrs = exclAttributes
		rs, err := hc.pr.GetResource(&getCtx)
		if err != nil {
			writeError(hc.w, err)
			return
		}

		ifMatch := hc.r.Header.Get("If-Match")
		if len(ifMatch) != 0 {
			version := rs.GetVersion()
			if strings.Compare(ifMatch, version) == 0 {
				hc.w.Header().Add("Etag", version)
				hc.w.WriteHeader(http.StatusNotModified)
				return
			}
		}

		var jsonData []byte

		if len(attributes) != 0 && len(exclAttributes) != 0 {
			err := base.NewBadRequestError("The parameters 'attributes' and 'excludedAttributes' cannot be set for fetching a resource")
			writeError(hc.w, err)
			return
		}

		attrLst, exclAttrLst := parseAttrParams(attributes, exclAttributes, rtByPath)
		rp := hc.OpContext.Session.EffPerms[rtByPath.Name]
		if attrLst != nil {
			if !rp.ReadPerm.AllowAll {
				filterAllowedAttrs(rp.ReadPerm.AllowAttrs, attrLst)
			}
			jsonData = rs.FilterAndSerialize(attrLst, true)
		} else {
			if !rp.ReadPerm.AllowAll {
				allow := base.CloneAtParamMap(rp.ReadPerm.AllowAttrs)
				filterExcludedAttrs(allow, exclAttrLst)
				jsonData = rs.FilterAndSerialize(allow, true)
			} else {
				jsonData = rs.FilterAndSerialize(exclAttrLst, false)
			}
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

	sr := &base.SearchRequest{}
	sr.Filter = hc.r.Form.Get("filter")
	sr.Attributes = attributes
	sr.ExcludedAttributes = exclAttributes

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

	attrByRtName := make(map[string][]map[string]*base.AttributeParam)
	for _, rt := range rTypes {
		rp := hc.OpContext.Session.EffPerms[rt.Name]
		if rp == nil {
			continue
		} else if !rp.ReadPerm.AllowAll && rp.ReadPerm.AllowAttrs == nil {
			continue
		}

		attrLst, exclAttrLst := parseAttrParams(sr.Attributes, sr.ExcludedAttributes, rt)

		if attrLst != nil {
			if !rp.ReadPerm.AllowAll {
				filterAllowedAttrs(rp.ReadPerm.AllowAttrs, attrLst)
			}
		} else {
			if !rp.ReadPerm.AllowAll {
				allow := base.CloneAtParamMap(rp.ReadPerm.AllowAttrs)
				filterExcludedAttrs(allow, exclAttrLst)
				attrLst = allow
				exclAttrLst = nil
			}
		}

		attrByRtName[rt.Name] = []map[string]*base.AttributeParam{attrLst, exclAttrLst}
	}

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

		rt := rs.GetType()
		arr := attrByRtName[rt.Name]
		// no read permission for this ResourceType
		if arr == nil {
			continue
		}

		attrLst := arr[0]
		exclAttrLst := arr[1]

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

func modifyGroupsOfUser(hc *httpContext) {
	defer hc.r.Body.Close()
	dec := json.NewDecoder(hc.r.Body)
	var autg base.ModifyGroupsOfUserRequest

	err := dec.Decode(&autg)
	if err != nil {
		log.Debugf("%#v", err)
		err = base.NewBadRequestError(err.Error())
		writeError(hc.w, err)
		return
	}

	autg.UserVersion = hc.r.Header.Get("If-Match")
	autg.OpContext = hc.OpContext

	user, err := hc.pr.ModifyGroupsOfUser(autg)
	if err != nil {
		log.Debugf("%#v", err)
		writeError(hc.w, err)
		return
	}

	writeCommonHeaders(hc.w)
	header := hc.w.Header()
	header.Add("Location", hc.r.RequestURI+"/"+autg.UserRid)
	header.Add("Etag", user.GetVersion())
	hc.w.WriteHeader(http.StatusCreated)
	d := user.Serialize()
	hc.w.Write(d)
	log.Debugf("Successfully added user to the given groups")
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
	err = hc.pr.CreateResource(&createCtx)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	rid := rs.GetId()
	writeCommonHeaders(hc.w)
	header := hc.w.Header()
	header.Add("Location", hc.r.RequestURI+"/"+rid)
	header.Add("Etag", rs.GetVersion())
	hc.w.WriteHeader(http.StatusCreated)
	d := rs.Serialize()
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
	replaceCtx.Rt = rsType
	replaceCtx.IfMatch = hc.r.Header.Get("If-Match")
	err = hc.pr.Replace(&replaceCtx)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	writeCommonHeaders(hc.w)
	header := hc.w.Header()
	header.Add("Location", hc.r.RequestURI+"/"+rid)
	header.Add("Etag", replaceCtx.Res.GetVersion())
	hc.w.WriteHeader(http.StatusOK)
	hc.w.Write(replaceCtx.Res.Serialize())
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

	patchReq.IfMatch = hc.r.Header.Get("If-Match")
	patchCtx := base.PatchContext{Rid: rid, Rt: rtByPath, Pr: patchReq, OpContext: hc.OpContext}
	err = hc.pr.Patch(&patchCtx)
	if err != nil {
		writeError(hc.w, err)
		return
	}

	patchedRes := patchCtx.Res
	writeCommonHeaders(hc.w)
	header := hc.w.Header()
	header.Add("Location", hc.r.RequestURI+"/"+rid)
	header.Add("Etag", patchedRes.GetVersion())

	if reqAttr == "" {
		hc.w.WriteHeader(http.StatusNoContent)
	} else {
		attrLst := parseAttrParam(reqAttr, rtByPath)
		rp := hc.OpContext.Session.EffPerms[rtByPath.Name]
		if attrLst != nil {
			if !rp.ReadPerm.AllowAll {
				filterAllowedAttrs(rp.ReadPerm.AllowAttrs, attrLst)
			}

			// send no content if none of the attributes are allowed to be read
			if len(attrLst) == 0 {
				hc.w.WriteHeader(http.StatusNoContent)
			} else {
				data := patchedRes.FilterAndSerialize(attrLst, true)
				hc.w.WriteHeader(http.StatusOK)
				hc.w.Write(data)
			}
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

func (sp *Sparrow) getSrvProvConf(w http.ResponseWriter, r *http.Request) {
	pr, err := getPrFromParam(r, sp)
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

func getPrFromParam(r *http.Request, sp *Sparrow) (pr *provider.Provider, err error) {
	// NO NEED TO parse Form cause the domain ID will be either in the
	// Header or in a Cookie
	//r.ParseForm()
	domain := ""
	domainCookie, _ := r.Cookie(TENANT_COOKIE)
	if domainCookie != nil {
		domain = domainCookie.Value
	}

	if len(domain) == 0 {
		domain = r.Header.Get(TENANT_HEADER)
	}

	/* no longer supported
	if len(domain) == 0 {
		domain = r.Form.Get("d")
	}*/

	domain = strings.ToLower(domain)

	if len(domain) == 0 {
		domain = sp.srvConf.DefaultDomain
	}

	pr = sp.providers[domain]
	if pr == nil {
		se := base.NewNotFoundError(fmt.Sprintf("No domain '%s' found", domain))
		return nil, se
	}
	return pr, nil
}

func (sp *Sparrow) getResTypes(w http.ResponseWriter, r *http.Request) {
	pr, err := getPrFromParam(r, sp)
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

func (sp *Sparrow) getSchemas(w http.ResponseWriter, r *http.Request) {
	pr, err := getPrFromParam(r, sp)
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

func (sp *Sparrow) handleLogout(w http.ResponseWriter, r *http.Request) {
	opCtx, err := createOpCtx(r, sp)
	if err != nil {
		writeError(w, err)
		return
	}

	pr := sp.providers[opCtx.Session.Domain]
	code := 404
	deleted := false
	if opCtx.Sso {
		log.Debugf("deleting session of %s of the domain %s", opCtx.Session.Sub, pr.Name)
		deleted = pr.DeleteSsoSession(opCtx)
	} else {
		log.Debugf("deleting OAuth token of %s of the domain %s", opCtx.Session.Sub, pr.Name)
		deleted = pr.DeleteOauthSession(opCtx)
	}

	if deleted {
		code = 200
		if opCtx.Sso {
			_logoutSessionApps(pr, opCtx)
		}
	}
	w.WriteHeader(code)
}

func (sp *Sparrow) selfServe(w http.ResponseWriter, r *http.Request) {
	log.Debugf("-------------------- Headers received on /Me -----------\n%#v\n--------------------------------", r.Header)

	opCtx, err := createOpCtx(r, sp)
	if err != nil {
		writeError(w, err)
		return
	}

	pr := sp.providers[opCtx.Session.Domain]
	log.Debugf("handling %s request on %s for the domain %s", r.Method, r.RequestURI, pr.Name)

	//TODO add additional checks for preventing CSRF

	switch r.Method {
	case http.MethodGet:
		ses := opCtx.Session
		user, err := pr.GetUserById(opCtx.Session.Sub)
		if err != nil {
			writeError(w, err)
			return
		}

		rt := pr.RsTypes["User"]
		attrs := parseAttrParam("*", rt)
		jsonMap := user.ToJsonObject(attrs)
		jsonMap["perms"] = ses.EffPerms
		jsonMap["domain"] = ses.Domain

		var keys []*base.SecurityKey
		keysMap := user.AuthData.Skeys
		if keysMap != nil {
			keys = make([]*base.SecurityKey, 0)
			for _, v := range keysMap {
				keys = append(keys, v)
			}
		} else {
			keys = make([]*base.SecurityKey, 0)
		}
		jsonMap["securitykeys"] = keys

		apps := make([]map[string]string, 0) // an array of allowed apps for this user, each map holds application name, home page URL and icon

		clients := pr.GetAllClients()
		for _, cl := range clients {
			for role, _ := range cl.GroupIds {
				if _, ok := ses.Roles[role]; ok {
					tmp := make(map[string]string)
					tmp["name"] = cl.Name
					tmp["url"] = cl.HomeUrl
					tmp["icon"] = cl.Icon
					apps = append(apps, tmp)
					break
				}
			}
		}

		jsonMap["apps"] = apps
		data, _ := json.Marshal(jsonMap)

		writeCommonHeaders(w)
		w.Write(data)
	}
}

func serveVersionInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte(aboutStr))
}

func (sp *Sparrow) serveUI(w http.ResponseWriter, r *http.Request) {
	//static assets
	if strings.HasSuffix(r.URL.Path, ".css") || strings.HasSuffix(r.URL.Path, ".js") {
		sp.uiHandler.ServeHTTP(w, r)
		return
	}

	cookie, err := r.Cookie(SSO_COOKIE)
	if err != nil {
		addUiRedirectTo(r)
		sp.showLogin(w, r)
		return
	}

	pr, err := getPrFromParam(r, sp)
	if pr == nil {
		addUiRedirectTo(r)
		sp.showLogin(w, r)
		return
	}

	session := pr.GetSsoSession(cookie.Value)

	if session == nil {
		log.Debugf("no session is found with the cookie %v", cookie)
		addUiRedirectTo(r)
		sp.showLogin(w, r)
		return
	}

	if session.IsExpired() {
		log.Debugf("Expired session %v", cookie)
		addUiRedirectTo(r)
		sp.showLogin(w, r)
		return
	}

	sp.uiHandler.ServeHTTP(w, r)
}

func addUiRedirectTo(r *http.Request) {
	r.ParseForm()
	r.Form.Add(PARAM_REDIRECT_TO, "/ui")
}

func (sp *Sparrow) directLogin(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	ar := base.AuthRequest{}
	data, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(data, &ar)
	if err != nil {
		e := base.NewBadRequestError("Invalid authentication request " + err.Error())
		writeError(w, e)
		return
	}

	ar.ClientIP = utils.GetRemoteAddr(r)
	normDomain := strings.ToLower(ar.Domain)
	if len(normDomain) == 0 {
		normDomain = sp.srvConf.DefaultDomain
	}
	pr := sp.providers[normDomain]

	if pr == nil {
		e := base.NewBadRequestError("Invalid domain name " + ar.Domain)
		writeError(w, e)
		return
	}

	ar.Domain = normDomain
	// TODO directlogin MUST be deprecated after introducing OTP
	lr := pr.Authenticate(ar)
	if lr.Status != base.LOGIN_SUCCESS {
		writeError(w, base.NewBadRequestError("Invalid credentials"))
		return
	}

	token := pr.GenSessionForUser(lr.User)
	pr.StoreOauthSession(token)

	log.Debugf("Issued token %s by %s", token.Jti, ar.Domain)
	// write the token
	headers := w.Header()
	headers.Add("Content-Type", "text/plain")
	w.Write([]byte(token.Jti))
}

func (sp *Sparrow) handleResRequest(w http.ResponseWriter, r *http.Request) {
	log.Debugf("-------------------- Headers received-----------\n%#v\n--------------------------------", r.Header)

	opCtx, err := createOpCtx(r, sp)
	if err != nil {
		writeError(w, err)
		return
	}

	pr := sp.providers[opCtx.Session.Domain]
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
		} else if strings.HasSuffix(hc.Endpoint, "/ModifyGroupsOfUser") {
			modifyGroupsOfUser(hc)
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

	if opCtx.UpdatedSession {
		setSsoCookie(pr, opCtx.Session, w)
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

func createOpCtx(r *http.Request, sp *Sparrow) (opCtx *base.OpContext, err error) {
	pr, err := getPrFromParam(r, sp)

	if err != nil {
		return nil, err
	}

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

	session, err := parseToken(authzHeader, opCtx, pr)
	if err != nil {
		return nil, err
	}

	opCtx.Session = session
	if opCtx.Sso {
		// update the last accessed time of the session
		now := time.Now().Unix()
		if (now - session.LastAccAt) >= fiveMin {
			session.LastAccAt = now
			pr.StoreSsoSession(session)
			opCtx.UpdatedSession = true
		}
	}
	opCtx.ClientIP = utils.GetRemoteAddr(r)
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

func parseAttrParam(attrParam string, rt *schema.ResourceType) map[string]*base.AttributeParam {
	attrSet, subAtPresent := base.SplitAttrCsv(attrParam, rt)
	if attrSet != nil {
		// the mandatory attributes that will always be returned
		for k, _ := range rt.AtsAlwaysRtn {
			attrSet[k] = 1
		}

		for k, _ := range rt.AtsNeverRtn {
			if _, ok := attrSet[k]; ok {
				delete(attrSet, k)
			}
		}

		// sort the names and eliminate redundant values, for example "name, name.familyName" will be reduced to name
		return base.ConvertToParamAttributes(attrSet, subAtPresent)
	}

	return nil
}

func parseToken(token string, opCtx *base.OpContext, pr *provider.Provider) (session *base.RbacSession, err error) {
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

func (sp *Sparrow) keyFunc(jt *jwt.Token) (key interface{}, err error) {
	domain := jt.Header["d"]
	if domain == nil {
		return nil, jwt.NewValidationError("Missing domain attribute 'd' in the header", jwt.ValidationErrorMalformed)
	}

	prv := sp.providers[domain.(string)]
	return prv.Cert.PublicKey, nil
}

func parseAttrParams(attributes string, excludedAttributes string, rt *schema.ResourceType) (attrLst map[string]*base.AttributeParam, exclAttrLst map[string]*base.AttributeParam) {
	if len(attributes) != 0 {
		attrLst = parseAttrParam(attributes, rt)
	} else {
		exclAttrLst = parseExcludedAttrs(excludedAttributes, rt)
	}

	return attrLst, exclAttrLst
}

func parseExcludedAttrs(excludedAttributes string, rt *schema.ResourceType) (exclAttrLst map[string]*base.AttributeParam) {
	exclAttrSet, subAtPresent := base.SplitAttrCsv(excludedAttributes, rt)

	if exclAttrSet == nil {
		// in this case compute the never return attribute list
		exclAttrSet = make(map[string]int)
		subAtPresent = true
	}

	// the mandatory attributes cannot be excluded
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

	exclAttrLst = base.ConvertToParamAttributes(exclAttrSet, subAtPresent)

	return exclAttrLst
}

func filterAllowedAttrs(allow map[string]*base.AttributeParam, attrLst map[string]*base.AttributeParam) {
	for k, v := range attrLst {
		existingV, ok := allow[k]
		if !ok {
			delete(attrLst, k)
		} else {
			//FIXME what if all sub-attributes are manually specified
			// e.g email.type, value, display, primary - this case needs to be handled in searchutil.go's ConvertToParamAttributes
			if len(existingV.SubAts) != 0 { // check if only certain sub-attributes are allowed
				if len(v.SubAts) == 0 { // if the request violates it then remove
					delete(attrLst, k)
				} else { // keep only allowed sub-attributes
					for subK, _ := range v.SubAts {
						if _, ok := existingV.SubAts[subK]; !ok {
							delete(v.SubAts, subK)
						}
					}
				}
			}
		}
	}
}

func filterExcludedAttrs(allow map[string]*base.AttributeParam, exclAttrLst map[string]*base.AttributeParam) {
	for k, v := range exclAttrLst {
		if len(v.SubAts) == 0 {
			delete(allow, k)
		} else {
			existingV, ok := allow[k]
			if ok {
				for subK, _ := range v.SubAts {
					if _, ok := existingV.SubAts[subK]; !ok {
						delete(existingV.SubAts, subK)
					}
				}

				if len(existingV.SubAts) == 0 {
					delete(allow, k)
				}
			}
		}
	}
}

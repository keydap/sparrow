package http

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sparrow/scim/base"
	"sparrow/scim/provider"
	"sparrow/scim/schema"
	"sparrow/scim/utils"
	"strconv"
	"strings"
)

var log logger.Logger

var providers = make(map[string]*provider.Provider)

var DIR_PERM os.FileMode = 0744 //rwxr--r--

var TENANT_HEADER = "X-Sparrow-Tenant-Id"
var SCIM_JSON_TYPE = "application/scim+json"
var API_BASE = "/v2" // NO slash at the end
var commaByte = []byte{','}

func init() {
	log = logger.GetLogger("sparrow.scim.http")
}

type httpContext struct {
	w  http.ResponseWriter
	r  *http.Request
	pr *provider.Provider
	*base.OpContext
}

func Start(srvHome string) {
	log.Debugf("Checking server home directory %s", srvHome)
	utils.CheckAndCreate(srvHome)

	domainsDir := filepath.Join(srvHome, "domains")
	log.Debugf("Checking server domains directory %s", domainsDir)
	utils.CheckAndCreate(domainsDir)

	loadProviders(domainsDir)

	cwd, _ := os.Getwd()
	fmt.Println("Current working directory: ", cwd)

	if len(providers) == 0 {
		createDefaultDomain(domainsDir)
	}

	log.Debugf("Starting server...")

	router := mux.NewRouter()
	router.StrictSlash(true)

	// scim requests
	scimRouter := router.PathPrefix(API_BASE).Subrouter()

	scimRouter.HandleFunc("/Me", handleResRequest).Methods("GET", "POST", "PUT", "PATCH", "DELETE")

	// generic service provider methods
	scimRouter.HandleFunc("/ServiceProviderConfig", getServProvConf).Methods("GET")
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

	http.ListenAndServe(":9090", router)
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

		rs, err := hc.pr.GetResource(hc.OpContext, rid, rtByPath)
		if err != nil {
			writeError(hc, err)
			return
		}

		writeCommonHeaders(hc.w, hc.pr)
		hc.w.Header().Add("Location", hc.r.RequestURI+"/"+rid)
		hc.w.WriteHeader(http.StatusOK)
		hc.w.Write(rs.Serialize())
		log.Debugf("Found the resource with ID %s", rid)
		return
	}

	rtByPath := hc.pr.RtPathMap[hc.Endpoint]

	err := hc.r.ParseForm()
	if err != nil {
		writeError(hc, err)
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
		writeError(hc, err)
		return
	}

	sr := &base.SearchRequest{}

	err := json.NewDecoder(hc.r.Body).Decode(sr)
	if err != nil {
		e := base.NewBadRequestError("Invalid search request " + err.Error())
		writeError(hc, e)
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
			writeError(hc, err)
			return
		}
	}

	if len(sr.Attributes) != 0 && len(sr.ExcludedAttributes) != 0 {
		err := base.NewBadRequestError("The parameters 'attributes' and 'excludedAttributes' cannot be set in a signle request")
		writeError(hc, err)
		return
	}

	filter, err := base.ParseFilter(paramFilter)
	if err != nil {
		se := base.NewBadRequestError(err.Error())
		se.ScimType = base.ST_INVALIDFILTER
		writeError(hc, se)
		return
	}

	err = base.FixSchemaUris(filter, rTypes)
	if err != nil {
		se := base.NewBadRequestError(err.Error())
		se.ScimType = base.ST_INVALIDFILTER
		writeError(hc, se)
		return
	}

	var attrLst []*base.AttributeParam
	var exclAttrLst []*base.AttributeParam

	if len(sr.Attributes) != 0 {
		attrSet, subAtPresent := base.SplitAttrCsv(sr.Attributes, rTypes)
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
			attrLst = base.ConvertToParamAttributes(attrSet, subAtPresent)
		}
	} else {
		exclAttrSet, subAtPresent := base.SplitAttrCsv(sr.ExcludedAttributes, rTypes)

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
	}

	sc := &base.SearchContext{}
	sc.Filter = filter
	sc.OpContext = hc.OpContext
	sc.ResTypes = rTypes

	outPipe := make(chan *base.Resource, 0)

	go hc.pr.Search(sc, outPipe)

	writeCommonHeaders(hc.w, hc.pr)
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
	rs, err := base.ParseResource(hc.pr.RsTypes, hc.pr.Schemas, hc.r.Body)
	if err != nil {
		writeError(hc, err)
		return
	}

	rtByPath := hc.pr.RtPathMap[hc.Endpoint]
	rsType := rs.GetType()
	if rsType != rtByPath {
		// return bad request error
		err = base.NewBadRequestError(fmt.Sprintf("Resource data of type %s is sent to the wrong endpoint %s", rsType.Name, hc.r.RequestURI))
		writeError(hc, err)
		return
	}

	hc.OpContext.Rs = rs
	insertedRs, err := hc.pr.CreateResource(hc.OpContext)
	if err != nil {
		writeError(hc, err)
		return
	}

	rid := insertedRs.GetId()
	writeCommonHeaders(hc.w, hc.pr)
	hc.w.Header().Add("Location", hc.r.RequestURI+"/"+rid)
	hc.w.WriteHeader(http.StatusCreated)
	hc.w.Write(insertedRs.Serialize())
	log.Debugf("Successfully inserted the resource with ID %s", rid)
}

func replaceResource(w http.ResponseWriter, r *http.Request, pr *provider.Provider) {
}

func modifyResource(w http.ResponseWriter, r *http.Request, pr *provider.Provider) {
}

func deleteResource(hc *httpContext) {
	log.Debugf(hc.Endpoint)
	pos := strings.LastIndex(hc.Endpoint, "/")
	pos++
	if pos >= len(hc.Endpoint) {
		writeCommonHeaders(hc.w, hc.pr)
		hc.w.WriteHeader(http.StatusBadRequest)
		detail := "Invalid delete request, missing resource ID"
		log.Debugf(detail)
		err := base.NewBadRequestError(detail)
		hc.w.Write(err.Serialize())
		return
	}

	rid := hc.Endpoint[pos:]
	rtByPath := hc.pr.RtPathMap[hc.Endpoint[0:pos-1]]
	err := hc.pr.DeleteResource(hc.OpContext, rid, rtByPath)
	if err != nil {
		writeError(hc, err)
		return
	}

	hc.w.WriteHeader(http.StatusNoContent)
	log.Debugf("Successfully deleted the resource with ID %s", rid)
}

func getServProvConf(w http.ResponseWriter, r *http.Request) {
	pr := getProv(createOpCtx(r))
	log.Debugf("Sending service provider configuration of domain %s", pr.Name)

	data, err := pr.GetConfigJson()
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
	} else {
		writeCommonHeaders(w, pr)
		w.Write(data)
	}
}

func getResTypes(w http.ResponseWriter, r *http.Request) {
	oc := createOpCtx(r)
	pr := getProv(oc)

	var data string
	tokens := strings.SplitAfter(oc.Endpoint, "ResourceTypes/")
	if len(tokens) == 2 {
		log.Debugf("Sending resource type %s of the domain %s", tokens[1], pr.Name)
		rt := pr.RsTypes[tokens[1]]
		if rt == nil {
			se := base.NewNotFoundError("ResourceType " + tokens[1] + " does not exist")
			writeCommonHeaders(w, pr)
			w.WriteHeader(se.Code())
			w.Write(se.Serialize())
			return
		}

		data = rt.Text
	} else {
		log.Debugf("Sending resource types of the domain %s", pr.Name)
		data = pr.GetResTypeJsonArray()
	}

	writeCommonHeaders(w, pr)
	w.Write([]byte(data))
}

func getSchemas(w http.ResponseWriter, r *http.Request) {
	oc := createOpCtx(r)
	pr := getProv(oc)

	var data string
	tokens := strings.SplitAfter(oc.Endpoint, "Schemas/")
	if len(tokens) == 2 {
		log.Debugf("Sending schema %s of the domain %s", tokens[1], pr.Name)
		sc := pr.Schemas[tokens[1]]
		if sc == nil {
			se := base.NewNotFoundError("Schema " + tokens[1] + " does not exist")
			writeCommonHeaders(w, pr)
			w.WriteHeader(se.Code())
			w.Write(se.Serialize())
			return
		}

		data = sc.Text
	} else {
		log.Debugf("Sending schemas of the domain %s", pr.Name)
		data = pr.GetSchemaJsonArray()
	}

	writeCommonHeaders(w, pr)
	w.Write([]byte(data))
}

func selfServe(w http.ResponseWriter, r *http.Request) {
}

func handleResRequest(w http.ResponseWriter, r *http.Request) {
	opCtx := createOpCtx(r)
	pr := getProv(opCtx)
	log.Debugf("handling %s request on %s for the domain %s", r.Method, r.RequestURI, pr.Name)

	hc := &httpContext{w, r, pr, opCtx}

	switch r.Method {
	case http.MethodGet:
		searchResource(hc)

	case http.MethodPost:
		if strings.HasSuffix(hc.Endpoint, "/.search") {
			searchWithSearchRequest(hc)
		} else {
			createResource(hc)
		}

	case http.MethodDelete:
		deleteResource(hc)
	}
}

func createOpCtx(r *http.Request) *base.OpContext {
	tenantId := r.Header.Get(TENANT_HEADER)
	if len(tenantId) == 0 {
		// testing purpose
		tenantId = "example.com"
	}

	opCtx := &base.OpContext{}
	opCtx.ClientIP = r.RemoteAddr
	opCtx.Tenant = strings.ToLower(tenantId)

	parts := strings.Split(r.URL.Path, API_BASE)
	if len(parts) == 2 { // extract the part after API_BASE
		opCtx.Endpoint = parts[1]
	} else {
		opCtx.Endpoint = r.RequestURI
	}

	return opCtx
}

func getProv(opCtx *base.OpContext) *provider.Provider {
	return providers[opCtx.Tenant]
}

func writeCommonHeaders(w http.ResponseWriter, pr *provider.Provider) {
	headers := w.Header()
	headers.Add("Content-Type", SCIM_JSON_TYPE)
	headers.Add(TENANT_HEADER, pr.Name)
}

func loadProviders(domainsDir string) {
	log.Infof("Loading domains")
	dir, err := os.Open(domainsDir)
	if err != nil {
		err = fmt.Errorf("Could not open domains directory %s [%s]", domainsDir, err.Error())
		panic(err)
	}

	files, err := dir.Readdir(-1)

	if err != nil {
		err = fmt.Errorf("Could not read domains from directory %s [%s]", domainsDir, err.Error())
		panic(err)
	}

	for _, f := range files {
		if f.IsDir() {
			lDir := filepath.Join(domainsDir, f.Name())
			layout, err := provider.NewLayout(lDir, false)
			if err != nil {
				log.Infof("Could not create a layout from the directory %s [%s]", lDir, err.Error())
			} else {
				lName := layout.Name()
				if _, ok := providers[lName]; ok {
					log.Infof("A provider for the domain %s already loaded, ignoring the domain present at %s", lName, lDir)
					continue
				}

				prv, err := provider.NewProvider(layout)
				if err != nil {
					log.Infof("Could not create a provider for the domain %s [%s]", layout.Name(), err.Error())
				} else {
					providers[lName] = prv
				}
			}
		}
	}

	log.Infof("Loaded providers for %d domains", len(providers))
}

func createDefaultDomain(domainsDir string) {
	log.Infof("Creating default domain")

	defaultDomain := filepath.Join(domainsDir, "example.com")
	layout, err := provider.NewLayout(defaultDomain, true)
	if err != nil {
		panic(err)
	}

	wDir, _ := os.Getwd()
	wDir += "/../resources"

	schemaDir := wDir + "/schemas"
	copyDir(schemaDir, layout.SchemaDir)

	rtDir := wDir + "/types"
	copyDir(rtDir, layout.ResTypesDir)

	confDir := wDir + "/conf"
	copyDir(confDir, layout.ConfDir)

	prv, err := provider.NewProvider(layout)
	if err != nil {
		panic(err)
	}

	providers[layout.Name()] = prv
}

func copyDir(src, dest string) {
	dir, err := os.Open(src)
	if err != nil {
		panic(err)
	}

	defer dir.Close()

	files, err := dir.Readdir(-1)

	if err != nil {
		panic(err)
	}

	for _, f := range files {
		sFile := filepath.Join(src, f.Name())
		tFile := filepath.Join(dest, f.Name())
		if f.IsDir() {
			err = os.Mkdir(tFile, DIR_PERM)
			if err != nil {
				panic(err)
			}
			copyDir(sFile, tFile)
			continue
		}

		data, err := ioutil.ReadFile(sFile)
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(tFile, data, DIR_PERM)

		if err != nil {
			panic(err)
		}
	}
}

func writeError(hc *httpContext, err error) {
	se, ok := err.(*base.ScimError)
	writeCommonHeaders(hc.w, hc.pr)
	if ok {
		hc.w.WriteHeader(se.Code())
		hc.w.Write(se.Serialize())
	} else {
		hc.w.WriteHeader(http.StatusInternalServerError) // unknown error
		unknown := base.NewInternalserverError(err.Error())
		hc.w.Write(unknown.Serialize())
	}
}

package http

import (
	"fmt"
	"github.com/gorilla/mux"
	logger "github.com/juju/loggo"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sparrow/scim/base"
	"sparrow/scim/provider"
	"sparrow/scim/utils"
	"strings"
)

var log logger.Logger

var providers = make(map[string]*provider.Provider)

var DIR_PERM os.FileMode = 0744 //rwxr--r--

var TENANT_HEADER = "X-Sparrow-Tenant-Id"
var SCIM_JSON_TYPE = "application/scim+json"

func init() {
	log = logger.GetLogger("sparrow.scim.http")
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

	// scim requests
	scimRouter := router.PathPrefix("/v2").Subrouter()

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
			scimRouter.HandleFunc(rt.Endpoint, handleResRequest).Methods("GET", "POST")
			scimRouter.HandleFunc(rt.Endpoint+"/.search", handleResRequest).Methods("POST")
			scimRouter.HandleFunc(rt.Endpoint+"/{id}", handleResRequest).Methods("GET", "PUT", "PATCH", "DELETE")
		}
	}

	http.ListenAndServe(":9090", router)
}

func bulkUpdate(w http.ResponseWriter, r *http.Request) {
}

func search(w http.ResponseWriter, r *http.Request, pr *provider.Provider) {
}

func createResource(w http.ResponseWriter, r *http.Request, pr *provider.Provider) {
	rs, err := base.ParseResource(pr.RsTypes, pr.Schemas, r.Body)
	if err != nil {

	}
}

func replaceResource(w http.ResponseWriter, r *http.Request, pr *provider.Provider) {
}

func modifyResource(w http.ResponseWriter, r *http.Request, pr *provider.Provider) {
}

func deleteResource(w http.ResponseWriter, r *http.Request, pr *provider.Provider) {
}

func getServProvConf(w http.ResponseWriter, r *http.Request) {
	pr := getProv(r)
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
	pr := getProv(r)
	log.Debugf("Sending resource types of the domain %s", pr.Name)

	data := pr.GetResTypeJsonArray()

	writeCommonHeaders(w, pr)
	w.Write([]byte(data))
}

func getSchemas(w http.ResponseWriter, r *http.Request) {
	pr := getProv(r)
	log.Debugf("Sending schemas of the domain %s", pr.Name)

	data := pr.GetSchemaJsonArray()
	writeCommonHeaders(w, pr)
	w.Write([]byte(data))
}

func selfServe(w http.ResponseWriter, r *http.Request) {
}

func handleResRequest(w http.ResponseWriter, r *http.Request) {
	pr := getProv(r)
	log.Debugf("handling %s request on %s for the domain %s", r.Method, r.RequestURI, pr.Name)

	switch r.Method {
	case "GET":
		search(w, r, pr)

	case "POST":
		if strings.Contains(r.RequestURI, "/.search") {
			search(w, r, pr)
		} else {
			createResource(w, r, pr)
		}
	}
}

func getProv(r *http.Request) *provider.Provider {
	tenantId := r.Header.Get(TENANT_HEADER)
	if len(tenantId) != 0 {
		return providers[strings.ToLower(tenantId)]
	}

	// testing purpose
	return providers["example.com"]
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

package http

import (
	"fmt"
	logger "github.com/juju/loggo"
	"net/http"
	"os"
	"path/filepath"
	"sparrow/scim/provider"
	"sparrow/scim/utils"
)

var log logger.Logger

var providers = make(map[string]*provider.Provider)

var DIR_PERM os.FileMode = 0744 //rwxr--r--

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

	fmt.Println(os.Getwd())
	if len(providers) == 0 {
		createDefaultDomain(domainsDir)
	}

	log.Debugf("Starting server...")

	http.HandleFunc("/v2/", handleSCIMRequest)
	http.ListenAndServe(":9090", nil)
}

func handleSCIMRequest(w http.ResponseWriter, r *http.Request) {
	log.Debugf("URI = %s", r.RequestURI)
	log.Debugf("URL = %s", r.URL)
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

	prv, err := provider.NewProvider(layout)
	if err != nil {
		panic(err)
	}

	providers[layout.Name()] = prv
}

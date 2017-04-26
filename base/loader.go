package base

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sparrow/schema"
	"strings"
)

func LoadSchemas(sDirPath string) (map[string]*schema.Schema, error) {
	dir, err := os.Open(sDirPath)
	if err != nil {
		log.Criticalf("Could not open schema directory %s [%s]", sDirPath, err)
		return nil, err
	}

	defer dir.Close()

	files, err := dir.Readdir(-1)

	if err != nil {
		return nil, err
	}

	schemas := make(map[string]*schema.Schema)

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			sc, err := schema.LoadSchema((sDirPath + "/" + name))
			if err != nil {
				log.Warningf("Failed to load schema from file %s [%s]", name, err)
				continue
			}

			log.Infof("Loaded schema %s", sc.Id)
			schemas[sc.Id] = sc
		}
	}

	log.Infof("Loaded %d schemas", len(schemas))
	return schemas, nil
}

func LoadResTypes(rtDirPath string, schemas map[string]*schema.Schema) (rsTypes map[string]*schema.ResourceType, rtPathMap map[string]*schema.ResourceType, err error) {
	dir, err := os.Open(rtDirPath)
	if err != nil {
		log.Criticalf("Could not open resourcetypes directory %s [%s]", rtDirPath, err)
		return nil, nil, err
	}

	defer dir.Close()

	files, err := dir.Readdir(-1)

	if err != nil {
		return nil, nil, err
	}

	rsTypes = make(map[string]*schema.ResourceType)
	rtPathMap = make(map[string]*schema.ResourceType)

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			rt, err := schema.LoadResourceType((rtDirPath + "/" + name), schemas)
			if err != nil {
				log.Warningf("Failed to load resource type from file %s [%s]", name, err)
				continue
			}

			log.Infof("Loaded resource type %s", rt.Id)

			// check if any of the resourceTypes are defined with duplicate Name or
			if _, ok := rsTypes[rt.Name]; ok {
				panic(fmt.Errorf("Duplicate resource type, a ResourceType with the Name '%s' already exists", rt.Name))
			}

			// are mapped to the same path
			if _, ok := rtPathMap[rt.Endpoint]; ok {
				panic(fmt.Errorf("Duplicate resource type, a ResourceType with the Endpoint '%s' already exists", rt.Endpoint))
			}

			rsTypes[rt.Name] = rt
			rtPathMap[rt.Endpoint] = rt
		}
	}

	log.Infof("Loaded %d resource types", len(rsTypes))
	return rsTypes, rtPathMap, nil
}

func LoadLdapTemplates(ldapTmplPath string, rsTypes map[string]*schema.ResourceType) map[string]*schema.LdapEntryTemplate {
	tmplMap := make(map[string]*schema.LdapEntryTemplate)

	dir, err := os.Open(ldapTmplPath)
	if err != nil {
		log.Criticalf("Could not open LDAP templates directory %s [%s]", ldapTmplPath, err)
		return tmplMap
	}

	defer dir.Close()

	files, err := dir.Readdir(-1)

	if err != nil {
		return tmplMap
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			fPath := filepath.Join(ldapTmplPath, name)
			tmplData, err := ioutil.ReadFile(fPath)
			if err != nil {
				log.Criticalf("Could not read LDAP template content from %s [%s]", fPath, err)
				continue
			}

			entry, err := schema.NewLdapTemplate(tmplData, rsTypes)
			if err != nil {
				log.Criticalf("Could not parse LDAP template from %s [%s]", fPath, err)
			} else {
				tmplMap[entry.Type] = entry
			}
		}
	}

	return tmplMap
}

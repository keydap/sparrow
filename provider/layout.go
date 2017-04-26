// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package provider

import (
	"os"
	"path/filepath"
	"sparrow/utils"
	"strings"
)

type Layout struct {
	ConfDir     string
	SchemaDir   string
	DataDir     string
	LogDir      string
	TmplDir     string // template directory
	LdapTmplDir string // LDAP entry templates directory
	ResTypesDir string
	name        string
}

func NewLayout(baseDir string, create bool) (layout *Layout, err error) {
	err = os.Chdir(baseDir)
	if err != nil && !create {
		log.Criticalf("Failed to open the base directory %s [%s]", baseDir, err)
		return nil, err
	}

	if create {
		err := os.MkdirAll(baseDir, utils.DIR_PERM)
		if err != nil {
			log.Criticalf("Failed to create the base directory %s [%#v]", baseDir, err)
			return nil, err
		}
	}

	defer func() {
		r := recover()
		if r != nil {
			log.Debugf("recovering after failed to create the layout %#v\n", r)
			err = r.(error)
		}
	}()

	cdir := filepath.Join(baseDir, "conf")
	utils.CheckAndCreate(cdir)

	sdir := filepath.Join(baseDir, "schema")
	utils.CheckAndCreate(sdir)

	ddir := filepath.Join(baseDir, "data")
	utils.CheckAndCreate(ddir)

	ldir := filepath.Join(baseDir, "logs")
	utils.CheckAndCreate(ldir)

	ldapDir := filepath.Join(baseDir, "ldap")
	utils.CheckAndCreate(ldapDir)

	resTypesdir := filepath.Join(baseDir, "resourcetypes")
	utils.CheckAndCreate(resTypesdir)

	layout = &Layout{ConfDir: cdir, SchemaDir: sdir, DataDir: ddir, LogDir: ldir, LdapTmplDir: ldapDir, ResTypesDir: resTypesdir}

	// open the base directory just to get it's name
	file, _ := os.Open(baseDir) // no error should be reported here
	stat, _ := file.Stat()

	layout.name = strings.ToLower(stat.Name())

	file.Close()

	return layout, nil
}

func (lo *Layout) Name() string {
	return lo.name
}

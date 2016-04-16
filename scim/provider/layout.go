package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Layout struct {
	ConfDir     string
	SchemaDir   string
	DataDir     string
	LogDir      string
	ResTypesDir string
	name        string
}

var DIR_PERM os.FileMode = 0744 //rwxr--r--

func NewLayout(baseDir string, create bool) (layout *Layout, err error) {
	err = os.Chdir(baseDir)
	if err != nil && !create {
		log.Criticalf("Failed to open the base directory %s [%s]", baseDir, err)
		return nil, err
	}

	if create {
		err := os.MkdirAll(baseDir, DIR_PERM)
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
	checkAndCreate(cdir)

	sdir := filepath.Join(baseDir, "schema")
	checkAndCreate(sdir)

	ddir := filepath.Join(baseDir, "data")
	checkAndCreate(ddir)

	ldir := filepath.Join(baseDir, "logs")
	checkAndCreate(ldir)

	resTypesdir := filepath.Join(baseDir, "resourcetypes")
	checkAndCreate(resTypesdir)

	layout = &Layout{ConfDir: cdir, SchemaDir: sdir, DataDir: ddir, LogDir: ldir, ResTypesDir: resTypesdir}

	// open the base directory just to get it's name
	file, _ := os.Open(baseDir) // no error should be reported here

	layout.name = strings.ToLower(file.Name())

	file.Close()

	return layout, nil
}

func checkAndCreate(dirName string) {
	finfo, err := os.Stat(dirName)

	if os.IsNotExist(err) {
		err := os.Mkdir(dirName, DIR_PERM)
		if err != nil {
			log.Criticalf("Failed to create the directory %s [%s]", dirName, err)
			panic(err)
		}
	} else if !finfo.IsDir() {
		s := fmt.Errorf("The file %s already exists and is not a directory, please delete it and retry\n", dirName)
		log.Criticalf(s.Error())
		panic(s)
	}
}

func (lo *Layout) Name() string {
	return lo.name
}

package provider

import (
	"os"
	"path/filepath"
)

type Layout struct {
	ConfDir   string
	SchemaDir string
	DataDir   string
	LogDir    string
}

var DIR_PERM os.FileMode = 0744 //rwxr--r--

func New(baseDir string, create bool) *Layout {
	err := os.Chdir(baseDir)
	if err != nil && !create {
		log.Criticalf("Failed to open the base directory %s [%s]", baseDir, err)
		os.Exit(1)
	}

	if create {
		err := os.MkdirAll(baseDir, DIR_PERM)
		if err != nil {
			log.Criticalf("Failed to create the base directory %s [%s]", baseDir, err)
			os.Exit(1)
		}
	}

	cdir := filepath.Join(baseDir, "conf")
	checkAndCreate(cdir)

	sdir := filepath.Join(baseDir, "schema")
	checkAndCreate(sdir)

	ddir := filepath.Join(baseDir, "data")
	checkAndCreate(ddir)

	ldir := filepath.Join(baseDir, "logs")
	checkAndCreate(ldir)

	layout := &Layout{SchemaDir: sdir, DataDir: ddir, LogDir: ldir}

	return layout
}

func checkAndCreate(dirName string) {
	finfo, err := os.Stat(dirName)

	if os.IsNotExist(err) {
		err := os.Mkdir(dirName, DIR_PERM)
		if err != nil {
			log.Criticalf("Failed to create the directory %s [%s]", dirName, err)
			os.Exit(1)
		}
	} else if !finfo.IsDir() {
		log.Criticalf("The file %s already exists and is not a directory, please delete it and retry [%s]", dirName, err)
		os.Exit(1)
	}
}

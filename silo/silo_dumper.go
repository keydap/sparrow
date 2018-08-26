// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package silo

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"sparrow/base"
	"sparrow/schema"
	"sparrow/utils"
)

// Dumps all the resources of a given type in JSON format
func (sl *Silo) DumpJSON(bkFilePath string, overwrite bool, rt *schema.ResourceType) error {
	if rt == nil {
		return fmt.Errorf("nil resourcetype")
	}

	buckName := sl.resources[rt.Name]
	if buckName == nil {
		return fmt.Errorf("No data exists for the resource type %s", rt.Name)
	}

	fInfo, _ := os.Stat(bkFilePath)
	if fInfo != nil {
		if fInfo.IsDir() {
			return fmt.Errorf("%s is a directory", bkFilePath)
		}

		if !overwrite {
			return fmt.Errorf("%s already exists, set the overwrite flag to overwrite", bkFilePath)
		}
	}

	file, err := os.Create(bkFilePath)
	if err != nil {
		return err
	}

	tx, err := sl.db.Begin(false)
	if err != nil {
		file.Close()
		os.Remove(bkFilePath)
		return err
	}

	defer func() {
		file.Close()
		tx.Rollback()
	}()

	var count int64
	var errCount int64
	cursor := tx.Bucket(buckName).Cursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		reader := bytes.NewReader(v)
		decoder := gob.NewDecoder(reader)

		if v != nil {
			var rs *base.Resource
			err = decoder.Decode(&rs)
			if err != nil {
				log.Warningf("Error while decoding the resource with ID %s", string(k))
				errCount++
				continue
			}
			rs.SetSchema(rt)
			jsonData := rs.Serialize()
			file.WriteString(string(jsonData))
			file.WriteString("\n") // one record per line
			count++
		}
	}

	log.Infof("Dumped %d resources of type %s to %s", count, rt.Name, bkFilePath)
	if errCount > 0 {
		log.Infof("There were %d resources that couldn't be read", errCount)
	}

	return nil
}

func (sl *Silo) GetMaxIndexedValOfAt(rt *schema.ResourceType, atName string) (int64, error) {
	at := rt.GetAtType(atName)
	if at == nil {
		return 0, fmt.Errorf("no attribute with the name %s found in resourcetype %s", atName, rt.Name)
	}

	if !at.IsUnique() {
		return 0, fmt.Errorf("attribute %s of resourcetype %s is not unique", atName, rt.Name)
	}

	if at.Type != "integer" {
		return 0, fmt.Errorf("attribute %s of resourcetype %s is not of integer type", atName, rt.Name)
	}

	idx := sl.indices[rt.Name][at.NormName]
	if idx == nil {
		return 0, fmt.Errorf("attribute %s of resourcetype %s has no idex", atName, rt.Name)
	}

	tx, err := sl.db.Begin(false)
	if err != nil {
		return 0, err
	}

	var highestVal int64
	cursor := idx.cursor(tx)
	key, _ := cursor.Last()

	if len(key) != 0 {
		highestVal = utils.Btoi(key)
	}

	tx.Rollback()

	return highestVal, nil
}

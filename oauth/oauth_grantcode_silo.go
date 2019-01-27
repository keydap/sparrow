// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package oauth

import (
	"bytes"
	"github.com/coreos/bbolt"
	"sparrow/utils"
	"time"
)

var (
	buc_grant_codes = []byte("grant_codes")
	dup_key_val     = []byte{0}
)

type oauthGrantCodeSilo struct {
	db                 *bolt.DB
	grantPurgeInterval int
	grantCodeTTL       int
}

func openGrantCodeSilo(path string, grantPurgeInterval int, grantCodeTTL int) (ogcsl *oauthGrantCodeSilo, err error) {
	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(buc_grant_codes)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Criticalf("Errors while opening the silo %s", err.Error())
		return nil, err
	}

	ogcsl = &oauthGrantCodeSilo{}
	ogcsl.db = db
	ogcsl.grantPurgeInterval = grantPurgeInterval
	ogcsl.grantCodeTTL = grantCodeTTL

	return ogcsl, nil
}

func (osl *OauthSilo) StoreGrantCodeId(creationTime int64, gcIvAsId []byte) (err error) {
	key := utils.Itob(creationTime)
	tx, err := osl.grantSilo.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	buck := tx.Bucket(buc_grant_codes)
	dupBuck := buck.Bucket(key)
	if dupBuck == nil {
		dupBuck, err = buck.CreateBucket(key)
		if err != nil {
			return err
		}
	}

	err = dupBuck.Put(gcIvAsId, dup_key_val)
	if err != nil {
		return err
	}

	return nil
}

func (osl *OauthSilo) HasGrantCodeId(creationTime int64, gcIvAsId []byte) bool {
	key := utils.Itob(creationTime)
	tx, err := osl.grantSilo.db.Begin(true)
	if err != nil {
		return false
	}

	buck := tx.Bucket(buc_grant_codes)
	dupBuck := buck.Bucket(key)
	if dupBuck == nil {
		return false
	}

	val := dupBuck.Get(gcIvAsId)
	tx.Rollback()

	return val != nil
}

func (osl *OauthSilo) removeExpiredGrantCodes() {
	log.Debugf("Starting oauth grant code cleaner")
	defer func() {
		// this can happen when the silo gets closed
		// but the goroutine is still executing
		recover()
		// do nothing
	}()

	for {
		tx, err := osl.grantSilo.db.Begin(true)
		if err != nil {
			log.Warningf("Failed to open a transaction for removing expired grant codes %s", err)
			continue
		}

		gcBuck := tx.Bucket(buc_grant_codes)

		cursor := gcBuck.Cursor()

		t := time.Now()
		now := t.Unix()
		now = now - int64(osl.grantSilo.grantCodeTTL)
		log.Debugf("searching key %d", now)
		key := utils.Itob(now)
		candidateKey, value := cursor.Seek(key)
		if candidateKey != nil && (bytes.Compare(candidateKey, key) <= 0) {
			log.Debugf("deleting key")
			gcBuck.Delete(value)
		}

		k, _ := cursor.Prev()
		for ; k != nil; k, _ = cursor.Prev() {
			log.Debugf("deleting prev key %d", utils.Btoi(k))
			gcBuck.Delete(k)
		}

		tx.Commit()

		sleepTime := time.Duration(osl.grantSilo.grantPurgeInterval) * time.Second
		log.Debugf("grant code cleaner sleeping for %s", sleepTime)
		time.Sleep(sleepTime)
	}
}

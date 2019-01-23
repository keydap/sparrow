// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package oauth

import (
	"github.com/coreos/bbolt"
)

var (
	BUC_GRANT_CODES = []byte("grant_codes")
)

type OauthGrantCodeSilo struct {
	db                 *bolt.DB
	grantPurgeInterval int
}

func OpenGrantCodeSilo(path string, grantPurgeInterval int) (ogcsl *OauthGrantCodeSilo, err error) {
	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(BUC_OAUTH_SESSIONS)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Criticalf("Errors while opening the silo %s", err.Error())
		return nil, err
	}

	ogcsl = &OauthGrantCodeSilo{}
	ogcsl.db = db
	ogcsl.grantPurgeInterval = grantPurgeInterval

	//go removeExpiredGrantCodes(ogcsl, BUC_GRANT_CODES)

	return ogcsl, nil
}

func (ogcsl *OauthGrantCodeSilo) StoreGrantCodeId(key string, gcIvAsId []byte) {

}

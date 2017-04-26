// Copyright 2017 Keydap. All rights reserved.
// Use of this source code is governed by a Apache
// license that can be found in the LICENSE file.

package oauth

import (
	"bytes"
	"encoding/gob"
	"github.com/boltdb/bolt"
	logger "github.com/juju/loggo"
	"runtime/debug"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/utils"
	"time"
)

var (
	// a bucket that holds the clients.
	BUC_SERVICE_PROVIDERS = []byte("service_providers")

	BUC_SSO_SESSIONS = []byte("sso_sessions")

	BUC_OAUTH_SESSIONS = []byte("oauth_sessions")

	BUC_REVOKED_OAUTH_SESSIONS = []byte("revoked_oauth_sessions")

	BUC_IDX_OAUTH_SESSION_BY_JTI = []byte("idx_token_by_jti")

	BUC_IDX_SSO_SESSION_BY_JTI = []byte("idx_session_by_jti")
)

var srvConf *conf.ServerConf

type OauthSilo struct {
	db       *bolt.DB
	rvTokens map[string]bool
}

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.oauth")
}

func Open(path string, cnf *conf.ServerConf) (osl *OauthSilo, err error) {
	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(BUC_SERVICE_PROVIDERS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_OAUTH_SESSIONS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_SSO_SESSIONS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_REVOKED_OAUTH_SESSIONS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_IDX_OAUTH_SESSION_BY_JTI)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_IDX_SSO_SESSION_BY_JTI)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Criticalf("Errors while opening the silo %s", err.Error())
		return nil, err
	}

	srvConf = cnf
	osl = &OauthSilo{}
	osl.db = db
	osl.rvTokens = make(map[string]bool)

	// load revoked tokens
	osl.loadRevokedSessions()

	go removeExpiredSessions(osl, BUC_OAUTH_SESSIONS, BUC_IDX_OAUTH_SESSION_BY_JTI)

	go removeExpiredSessions(osl, BUC_SSO_SESSIONS, BUC_IDX_SSO_SESSION_BY_JTI)

	return osl, nil
}

func (osl *OauthSilo) AddClient(cl *Client) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(cl)

	if err != nil {
		log.Warningf("Failed to encode client %s", err)
		panic(err)
	}

	err = osl.db.Update(func(tx *bolt.Tx) error {
		clBucket := tx.Bucket(BUC_SERVICE_PROVIDERS)
		return clBucket.Put([]byte(cl.Id), buf.Bytes())
	})

	if err != nil {
		log.Warningf("Failed to save client %s", err)
		panic(err)
	}
}

func (osl *OauthSilo) DeleteClient(id string) error {
	err := osl.db.Update(func(tx *bolt.Tx) error {
		clBucket := tx.Bucket(BUC_SERVICE_PROVIDERS)
		return clBucket.Delete([]byte(id))
	})

	if err != nil {
		log.Warningf("Failed to delete client %s %s", id, err)
	}

	return err
}

func (osl *OauthSilo) GetClient(id string) (cl *Client) {

	err := osl.db.View(func(tx *bolt.Tx) error {
		clBucket := tx.Bucket(BUC_SERVICE_PROVIDERS)
		data := clBucket.Get([]byte(id))
		var err error
		if data != nil {
			reader := bytes.NewReader(data)
			dec := gob.NewDecoder(reader)
			err = dec.Decode(&cl)
		}

		return err
	})

	if err != nil {
		log.Warningf("Cound not find client with the id %s %s", id, err)
	}

	return cl
}

func (osl *OauthSilo) StoreOauthSession(session *base.RbacSession) {
	osl._storeSession(BUC_OAUTH_SESSIONS, BUC_IDX_OAUTH_SESSION_BY_JTI, session)
}

func (osl *OauthSilo) StoreSsoSession(session *base.RbacSession) {
	osl._storeSession(BUC_SSO_SESSIONS, BUC_IDX_SSO_SESSION_BY_JTI, session)
}

func (osl *OauthSilo) _storeSession(bucketName []byte, idxBuckName []byte, session *base.RbacSession) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(session)

	if err != nil {
		log.Warningf("Failed to encode RBAC session %s", err)
		panic(err)
	}

	tx, err := osl.db.Begin(true)
	if err != nil {
		log.Warningf("Failed to begin transaction in session silo %s", err)
		panic(err)
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
			log.Warningf("Panicked while trying to store RBAC session %s", e)
			debug.PrintStack()
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	clBucket := tx.Bucket(bucketName)
	key := []byte(session.Jti)
	err = clBucket.Put(key, buf.Bytes())

	if err != nil {
		log.Warningf("Failed to save RBAC session %s", err)
		panic(err)
	}

	idxBuck := tx.Bucket(idxBuckName)
	expTime := utils.Itob(session.Exp)
	idxBuck.Put(key, expTime)
}

func (osl *OauthSilo) RevokeOauthSession(session *base.RbacSession) {
	err := osl.db.Update(func(tx *bolt.Tx) error {
		tBucket := tx.Bucket(BUC_REVOKED_OAUTH_SESSIONS)
		now := time.Now().Unix()
		key := []byte(session.Jti)

		existing := tBucket.Get(key)
		if len(existing) == 0 { // only revoke if it wasn't already
			// AUDIT
			osl.rvTokens[session.Jti] = true
			return tBucket.Put(key, utils.Itob(now))
		}

		return nil
	})

	if err != nil {
		log.Warningf("Failed to save revoked oauth session %s", err)
		panic(err)
	}
}

func (osl *OauthSilo) IsRevokedSession(session *base.RbacSession) bool {
	_, ok := osl.rvTokens[session.Jti]

	return ok
}

func (osl *OauthSilo) loadRevokedSessions() int {
	tx, err := osl.db.Begin(false)
	if err != nil {
		log.Warningf("Failed to start readonly transaction for loading revoked tokens %s", err)
		return 0
	}

	tBucket := tx.Bucket(BUC_REVOKED_OAUTH_SESSIONS)
	cursor := tBucket.Cursor()
	for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
		osl.rvTokens[string(k)] = true
	}

	tx.Rollback()

	return len(osl.rvTokens)
}

func (osl *OauthSilo) GetOauthSession(jti string) *base.RbacSession {
	return osl._getSession(BUC_OAUTH_SESSIONS, jti)
}

func (osl *OauthSilo) GetSsoSession(jti string) *base.RbacSession {
	return osl._getSession(BUC_SSO_SESSIONS, jti)
}

func (osl *OauthSilo) _getSession(bucketName []byte, jti string) *base.RbacSession {
	tx, err := osl.db.Begin(false)
	if err != nil {
		log.Warningf("Failed to start readonly transaction for fetching token %s", err)
		return nil
	}

	tBucket := tx.Bucket(bucketName)

	token := tBucket.Get([]byte(jti))
	tx.Rollback()

	if len(token) == 0 {
		return nil
	}

	var session *base.RbacSession
	buf := bytes.NewBuffer(token)
	dec := gob.NewDecoder(buf)
	err = dec.Decode(&session)

	if err != nil {
		panic(err)
	}

	return session
}

func (osl *OauthSilo) DeleteToken(jti string) bool {
	log.Debugf("Deleting token %s", jti)
	return osl._deleteSession(BUC_OAUTH_SESSIONS, BUC_IDX_OAUTH_SESSION_BY_JTI, jti)
}

func (osl *OauthSilo) DeleteSsoSession(jti string) bool {
	log.Debugf("Deleting SSO session %s", jti)
	return osl._deleteSession(BUC_SSO_SESSIONS, BUC_IDX_SSO_SESSION_BY_JTI, jti)
}

func (osl *OauthSilo) _deleteSession(bucketName []byte, idxBuckName []byte, jti string) bool {
	tx, err := osl.db.Begin(true)
	if err != nil {
		log.Warningf("Failed to start write transaction for deleting token %s", err)
		return false
	}

	tBucket := tx.Bucket(bucketName)
	key := []byte(jti)
	tBucket.Delete(key)

	idxBuck := tx.Bucket(idxBuckName)
	idxBuck.Delete(key)

	err = tx.Commit()
	if err != nil {
		panic(err)
	}

	return true
}

func (osl *OauthSilo) Close() {
	log.Infof("Closing oauth silo")
	osl.db.Close()
	osl.db = nil
	osl.rvTokens = nil
}

func removeExpiredSessions(osl *OauthSilo, buckName []byte, idxBuckName []byte) {
	log.Debugf("Starting session remover")
	defer func() {
		// this can happen when the silo gets closed
		// but the goroutine is still executing
		recover()
		// do nothing
	}()

	for {
		if osl.db == nil {
			break
		}

		tx, err := osl.db.Begin(true)
		if err != nil {
			log.Warningf("Failed to open a read-only transaction for removing expired sessions %s", err)
			continue
		}

		idxBuck := tx.Bucket(idxBuckName)
		tokenBuck := tx.Bucket(buckName)

		cursor := idxBuck.Cursor()

		t := time.Now()
		now := t.Unix()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			exp := utils.Btoi(v)
			if exp <= now {
				log.Debugf("Removed expired token %s", string(k))
				idxBuck.Delete(k)
				tokenBuck.Delete(k)
			} else {
				//log.Debugf("token %d didn't expire at %s", exp, t.Format(time.RFC3339))
			}
		}

		tx.Commit()

		time.Sleep(time.Duration(srvConf.TokenPurgeInterval) * time.Second)
	}
}

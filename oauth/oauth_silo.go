package oauth

import (
	"bytes"
	"encoding/gob"
	"github.com/boltdb/bolt"
	logger "github.com/juju/loggo"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/utils"
	"time"
)

var (
	// a bucket that holds the clients.
	BUC_OAUTH_CLIENTS = []byte("oauth_clients")

	BUC_ISSUED_TOKENS = []byte("issued_tokens")

	BUC_REVOKED_TOKENS = []byte("revoked_tokens")

	BUC_IDX_TOKEN_BY_JTI = []byte("idx_token_by_jti")
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
		_, err := tx.CreateBucketIfNotExists(BUC_OAUTH_CLIENTS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_ISSUED_TOKENS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_REVOKED_TOKENS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_IDX_TOKEN_BY_JTI)
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
	osl.loadRevokedTokens()

	go removeExpiredTokens(osl)

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
		clBucket := tx.Bucket(BUC_OAUTH_CLIENTS)
		return clBucket.Put([]byte(cl.Id), buf.Bytes())
	})

	if err != nil {
		log.Warningf("Failed to save client %s", err)
		panic(err)
	}
}

func (osl *OauthSilo) DeleteClient(id string) error {
	err := osl.db.Update(func(tx *bolt.Tx) error {
		clBucket := tx.Bucket(BUC_OAUTH_CLIENTS)
		return clBucket.Delete([]byte(id))
	})

	if err != nil {
		log.Warningf("Failed to delete client %s %s", id, err)
	}

	return err
}

func (osl *OauthSilo) GetClient(id string) (cl *Client) {

	err := osl.db.View(func(tx *bolt.Tx) error {
		clBucket := tx.Bucket(BUC_OAUTH_CLIENTS)
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

func (osl *OauthSilo) StoreToken(session *base.RbacSession) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(session)

	if err != nil {
		log.Warningf("Failed to encode RBAC session %s", err)
		panic(err)
	}

	tx, err := osl.db.Begin(true)
	if err != nil {
		log.Warningf("Failed to begin transaction in token silo %s", err)
		panic(err)
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
			log.Warningf("Panicked while trying to store RBAC session %s", e)
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	clBucket := tx.Bucket(BUC_ISSUED_TOKENS)
	err = clBucket.Put([]byte(session.Jti), buf.Bytes())

	if err != nil {
		log.Warningf("Failed to save RBAC session %s", err)
		panic(err)
	}
}

func (osl *OauthSilo) RevokeToken(session *base.RbacSession) {
	err := osl.db.Update(func(tx *bolt.Tx) error {
		tBucket := tx.Bucket(BUC_REVOKED_TOKENS)
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
		log.Warningf("Failed to save revoked token %s", err)
		panic(err)
	}
}

func (osl *OauthSilo) IsRevokedToken(session *base.RbacSession) bool {
	_, ok := osl.rvTokens[session.Jti]

	return ok
}

func (osl *OauthSilo) loadRevokedTokens() int {
	tx, err := osl.db.Begin(false)
	if err != nil {
		log.Warningf("Failed to start readonly transaction for loading revoked tokens %s", err)
		return 0
	}

	tBucket := tx.Bucket(BUC_REVOKED_TOKENS)
	cursor := tBucket.Cursor()
	for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
		osl.rvTokens[string(k)] = true
	}

	tx.Rollback()

	return len(osl.rvTokens)
}

func (osl *OauthSilo) GetToken(jti string) *base.RbacSession {
	tx, err := osl.db.Begin(false)
	if err != nil {
		log.Warningf("Failed to start readonly transaction for fetching token %s", err)
		return nil
	}

	tBucket := tx.Bucket(BUC_ISSUED_TOKENS)

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

func (osl *OauthSilo) Close() {
	log.Infof("Closing oauth silo")
	osl.db.Close()
	osl.db = nil
	osl.rvTokens = nil
}

func removeExpiredTokens(osl *OauthSilo) {
	log.Debugf("Starting token remover")
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
			log.Warningf("Failed to open a read-only transaction for removing expired tokens %s", err)
			continue
		}

		idxBuck := tx.Bucket(BUC_IDX_TOKEN_BY_JTI)
		tokenBuck := tx.Bucket(BUC_ISSUED_TOKENS)

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
				log.Debugf("cookie %d didn't expire at %s", exp, t.Format(time.RFC3339))
			}
		}

		tx.Commit()

		time.Sleep(time.Duration(srvConf.TokenPurgeInterval) * time.Second)
	}
}

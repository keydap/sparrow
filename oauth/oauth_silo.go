package oauth

import (
	"bytes"
	"encoding/gob"
	"github.com/boltdb/bolt"
	logger "github.com/juju/loggo"
)

var (
	// a bucket that holds the clients.
	BUC_OAUTH_CLIENTS = []byte("oauth_clients")
)

type OauthSilo struct {
	db *bolt.DB
}

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.scim.oauth")
}

func Open(path string) (osl *OauthSilo, err error) {
	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(BUC_OAUTH_CLIENTS)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Criticalf("Errors while opening the silo %s", err.Error())
		return nil, err
	}

	osl = &OauthSilo{}
	osl.db = db

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

func (osl *OauthSilo) Close() {
	log.Infof("Closing oauth silo")
	osl.db.Close()
}

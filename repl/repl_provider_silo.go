package repl

import (
	"bytes"
	"encoding/gob"
	"fmt"
	bolt "github.com/coreos/bbolt"
	"net/http"
)

var (
	// a bucket that holds the replication events
	BUC_REPL_EVENTS = []byte("repl_events")
)

type ReplProviderSilo struct {
	db *bolt.DB
}

func OpenReplProviderSilo(path string) (*ReplProviderSilo, error) {
	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(BUC_REPL_EVENTS)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Criticalf("errors while opening the replication silo %s", err.Error())
		return nil, err
	}

	rl := &ReplProviderSilo{}
	rl.db = db

	log.Debugf("opened replication provider silo")
	return rl, nil
}

func (rpl *ReplProviderSilo) StoreEvent(event ReplicationEvent) (*bytes.Buffer, error) {
	tx, err := rpl.db.Begin(true)
	if err != nil {
		return nil, err
	}

	// not using defer block intentionally

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(event)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	buck := tx.Bucket(BUC_REPL_EVENTS)
	err = buck.Put([]byte(event.Version), buf.Bytes())
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	err = tx.Commit()

	return &buf, err
}

func (rpl *ReplProviderSilo) SendEventsAfter(csn string, peer *ReplicationPeer, transport *http.Transport, serverId uint16, webhookToken string, domainCode string) (string, error) {
	tx, err := rpl.db.Begin(true)
	if err != nil {
		return "", err
	}

	if peer.catchingUpBacklog {
		return "", fmt.Errorf("peer is already sending backlog events, try again later")
	}

	peer.lock.Lock()
	peer.catchingUpBacklog = true

	defer func() {
		peer.lock.Unlock()
		tx.Rollback()
	}()

	key := []byte(csn)
	buck := tx.Bucket(BUC_REPL_EVENTS)
	cursor := buck.Cursor()
	cursor.Seek(key)
	lastSentVersion := ""
	for k, v := cursor.Prev(); k != nil; k, v = cursor.Prev() {
		version := string(k)
		err = peer._sendEvent(v, transport, serverId, webhookToken, domainCode, version)
		if err != nil {
			break
		}
		lastSentVersion = version
	}

	if err == nil {
		peer.updatePendingVersionMap(domainCode, lastSentVersion)
		peer.catchingUpBacklog = false
	}
	return lastSentVersion, err
}

func (rpl *ReplProviderSilo) _sendEventsWithoutLockAfter(csn string, peer *ReplicationPeer, transport *http.Transport, serverId uint16, webhookToken string, domainCode string) (string, error) {
	tx, err := rpl.db.Begin(true)
	if err != nil {
		return "", err
	}

	peer.catchingUpBacklog = true

	defer func() {
		tx.Rollback()
	}()

	key := []byte(csn)
	buck := tx.Bucket(BUC_REPL_EVENTS)
	cursor := buck.Cursor()
	cursor.Seek(key)
	lastSentVersion := ""
	for k, v := cursor.Prev(); k != nil; k, v = cursor.Prev() {
		version := string(k)
		err = peer._sendEvent(v, transport, serverId, webhookToken, domainCode, version)
		if err != nil {
			break
		}
		lastSentVersion = version
	}

	if err == nil {
		peer.catchingUpBacklog = false
	}
	return lastSentVersion, err
}

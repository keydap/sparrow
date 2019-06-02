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

func (rpl *ReplProviderSilo) Close() {
	log.Infof("Closing replication preovider silo")
	rpl.db.Close()
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
		if lastSentVersion != "" {
			peer.updatePendingVersionMap(domainCode, lastSentVersion)
		}
		peer.catchingUpBacklog = false
	}
	return lastSentVersion, err
}

func (rpl *ReplProviderSilo) WriteBacklogEvents(csn string, peer *ReplicationPeer, w http.ResponseWriter, domainCode string) (string, error) {
	tx, err := rpl.db.Begin(true)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return "", err
	}

	if peer.catchingUpBacklog {
		w.WriteHeader(http.StatusTooManyRequests)
		return "", fmt.Errorf("peer is already sending backlog events, try again later")
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		return "", fmt.Errorf("writer interface is not a Flusher")
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
	log.Debugf("version => %s", csn)
	for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
		log.Debugf("%s", string(k))
	}

	k, v := cursor.Seek(key)
	if bytes.Compare(k, key) == 0 {
		k, v = cursor.Next()
	}

	lastSentVersion := ""
	for ; k != nil; k, v = cursor.Next() {
		version := string(k)
		log.Debugf("****************************** %s", version)
		_, err := w.Write(v)
		flusher.Flush()
		if err != nil {
			break
		}
		lastSentVersion = version
	}

	if err == nil {
		peer.updatePendingVersionMap(domainCode, lastSentVersion)
		peer.catchingUpBacklog = false
		//w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
	}

	flusher.Flush()
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

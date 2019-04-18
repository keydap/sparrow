package repl

import (
	"bytes"
	"encoding/gob"
	bolt "github.com/coreos/bbolt"
	"sparrow/base"
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

func (rpl *ReplProviderSilo) StoreEvent(event base.ReplicationEvent) (*bytes.Buffer, error) {
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
	err = buck.Put([]byte(event.Csn), buf.Bytes())
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	err = tx.Commit()

	return &buf, err
}

func (rpl *ReplProviderSilo) SendEventsAfter(csn string, target chan []byte) {
	tx, err := rpl.db.Begin(true)
	if err != nil {
		target <- nil //TODO improve this to notify the caller about failure to open a read transaction
		return
	}

	defer func() {
		recover() // to recover when the channel is closed by the caller
		tx.Rollback()
	}()

	key := []byte(csn)
	buck := tx.Bucket(BUC_REPL_EVENTS)
	cursor := buck.Cursor()
	cursor.Seek(key)
	for k, v := cursor.Prev(); k != nil; k, v = cursor.Prev() {
		target <- v
	}

	target <- nil
}

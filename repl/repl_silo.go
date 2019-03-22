package repl

import (
	"bytes"
	"encoding/gob"
	"github.com/coreos/bbolt"
	logger "github.com/juju/loggo"
	"sparrow/base"
	"sparrow/utils"
)

var (
	// a bucket that holds the pending join requests
	BUC_PENDING_JOIN_REQUESTS = []byte("pending_join_requests")
	BUC_PEERS                 = []byte("peers")
)
var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.repl.silo")
}

type ReplSilo struct {
	db *bbolt.DB
}

func OpenReplSilo(path string) (*ReplSilo, error) {
	db, err := bbolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(BUC_PENDING_JOIN_REQUESTS)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_PEERS)
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		log.Criticalf("Errors while opening the replication silo %s", err.Error())
		return nil, err
	}

	rl := &ReplSilo{}
	rl.db = db

	log.Debugf("opened replication silo")
	return rl, nil
}

func (rl *ReplSilo) AddPendingJoinPeer(req base.PendingJoinPeer) error {
	key := utils.Uint16tob(req.ServerId)
	tx, err := rl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		e := recover()
		if e != nil || err != nil {
			tx.Rollback()
		}
	}()

	buck := tx.Bucket(BUC_PENDING_JOIN_REQUESTS)
	data := buck.Get(key)
	if data != nil {
		log.Debugf("replacing a pending join request for the server with ID %d", req.ServerId)
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(req)
	if err != nil {
		return err
	}
	err = buck.Put(key, buf.Bytes())
	if err == nil {
		tx.Commit()
	}

	return err
}

func (rl *ReplSilo) DeletePendingJoinPeer(serverId uint16) error {
	key := utils.Uint16tob(serverId)
	tx, err := rl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		e := recover()
		if e != nil || err != nil {
			tx.Rollback()
		}
	}()

	buck := tx.Bucket(BUC_PENDING_JOIN_REQUESTS)
	err = buck.Delete(key)
	if err == nil {
		tx.Commit()
	}
	return err
}

func (rl *ReplSilo) GetPendingJoinPeers() []base.PendingJoinPeer {
	requests := make([]base.PendingJoinPeer, 0)
	tx, err := rl.db.Begin(false)
	if err != nil {
		log.Warningf("%#v", err)
		return requests
	}

	defer func() {
		tx.Rollback()
	}()

	buck := tx.Bucket(BUC_PENDING_JOIN_REQUESTS)
	cursor := buck.Cursor()

	var buf bytes.Buffer
	dec := gob.NewDecoder(&buf)
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		buf.Write(v)
		var r base.PendingJoinPeer
		err = dec.Decode(&r)
		if err == nil {
			requests = append(requests, r)
		}
		buf.Reset()
	}

	return requests
}

func (rl *ReplSilo) AddReplicationPeer(req base.ReplicationPeer) error {
	key := utils.Uint16tob(req.ServerId)
	tx, err := rl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		e := recover()
		if e != nil || err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	buck := tx.Bucket(BUC_PEERS)
	data := buck.Get(key)
	if data != nil {
		log.Debugf("replacing existing entry of replication peer with ID %d", req.ServerId)
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(req)
	if err != nil {
		return err
	}
	err = buck.Put(key, buf.Bytes())

	return err
}

func (rl *ReplSilo) DeleteReplicationPeer(serverId uint16) error {
	key := utils.Uint16tob(serverId)
	tx, err := rl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		e := recover()
		if e != nil || err != nil {
			tx.Rollback()
		}
	}()

	buck := tx.Bucket(BUC_PEERS)
	err = buck.Delete(key)
	if err == nil {
		tx.Commit()
		log.Debugf("deleted replication peer with ID %d", serverId)
	}
	return err
}

func (rl *ReplSilo) GetReplicationPeer(serverId uint16) *base.ReplicationPeer {
	key := utils.Uint16tob(serverId)
	tx, err := rl.db.Begin(false)
	if err != nil {
		return nil
	}

	defer func() {
		e := recover()
		if e != nil {
			log.Warningf("%#v", e)
		}
		tx.Rollback()
	}()

	buck := tx.Bucket(BUC_PEERS)
	data := buck.Get(key)
	var peer *base.ReplicationPeer
	if data != nil {
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		err = dec.Decode(&peer)
	}

	return peer
}

func (rl *ReplSilo) Close() {
	rl.db.Close()
}

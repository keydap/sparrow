package repl

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/coreos/bbolt"
	logger "github.com/juju/loggo"
	"sparrow/base"
	"sparrow/utils"
)

var (
	// a bucket that holds the pending join requests
	BUC_PENDING_JOIN_REQUESTS = []byte("pending_join_requests")
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

func (rl *ReplSilo) AddPendingJoinReq(req base.PendingJoinRequest) error {
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
	if data == nil {
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
	} else {
		err = fmt.Errorf("a join request is already pending for the server with ID %d", req.ServerId)
		log.Debugf("%s", err)
	}

	return err
}
